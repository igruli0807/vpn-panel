#!/bin/bash
# Integration test for server/awgctl against real containers:
#   awg3          — installed by server/install-awg3.sh into a temp dir
#   amnezia-awg2  — mock of the Amnezia app container (same image, Amnezia paths + clientsTable)
# Needs docker; leaves nothing behind.
set -euo pipefail
IMAGE=${1:-awg3:3.1.20260828}
HERE=$(cd "$(dirname "$0")/.." && pwd)
CTL="$HERE/server/awgctl"
WORK=$(mktemp -d)
export AWGCTL_BACKUP_DIR="$WORK/backups"
cleanup() { docker rm -f awg3 amnezia-awg2 >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
pass=0; fail() { echo "FAIL: $*"; exit 1; }; ok() { pass=$((pass+1)); echo "ok  $*"; }
j() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }
key() { docker run --rm -i --entrypoint awg "$IMAGE" "$@"; }

AWG3_IMAGE=$IMAGE "$HERE/server/install-awg3.sh" --dir "$WORK/awg3" --port 51821 >/dev/null

# Mock Amnezia awg2 container: one existing client in conf and in clientsTable.
mkdir -p "$WORK/amn"
spriv=$(key genkey); c1=$(key genkey | key pubkey)
cat > "$WORK/amn/awg0.conf" <<EOF
[Interface]
PrivateKey = $spriv
Address = 10.8.1.0/24
ListenPort = 51822
Jc = 4
Jmin = 10
Jmax = 50
S1 = 20
S2 = 30
S3 = 14
S4 = 13
H1 = 100-200
H2 = 300-400
H3 = 500-600
H4 = 700-800
# I1 = <r 2><b 0x8580>

[Peer]
PublicKey = $c1
AllowedIPs = 10.8.1.1/32
EOF
printf '%s' "$spriv" | key pubkey > "$WORK/amn/wireguard_server_public_key.key"
printf '[{"clientId":"%s","userData":{"clientName":"Existing [Android]","creationDate":"x"}}]' "$c1" > "$WORK/amn/clientsTable"
docker run -d --name amnezia-awg2 --cap-add NET_ADMIN --device /dev/net/tun -v "$WORK/amn:/opt/amnezia/awg" \
  --entrypoint sh "$IMAGE" -c 'awg-quick up /opt/amnezia/awg/awg0.conf >/dev/null 2>&1; sleep 3600' >/dev/null
sleep 2

out=$("$CTL" list); [ "$(echo "$out" | j 'sorted(c["name"] for c in d)')" = "['amnezia-awg2', 'awg3']" ] && ok list || fail "list: $out"
[ "$(echo "$out" | j 'all(c["up"] for c in d)')" = True ] && ok "both up" || fail "up: $out"

out=$("$CTL" dump amnezia-awg2)
[ "$(echo "$out" | j 'd["amnezia-awg2"]["peers"][0]["name"]')" = "Existing [Android]" ] && ok "names from clientsTable" || fail "$out"

out=$("$CTL" params amnezia-awg2)
[ "$(echo "$out" | j 'd["client_side"]["I1"]')" = "<r 2><b 0x8580>" ] && ok "params: commented I1 picked up" || fail "$out"
out=$("$CTL" params awg3)
[ "$(echo "$out" | j 'bool(d["header_protection_key"]) and d["port"]==51821')" = True ] && ok "params awg3" || fail "$out"

ip=$("$CTL" next-ip awg3 | j 'd["ip"]'); [ "$ip" = "10.8.3.2/32" ] && ok "next-ip awg3 = $ip" || fail "next-ip $ip"
ip2=$("$CTL" next-ip amnezia-awg2 | j 'd["ip"]'); [ "$ip2" = "10.8.1.2/32" ] && ok "next-ip awg2 = $ip2" || fail "next-ip $ip2"

p1=$(key genkey | key pubkey); psk=$(key genpsk)
echo "$psk" | "$CTL" add awg3 --pub "$p1" --ip "$ip" --name "Тест телефон" >/dev/null
docker exec awg3 awg show awg0 peers | grep -q "$p1" && ok "add: live peer present" || fail "add live"
docker exec awg3 grep -q "$p1" /etc/awg/awg0.conf && ok "add: persisted to conf" || fail "add conf"
[ "$("$CTL" dump awg3 | j 'd["awg3"]["peers"][0]["name"]')" = "Тест телефон" ] && ok "add: name stored" || fail "name"
out=$("$CTL" dump awg3); grep -q -- "$psk" <<<"$out" && fail "psk leaked in dump" || ok "dump does not leak psk"

out=$(echo "$psk" | "$CTL" add awg3 --pub "$p1" --ip 10.8.3.9/32 || true); grep -q "already exists" <<<"$out" && ok "duplicate refused" || fail "dup: $out"
p2=$(key genkey | key pubkey)
out=$(echo "" | "$CTL" add awg3 --pub "$p2" --ip "$ip" || true); grep -q "ip already used" <<<"$out" && ok "ip clash refused" || fail "clash: $out"
out=$("$CTL" add awg3 --pub 'bad;rm -rf /' --ip 10.8.3.9/32 </dev/null || true); grep -q "bad public key" <<<"$out" && ok "bad key refused" || fail "badkey: $out"

"$CTL" disable awg3 --pub "$p1" >/dev/null
docker exec awg3 awg show awg0 peers | grep -q "$p1" && fail "disable: still live" || ok "disable: removed from live"
docker exec awg3 grep -q "$p1" /etc/awg/awg0.conf.disabled && ok "disable: kept in .disabled" || fail "disable file"
[ "$("$CTL" dump awg3 | j 'd["awg3"]["peers"][0]["disabled"]')" = True ] && ok "dump shows disabled" || fail "dump disabled"
"$CTL" enable awg3 --pub "$p1" >/dev/null
docker exec awg3 awg show awg0 preshared-keys | grep -q "$psk" && ok "enable: live again with psk" || fail enable

echo "" | "$CTL" add amnezia-awg2 --pub "$p2" --ip "$ip2" --name "Новый" >/dev/null
python3 -c "import json;t=json.load(open('$WORK/amn/clientsTable'));assert [c['userData']['clientName'] for c in t]==['Existing [Android]','Новый'],t" \
  && ok "awg2: clientsTable updated for Amnezia app" || fail clientsTable
"$CTL" remove amnezia-awg2 --pub "$p2" >/dev/null
python3 -c "import json;t=json.load(open('$WORK/amn/clientsTable'));assert len(t)==1" && ok "awg2: remove cleans clientsTable" || fail rm
docker exec amnezia-awg2 awg show awg0 peers | grep -q "$p2" && fail "remove live" || ok "awg2: remove from live"

SSH_ORIGINAL_COMMAND="awgctl list" "$CTL" --ssh >/dev/null && ok "ssh mode: awgctl allowed" || fail sshmode
out=$(SSH_ORIGINAL_COMMAND="bash -c id" "$CTL" --ssh || true); grep -q "only awgctl" <<<"$out" && ok "ssh mode: other commands refused" || fail "sshdeny: $out"

[ "$(ls "$AWGCTL_BACKUP_DIR"/awg3 | wc -l)" -gt 0 ] && ok "backups written" || fail backups
echo "PASS: $pass checks"
