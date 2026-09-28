#!/bin/bash
# Integration test for vpnctl install/uninstall + SSTP and VLESS drivers, with real clients:
#   VLESS: an Xray client container connects through REALITY and fetches a page via SOCKS;
#   SSTP:  sstpc brings up PPP and pings the server end of the tunnel.
# Needs docker, root, the ppp kernel module, images sstp:1.14.0 and xray:26.3.27 (or ghcr access),
# and internet from the server container (REALITY target check). Leaves nothing behind.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
CTL="$HERE/server/vpnctl"
WORK=$(mktemp -d)
export VPNCTL_SSTP_DIR="$WORK/sstp" VPNCTL_XRAY_DIR="$WORK/xray" VPNCTL_BACKUP_DIR="$WORK/backups" \
       VPNCTL_LOCK="$WORK/lock" VPNCTL_HOST_SSTP_CONF="$WORK/none.conf"
NET=vpnctl-test-$$
cleanup() {
  docker rm -f sstp xray vt-web vt-xcli vt-scli >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
pass=0; fail() { echo "FAIL: $*"; exit 1; }; ok() { pass=$((pass+1)); echo "ok  $*"; }
j() { python3 -c "import json,sys; d=json.loads(sys.stdin.read().splitlines()[-1]); print(eval(sys.argv[1]))" "$1"; }
docker network create "$NET" >/dev/null
docker run -d --name vt-web --network "$NET" busybox:1.36 sh -c 'mkdir -p /w && echo vpn-e2e-ok > /w/index.html && httpd -f -p 8080 -h /w' >/dev/null

# ------------------------------------------------------------------ VLESS
out=$("$CTL" install vless); port=$(echo "$out" | j 'd["port"]')
[ "$(echo "$out" | j 'd["ok"]')" = True ] && ok "install vless (TCP $port)" || fail "install vless: $out"
docker network connect "$NET" xray
[ "$("$CTL" list | j '[u["up"] for u in d if u["name"]=="xray"][0]')" = True ] && ok "xray listed and up" || fail list
uid=$(cat /proc/sys/kernel/random/uuid)
"$CTL" add xray --pub "$uid" --name "Тест VLESS" </dev/null | grep -q '"ok": true' && ok "vless add" || fail "vless add"
grep -q "$uid" "$VPNCTL_XRAY_DIR/config.json" && ok "vless user persisted to config.json" || fail persist
p=$("$CTL" params xray)
pbk=$(echo "$p" | j 'd["public_key"]'); sid=$(echo "$p" | j 'd["short_id"]'); sni=$(echo "$p" | j 'd["sni"]')
[ -n "$pbk" ] && [ -n "$sid" ] && ok "vless params (sni $sni)" || fail "params $p"
SRV=$(docker inspect xray --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")
mkdir -p "$WORK/xcli"
cat > "$WORK/xcli/config.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"0.0.0.0","port":1080,"protocol":"socks","settings":{"udp":false}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"$SRV","port":$port,
   "users":[{"id":"$uid","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality",
   "realitySettings":{"serverName":"$sni","fingerprint":"chrome","publicKey":"$pbk","shortId":"$sid"}}}]}
EOF
docker run -d --name vt-xcli --network "$NET" -v "$WORK/xcli:/etc/xray" xray:26.3.27 >/dev/null
fetch() { docker run --rm --network "$NET" curlimages/curl:8.10.1 -s -m 8 --socks5-hostname vt-xcli:1080 http://vt-web:8080/ 2>/dev/null || true; }
got=""; for _ in $(seq 1 10); do got=$(fetch); [ "$got" = vpn-e2e-ok ] && break; sleep 1; done
[ "$got" = vpn-e2e-ok ] && ok "VLESS REALITY end-to-end: page fetched through the tunnel" || fail "vless e2e: '$got'"
d=$("$CTL" dump xray)
[ "$(echo "$d" | j '[p["rx"]+p["tx"] for p in d["xray"]["peers"] if p["pub"]=="'"$uid"'"][0] > 0')" = True ] && ok "vless traffic counted" || fail "stats $d"
[ "$(echo "$d" | j '[p["latest_handshake"] for p in d["xray"]["peers"] if p["pub"]=="'"$uid"'"][0] > 0')" = True ] && ok "vless last-seen reported" || echo "note: statsonlineiplist gave no timestamp (xray version dependent)"
"$CTL" disable xray --pub "$uid" >/dev/null
docker restart vt-xcli >/dev/null; sleep 2
[ "$(fetch)" != vpn-e2e-ok ] && ok "vless disable: access cut live" || fail "still works after disable"
[ "$("$CTL" dump xray | j '[p["disabled"] for p in d["xray"]["peers"]][0]')" = True ] && ok "vless dump shows disabled" || fail dis
"$CTL" enable xray --pub "$uid" >/dev/null
got=""; for _ in $(seq 1 10); do got=$(fetch); [ "$got" = vpn-e2e-ok ] && break; sleep 1; done
[ "$got" = vpn-e2e-ok ] && ok "vless enable: access back live" || fail "enable"
"$CTL" set-name xray --pub "$uid" --name "Новое имя" >/dev/null
[ "$("$CTL" dump xray | j 'd["xray"]["peers"][0]["name"]')" = "Новое имя" ] && ok "vless set-name" || fail setname
out=$("$CTL" add xray --pub not-a-uuid </dev/null || true); grep -q "bad uuid" <<<"$out" && ok "vless bad uuid refused" || fail "$out"
"$CTL" remove xray --pub "$uid" >/dev/null
[ "$("$CTL" dump xray | j 'len(d["xray"]["peers"])')" = 0 ] && ok "vless remove" || fail remove

# ------------------------------------------------------------------ SSTP
out=$("$CTL" install sstp); sport=$(echo "$out" | j 'd["port"]')
[ "$(echo "$out" | j 'd["ok"]')" = True ] && ok "install sstp (TCP $sport)" || fail "install sstp: $out"
docker network connect "$NET" sstp
[ "$("$CTL" list | j '[u["up"] for u in d if u["name"]=="sstp"][0]')" = True ] && ok "sstp listed and up" || fail slist
pw="Test-$(openssl rand -hex 6)"
echo "$pw" | "$CTL" add sstp --pub alice --name "Алиса" | grep -q '"ok": true' && ok "sstp add" || fail "sstp add"
out=$(echo "short" | "$CTL" add sstp --pub bob || true); grep -q "bad password" <<<"$out" && ok "sstp weak password refused" || fail "$out"
[ "$("$CTL" params sstp | j 'd["port"] == '"$sport"' and "BEGIN CERTIFICATE" in d["cert_pem"] and d["self_signed"]')" = True ] && ok "sstp params with certificate" || fail sparams
SSRV=$(docker inspect sstp --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")
docker run -d --name vt-scli --network "$NET" --cap-add NET_ADMIN --device /dev/ppp vpnpanel-test-sstpc \
  sstpc --log-stderr --cert-warn --save-server-route --user alice --password "$pw" "$SSRV:$sport" \
  usepeerdns require-mschap-v2 noauth noipdefault nodefaultroute nodetach >/dev/null
up=0; for _ in $(seq 1 20); do docker exec vt-scli ping -c1 -W1 10.13.0.1 >/dev/null 2>&1 && { up=1; break; }; sleep 1; done
[ $up = 1 ] && ok "SSTP end-to-end: PPP up, server end 10.13.0.1 answers" || { docker logs vt-scli 2>&1 | tail -15; fail "sstp e2e"; }
d=$("$CTL" dump sstp)
[ "$(echo "$d" | j '[p["ip"] for p in d["sstp"]["peers"] if p["pub"]=="alice"][0].startswith("10.13.0.")')" = True ] && ok "sstp session visible in dump" || fail "sdump $d"
"$CTL" disable sstp --pub alice >/dev/null
gone=0; for _ in $(seq 1 10); do docker exec vt-scli ping -c1 -W1 10.13.0.1 >/dev/null 2>&1 || { gone=1; break; }; sleep 1; done
[ $gone = 1 ] && ok "sstp disable: session terminated" || fail "session still up"
grep -q "^#disabled alice " "$VPNCTL_SSTP_DIR/chap-secrets" && ok "sstp disabled user kept commented" || fail comment
"$CTL" enable sstp --pub alice >/dev/null && grep -q "^alice " "$VPNCTL_SSTP_DIR/chap-secrets" && ok "sstp enable" || fail senable
"$CTL" remove sstp --pub alice >/dev/null
grep -q alice "$VPNCTL_SSTP_DIR/chap-secrets" && fail "user still in chap-secrets" || ok "sstp remove"

# ------------------------------------------------------------------ preflight / uninstall / ssh mode
[ "$("$CTL" preflight | j 'd["docker"] and d["ppp"] and d["free_mb"] > 0')" = True ] && ok "preflight" || fail preflight
"$CTL" uninstall vless | grep -q '"ok": true' && ! docker ps --format '{{.Names}}' | grep -qx xray && ok "uninstall vless" || fail "uninstall vless"
ls -d "$WORK"/xray.removed-* >/dev/null 2>&1 && ok "vless data kept aside" || fail "vless data"
"$CTL" uninstall sstp | grep -q '"ok": true' && ! docker ps --format '{{.Names}}' | grep -qx sstp && ok "uninstall sstp" || fail "uninstall sstp"
out=$(SSH_ORIGINAL_COMMAND="vpnctl version" "$CTL" --ssh); grep -q version <<<"$out" && ok "ssh mode: vpnctl allowed" || fail "$out"
out=$(SSH_ORIGINAL_COMMAND="sh -c id" "$CTL" --ssh || true); grep -q "only vpnctl" <<<"$out" && ok "ssh mode: other commands refused" || fail "$out"
echo "PASS: $pass checks"
