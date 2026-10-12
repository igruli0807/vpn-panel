#!/bin/bash
# Integration test for the Telegram proxies of vpnctl (telemt, mtg): install into temp dirs on spare ports,
# then act as a client and as a stranger:
#   - tests/tg-probe.py does the MTProto FakeTLS handshake with the secret and asks Telegram a question
#     through the proxy (no account needed) — the whole path client -> proxy -> Telegram is checked;
#   - a plain TLS client must be served by the real site the proxy pretends to be (vpnctl's own self-test).
# Needs docker, root, openssl and internet (the fronting sites, Telegram, the upstream images).
# Refuses to run where containers `telemt` / `mtg-doppel` already exist. Leaves nothing behind.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
CTL="$HERE/server/vpnctl"
if docker ps -a --format '{{.Names}}' | grep -qxE 'telemt|mtg-doppel'; then
  echo "SKIP: this host already runs telemt / mtg-doppel — the test would replace them"; exit 2
fi
WORK=$(mktemp -d)
export VPNCTL_TELEMT_DIR="$WORK/telemt" VPNCTL_MTG_DIR="$WORK/mtg" VPNCTL_SSTP_DIR="$WORK/sstp" VPNCTL_XRAY_DIR="$WORK/xray" \
       VPNCTL_BACKUP_DIR="$WORK/backups" VPNCTL_LOCK="$WORK/lock" VPNCTL_STATE_DIR="$WORK/state" \
       VPNCTL_HOST_SSTP_CONF="$WORK/none.conf"
cleanup() { docker rm -f telemt mtg-doppel >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT
pass=0; fail() { echo "FAIL: $*"; exit 1; }; ok() { pass=$((pass+1)); echo "ok  $*"; }
j() { python3 -c "import json,sys; d=json.loads(sys.stdin.read().splitlines()[-1]); print(eval(sys.argv[1]))" "$1"; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])'; }
probe() { python3 "$HERE/tests/tg-probe.py" 127.0.0.1 "$@"; }
hex() { openssl rand -hex 16; }
TP=$(free_port); MP=$(free_port)

# ------------------------------------------------------------------ telemt
out=$("$CTL" install telemt --port "$TP"); echo "$out" | sed 's/^/    /'
[ "$(echo "$out" | j 'd["ok"] and d["port"] == '"$TP"' and d["sni"] == "www.samsung.com"')" = True ] && ok "install telemt (TCP $TP): strangers get the real site" || fail "install telemt"
[ "$(stat -c '%u %a' "$WORK/telemt/config")" = "65532 700" ] && ok "telemt config dir belongs to the container user, 700" || fail "config dir perms"
[ "$("$CTL" list | j '[(u["kind"], u["up"], u["peers"]) for u in d if u["name"]=="telemt"]')" = "[('telemt', True, 0)]" ] && ok "telemt listed, the placeholder user is hidden" || fail "list: $("$CTL" list)"
S=$(hex)
echo "$S" | "$CTL" add telemt --pub alice --name "Алиса" | grep -q '"ok": true' && ok "telemt add" || fail "telemt add"
"$CTL" dump telemt | grep -q "$S" && fail "dump prints the secret" || ok "secret is not printed"
[ "$("$CTL" params telemt | j 'sorted(d) == ["domain", "kind", "port"] and d["domain"] == "www.samsung.com"')" = True ] && ok "telemt params (no secret)" || fail params
sleep 1
probe "$TP" "$S" www.samsung.com --deep | grep -q "Telegram answered" && ok "telemt end-to-end: Telegram answers through the proxy" || fail "telemt e2e: $(probe "$TP" "$S" www.samsung.com --deep || true)"
probe "$TP" "$(hex)" www.samsung.com >/dev/null && fail "a wrong secret was accepted" || ok "telemt: wrong secret gets the real site, not the proxy"
sleep 2
[ "$("$CTL" dump telemt | j '[p["rx"] > 0 for p in d["telemt"]["peers"] if p["pub"]=="alice"][0]')" = True ] && ok "telemt traffic counted" || fail "stats $("$CTL" dump telemt)"
"$CTL" disable telemt --pub alice >/dev/null; sleep 1
probe "$TP" "$S" www.samsung.com --deep >/dev/null && fail "still works after disable" || ok "telemt disable: access cut live"
[ "$("$CTL" dump telemt | j 'd["telemt"]["peers"][0]["disabled"]')" = True ] && ok "telemt dump shows disabled" || fail dis
"$CTL" enable telemt --pub alice >/dev/null; sleep 1
probe "$TP" "$S" www.samsung.com --deep >/dev/null && ok "telemt enable: access back live" || fail enable
"$CTL" set-name telemt --pub alice --name "Новое имя" >/dev/null
[ "$("$CTL" dump telemt | j 'd["telemt"]["peers"][0]["name"]')" = "Новое имя" ] && ok "telemt set-name" || fail setname
out=$(echo short | "$CTL" add telemt --pub bob || true); grep -q "bad secret" <<<"$out" && ok "telemt bad secret refused" || fail "$out"
out=$(hex | "$CTL" add telemt --pub alice || true); grep -q "already exists" <<<"$out" && ok "telemt duplicate refused" || fail "$out"
out=$("$CTL" remove telemt --pub _vpnctl || true); grep -q "bad user" <<<"$out" && ok "the placeholder user cannot be touched" || fail "$out"
"$CTL" install telemt | grep -q '"ok": true' && probe "$TP" "$S" www.samsung.com >/dev/null && ok "re-install keeps users and links" || fail reinstall
out=$("$CTL" install telemt --sni no-such-host-zz9.example || true)
grep -q "does not answer" <<<"$out" && probe "$TP" "$S" www.samsung.com >/dev/null && ok "failed re-install leaves the running proxy alone" || fail "$out"
docker stop telemt >/dev/null
[ "$("$CTL" dump telemt | j '(d["telemt"]["up"], [p["pub"] for p in d["telemt"]["peers"]])')" = "(False, ['alice'])" ] && ok "telemt down: users still listed from config" || fail "down dump"
docker start telemt >/dev/null; sleep 5
"$CTL" remove telemt --pub alice >/dev/null; sleep 1
[ "$("$CTL" dump telemt | j 'len(d["telemt"]["peers"])')" = 0 ] && ok "telemt remove (the last visible user too)" || fail remove
probe "$TP" "$S" www.samsung.com >/dev/null && fail "removed user still accepted" || ok "telemt: removed secret no longer accepted"

# ------------------------------------------------------------------ mtg
out=$("$CTL" install mtg --port "$TP" || true); grep -q "is busy" <<<"$out" && ok "busy port refused with a clear message" || fail "$out"
out=$("$CTL" install mtg --port "$MP"); echo "$out" | sed 's/^/    /'
[ "$(echo "$out" | j 'd["ok"] and d["port"] == '"$MP"' and d["sni"] == "www.intel.com"')" = True ] && ok "install mtg (TCP $MP): strangers get the real site" || fail "install mtg"
p=$("$CTL" params mtg-doppel); MS=$(echo "$p" | j 'd["secret"]')
[ "${MS:0:2}" = ee ] && [ "${MS:34}" = "$(printf www.intel.com | od -An -tx1 | tr -d ' \n')" ] && ok "mtg params: FakeTLS secret carries the site name" || fail "mtg params"
[ "$("$CTL" dump mtg-doppel | j '[(p["pub"], p["disabled"]) for p in d["mtg-doppel"]["peers"]]')" = "[('shared', False)]" ] && ok "mtg dump: one shared peer" || fail mdump
"$CTL" dump mtg-doppel | grep -q "${MS:2:32}" && fail "dump prints the secret" || ok "mtg dump does not print the secret"
grep -q 'drs = true' "$WORK/mtg/config.toml" && grep -q 'intel.com/content' "$WORK/mtg/config.toml" && ok "mtg config: Doppelganger pages + DRS" || fail "mtg config"
probe "$MP" "${MS:2:32}" www.intel.com --deep | grep -q "Telegram answered" && ok "mtg end-to-end: Telegram answers through the proxy" || fail "mtg e2e"
probe "$MP" "$(hex)" www.intel.com >/dev/null && fail "a wrong secret was accepted" || ok "mtg: wrong secret gets the real site, not the proxy"
for op in "add mtg-doppel --pub x" "remove mtg-doppel --pub shared" "disable mtg-doppel --pub shared"; do
  out=$("$CTL" $op </dev/null || true); grep -q "one shared link" <<<"$out" || fail "$op: $out"
done; ok "mtg add/remove/disable refused with an explanation"
"$CTL" set-name mtg-doppel --pub shared --name "Общая" >/dev/null && [ "$("$CTL" dump mtg-doppel | j 'd["mtg-doppel"]["peers"][0]["name"]')" = "Общая" ] && ok "mtg set-name" || fail msetname
"$CTL" install mtg >/dev/null && [ "$("$CTL" params mtg-doppel | j 'd["secret"]')" = "$MS" ] && ok "re-install keeps the link" || fail "mtg reinstall"

# ------------------------------------------------------------------ uninstall
[ "$("$CTL" preflight | j 'sorted(u for u in d["units"] if u in ("telemt", "mtg-doppel"))')" = "['mtg-doppel', 'telemt']" ] && ok "preflight lists both" || fail preflight
"$CTL" uninstall telemt | grep -q '"ok": true' && ! docker ps -a --format '{{.Names}}' | grep -qx telemt && ok "uninstall telemt" || fail "uninstall telemt"
"$CTL" uninstall mtg | grep -q '"ok": true' && ! docker ps -a --format '{{.Names}}' | grep -qx mtg-doppel && ok "uninstall mtg" || fail "uninstall mtg"
ls -d "$WORK"/telemt.removed-* "$WORK"/mtg.removed-* >/dev/null 2>&1 && ok "data kept aside" || fail "kept data"
[ "$("$CTL" list | j 'len(d)')" = 0 ] && ok "nothing left listed" || fail "list after uninstall"
echo "PASS: $pass checks"
