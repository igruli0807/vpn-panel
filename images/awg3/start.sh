#!/bin/bash
# Entry point of the awg3 container.
# Brings the interface up, sets NAT, then watches it: an Amnezia container can stay "Up"
# for days with no interface after a failed awg-quick (seen 20.09.2026) — here the
# watchdog re-runs awg-quick instead of silently idling.
set -u
IFC=${AWG_IF:-awg0}
CONF=${AWG_DIR:-/etc/awg}/${IFC}.conf
CHECK_EVERY=${AWG_CHECK_EVERY:-10}

log() { echo "$(date '+%F %T') awg3: $*"; }

stop() {
  log "stopping"
  awg-quick down "$CONF" >/dev/null 2>&1
  exit 0
}
trap stop TERM INT

until [ -f "$CONF" ]; do
  log "waiting for $CONF"
  sleep 5 & wait $!
done
chmod 600 "$CONF"

subnet=$(awk -F'= *' '/^Address/{print $2; exit}' "$CONF" | cut -d, -f1)
out=$(ip route show default | awk '{print $5; exit}')
[ -n "$subnet" ] && [ -n "$out" ] || { log "no Address in $CONF or no default route"; exit 1; }

ipt() { # idempotent append: ipt <table> <chain> <rule...>
  local t=$1 c=$2; shift 2
  iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -A "$c" "$@"
}
ipt filter FORWARD -i "$IFC" -j ACCEPT
ipt filter FORWARD -o "$IFC" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt nat POSTROUTING -s "$subnet" -o "$out" -j MASQUERADE

up() {
  if awg-quick up "$CONF" 2>&1 | grep -v -i -E 'privatekey|presharedkey|headerprotectionkey' | sed 's/^/  /'; then :; fi
  ip link show "$IFC" >/dev/null 2>&1
}

if up; then log "$IFC up ($subnet via $out)"; else log "$IFC FAILED to come up, watchdog will retry"; fi

while true; do
  sleep "$CHECK_EVERY" & wait $!
  if ! ip link show "$IFC" >/dev/null 2>&1; then
    log "$IFC is missing, bringing it up again"
    up && log "$IFC restored" || log "$IFC restore FAILED"
  fi
done
