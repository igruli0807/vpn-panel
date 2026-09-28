#!/bin/bash
# Entry point of the sstp container: NAT for the client pool, then accel-pppd in the foreground
# (so docker sees a crash and restarts the container).
set -u
CONF=/etc/accel-ppp/accel-ppp.conf
log() { echo "$(date '+%F %T') sstp: $*"; }
until [ -f "$CONF" ]; do log "waiting for $CONF"; sleep 5; done
[ -e /dev/ppp ] || { log "/dev/ppp is missing (run with --device /dev/ppp; host needs ppp_generic)"; exit 1; }
pool=$(awk -F= '/^gw-ip-address/{print $2; exit}' "$CONF" | sed 's/\.[0-9]*$/.0\/24/')
out=$(ip route show default | awk '{print $5; exit}')
ipt() { local t=$1 c=$2; shift 2; iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -A "$c" "$@"; }
ipt filter FORWARD -i ppp+ -j ACCEPT
ipt filter FORWARD -o ppp+ -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt nat POSTROUTING -s "$pool" -o "$out" -j MASQUERADE
ipt mangle FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
mkdir -p /var/log/accel-ppp
log "starting accel-pppd (pool $pool via $out)"
exec accel-pppd -c "$CONF"
