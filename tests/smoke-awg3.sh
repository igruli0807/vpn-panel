#!/bin/bash
# Smoke test for the awg3 image: server + client containers on a private docker network,
# client must complete an AWG 3.1 handshake (header protection on) and ping the server.
#   tests/smoke-awg3.sh [image]
set -euo pipefail
IMAGE=${1:-awg3:3.1.20260828}
HERE=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d); NET=awg3-smoke-$$
cleanup() { docker rm -f awg3 awg3-smoke-client >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

AWG3_IMAGE=$IMAGE "$HERE/server/install-awg3.sh" --dir "$WORK/srv" --port 51820 >/dev/null
docker network create "$NET" >/dev/null
docker network connect "$NET" awg3
SRV_IP=$(docker inspect awg3 --format "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")

awg() { docker run --rm -i --entrypoint awg "$IMAGE" "$@"; }
cpriv=$(awg genkey); cpub=$(printf '%s' "$cpriv" | awg pubkey); psk=$(awg genpsk)
docker exec -i awg3 sh -c "awg set awg0 peer $cpub preshared-key /dev/stdin allowed-ips 10.8.3.2/32" <<<"$psk"

mkdir -p "$WORK/cli"
WORK=$WORK CPRIV=$cpriv PSK=$psk SRV_IP=$SRV_IP python3 - <<'PY'
import json, os
c = json.load(open(os.environ["WORK"] + "/srv/client.json"))
lines = ["[Interface]", f"PrivateKey = {os.environ['CPRIV']}", "Address = 10.8.3.2/32"]
lines += [f"{k} = {v}" for k, v in c["client_side"].items()]
lines += [f"{k} = {v}" for k, v in c["shared"].items()]
lines += [f"HeaderProtectionKey = {c['header_protection_key']}", "",
          "[Peer]", f"PublicKey = {c['server_public_key']}", f"PresharedKey = {os.environ['PSK']}",
          f"Endpoint = {os.environ['SRV_IP']}:{c['port']}", "AllowedIPs = 10.8.3.1/32",
          "PersistentKeepalive = 5", ""]
open(os.environ["WORK"] + "/cli/awg0.conf", "w").write("\n".join(lines))
PY

docker run -d --name awg3-smoke-client --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$WORK/cli:/etc/awg" --entrypoint sh "$IMAGE" -c 'awg-quick up /etc/awg/awg0.conf >/dev/null 2>&1; sleep 3600' >/dev/null

for _ in $(seq 1 20); do
  if docker exec awg3-smoke-client ping -c1 -W1 10.8.3.1 >/dev/null 2>&1; then
    hs=$(docker exec awg3 awg show awg0 latest-handshakes | awk '{print $2}')
    echo "OK: AWG 3.1 handshake (header protection on) and ping through the tunnel; handshake=$hs"
    exit 0
  fi
  sleep 1
done
echo "FAIL: no ping through the tunnel"; docker exec awg3 awg show awg0 | grep -v -i key; exit 1
