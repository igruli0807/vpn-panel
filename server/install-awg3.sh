#!/bin/bash
# Install an AmneziaWG 3.1 server as docker container "awg3" next to anything already running.
#
#   install-awg3.sh [--port N] [--subnet 10.8.3.1/24] [--image awg3:TAG] [--dir /opt/awg3]
#   install-awg3.sh --remove            # stop and remove the container (keys stay in --dir)
#
# Re-running is safe: existing keys/params in --dir are kept, only the container is (re)created.
# The container is named "awg3", not "amnezia-*", so the Amnezia app never mistakes it for its own.
set -euo pipefail

PORT="" SUBNET="10.8.3.1/24" IMAGE="${AWG3_IMAGE:-awg3:3.1.20260828}" DIR="/opt/awg3" NAME="awg3" REMOVE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT=$2; shift 2 ;;
    --subnet) SUBNET=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --dir) DIR=$2; shift 2 ;;
    --remove) REMOVE=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { echo "[awg3] $*"; }

if [ "$REMOVE" = 1 ]; then
  docker rm -f "$NAME" >/dev/null 2>&1 && say "container removed; keys kept in $DIR" || say "no container"
  exit 0
fi

command -v docker >/dev/null || { say "docker is required"; exit 1; }
command -v python3 >/dev/null || { say "python3 is required"; exit 1; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { say "image $IMAGE not found (docker load / docker pull first)"; exit 1; }
[ -e /dev/net/tun ] || { say "/dev/net/tun is missing"; exit 1; }

# Preflight: things that silently break VPN containers on reboot (lesson L0127).
if systemctl is-enabled netfilter-persistent >/dev/null 2>&1; then
  say "WARNING: netfilter-persistent is enabled; do NOT run 'netfilter-persistent save' while containers run"
fi
free_mb=$(df -Pm / | awk 'NR==2{print $4}')
[ "$free_mb" -ge 200 ] || { say "less than 200 MB free on /"; exit 1; }

mkdir -p "$DIR"; chmod 700 "$DIR"
CONF="$DIR/awg0.conf" CLIENT="$DIR/client.json"

udp_busy() { ss -Hlun "sport = :$1" | grep -q .; }

if [ ! -f "$CONF" ]; then
  if [ -z "$PORT" ]; then
    for _ in $(seq 1 50); do
      p=$(( 20000 + $(od -An -N2 -tu2 /dev/urandom) % 40000 ))
      udp_busy "$p" || { PORT=$p; break; }
    done
  fi
  [ -n "$PORT" ] || { say "could not pick a free UDP port"; exit 1; }
  udp_busy "$PORT" && { say "UDP $PORT is busy"; exit 1; }

  awg() { docker run --rm -i --entrypoint awg "$IMAGE" "$@"; }
  priv=$(awg genkey); pub=$(printf '%s' "$priv" | awg pubkey); hpk=$(awg genkey)

  # Obfuscation: S1-S4 >= 12 (header protection needs it), S1+56 != S2 (message sizes must
  # stay distinct), H1-H4 disjoint ranges. I1 mimics a DNS answer, same as Amnezia's awg2 default.
  umask 077
  PORT="$PORT" SUBNET="$SUBNET" PRIV="$priv" PUB="$pub" HPK="$hpk" CONF="$CONF" CLIENT="$CLIENT" python3 - <<'PY'
import json, os, secrets
r = secrets.SystemRandom()
s1 = r.randint(15, 150)
s2 = r.randint(15, 150)
while s1 + 56 == s2:
    s2 = r.randint(15, 150)
s3, s4 = r.randint(12, 64), r.randint(12, 32)
cuts = sorted(r.sample(range(5, 2**31 - 1), 8))
h = [f"{cuts[i]}-{cuts[i+1]}" for i in range(0, 8, 2)]
r.shuffle(h)
jmin = r.randint(8, 40)
params = {"S1": s1, "S2": s2, "S3": s3, "S4": s4,
          "H1": h[0], "H2": h[1], "H3": h[2], "H4": h[3]}
conf = ["[Interface]", f"PrivateKey = {os.environ['PRIV']}", f"Address = {os.environ['SUBNET']}",
        f"ListenPort = {os.environ['PORT']}"]
conf += [f"{k} = {v}" for k, v in params.items()]
conf += [f"HeaderProtectionKey = {os.environ['HPK']}", ""]
open(os.environ["CONF"], "w").write("\n".join(conf) + "\n")
client = {
    "server_public_key": os.environ["PUB"], "port": int(os.environ["PORT"]),
    "subnet": os.environ["SUBNET"], "header_protection_key": os.environ["HPK"],
    "shared": params,
    "client_side": {"Jc": r.randint(4, 8), "Jmin": jmin, "Jmax": jmin + r.randint(30, 200),
                    "I1": "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"},
    "mtu": 1280, "dns": "1.1.1.1, 1.0.0.1", "keepalive": 25,
}
json.dump(client, open(os.environ["CLIENT"], "w"), indent=2)
PY
  chmod 600 "$CONF" "$CLIENT"
  say "generated new server keys and params (UDP $PORT)"
else
  PORT=$(awk -F'= *' '/^ListenPort/{print $2}' "$CONF")
  say "keeping existing config in $DIR (UDP $PORT)"
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --restart unless-stopped \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -p "$PORT:$PORT/udp" -v "$DIR:/etc/awg" \
  --log-driver json-file --log-opt max-size=5m --log-opt max-file=2 \
  --memory 128m \
  "$IMAGE" >/dev/null

for _ in $(seq 1 15); do
  sleep 1
  if docker exec "$NAME" awg show awg0 >/dev/null 2>&1; then
    say "running: container $NAME, UDP $PORT, interface awg0 up"
    exit 0
  fi
done
say "container started but awg0 is not up; see: docker logs $NAME"
exit 1
