#!/bin/bash
# VPN panel starter pack.
#
#   ./install.sh panel [--port 2053] [--id fin] [--title "Финляндия"] [--endpoint IP] [--tz Europe/Helsinki]
#       install the web panel on this host (and register this host's VPN containers, if any)
#   ./install.sh add-server --id usa --title "США" --host IP [--ssh-port 22] [--endpoint IP]
#       run on the panel host: connect another VPN server (uses your root SSH access once)
#   ./install.sh server --proto awg3 [--port N]
#       run on a VPN host: install AmneziaWG 3.1 (docker container "awg3") + awgctl
#   ./install.sh server --remove --proto awg3
#
# Re-running any mode is safe. Nothing secret is written into the repository directory.
set -euo pipefail

REPO=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/vpn-panel
ETC=/etc/vpn-panel
LIB=/var/lib/vpn-panel
USER_=vpnpanel
IMAGE_TAG=3.1.20260828
IMAGE="awg3:$IMAGE_TAG"
GHCR_IMAGE="${AWG3_GHCR_IMAGE:-ghcr.io/igruli0807/awg3:$IMAGE_TAG}"

say() { echo -e "\033[1m[vpn-panel]\033[0m $*"; }
die() { echo "[vpn-panel] ERROR: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "run as root"; }
public_ip() { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'; }

sync_code() {
  if [ "$REPO" != "$PREFIX" ]; then
    mkdir -p "$PREFIX"
    cp -a "$REPO"/. "$PREFIX"/
  fi
}

install_awgctl() {
  install -m 755 "$PREFIX/server/awgctl" /usr/local/sbin/awgctl
}

install_guard() {
  # Watchdog for Amnezia-app containers: they can stay "Up" with no VPN interface (lesson L0307).
  install -m 755 "$PREFIX/server/awg-guard.sh" /usr/local/sbin/awg-guard.sh
  install -m 644 "$PREFIX/server/awg-guard.service" "$PREFIX/server/awg-guard.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now awg-guard.timer >/dev/null 2>&1
}

json_edit() { # json_edit FILE PYTHON-EXPR-ON-d
  python3 - "$1" "$2" <<'PY'
import json, sys
path, expr = sys.argv[1], sys.argv[2]
d = json.load(open(path))
exec(expr)
import os
st = os.stat(path)
tmp = path + ".tmp"
with open(tmp, "w") as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
os.chown(tmp, st.st_uid, st.st_gid)
os.chmod(tmp, st.st_mode & 0o777)
os.replace(tmp, path)
PY
}

# ---------------------------------------------------------------- panel
cmd_panel() {
  need_root
  local port=2053 id="" title="" endpoint="" tz="UTC"
  while [ $# -gt 0 ]; do case "$1" in
    --port) port=$2; shift 2 ;; --id) id=$2; shift 2 ;; --title) title=$2; shift 2 ;;
    --endpoint) endpoint=$2; shift 2 ;; --tz) tz=$2; shift 2 ;; *) die "unknown option $1" ;; esac; done
  command -v python3 >/dev/null || die "python3 is required"
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "python3 >= 3.9 is required"
  for b in openssl sudo ssh ssh-keygen; do command -v $b >/dev/null || die "$b is required (apt install $b)"; done
  endpoint=${endpoint:-$(public_ip)}
  sync_code

  id -u $USER_ >/dev/null 2>&1 || useradd --system --home-dir $LIB --shell /usr/sbin/nologin $USER_
  install -d -m 750 -o root -g $USER_ $ETC
  install -d -m 700 -o $USER_ -g $USER_ $LIB $ETC/ssh
  chown -R root:root "$PREFIX"; chmod -R go-w "$PREFIX"

  if [ ! -f $ETC/tls.crt ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$endpoint" \
      -addext "subjectAltName=IP:$endpoint" -keyout $ETC/tls.key -out $ETC/tls.crt >/dev/null 2>&1
    chown root:$USER_ $ETC/tls.key $ETC/tls.crt; chmod 640 $ETC/tls.key; chmod 644 $ETC/tls.crt
    say "self-signed certificate for $endpoint (10 years)"
  fi
  [ -f $ETC/ssh/id_ed25519 ] || { sudo -u $USER_ ssh-keygen -q -t ed25519 -N "" -C "vpn-panel@$(hostname)" -f $ETC/ssh/id_ed25519; }

  if [ ! -f $ETC/config.json ]; then
    python3 - "$ETC/config.json" "$port" "$endpoint" "$tz" <<'PY'
import json, sys
path, port, endpoint, tz = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
json.dump({"listen": "0.0.0.0", "port": port, "public_url": f"https://{endpoint}:{port}",
           "timezone": tz, "servers": [], "protected_pubkeys": []}, open(path, "w"), ensure_ascii=False, indent=2)
PY
    chown root:$USER_ $ETC/config.json; chmod 640 $ETC/config.json
  fi

  # This host runs VPN containers too -> manage them locally through sudo awgctl.
  if command -v docker >/dev/null && docker ps --format '{{.Names}}' | grep -qE '^(awg3|amnezia-(awg2?|wireguard))$'; then
    install_awgctl; install_guard
    id=${id:-$(hostname -s)}; title=${title:-$id}
    json_edit $ETC/config.json "
s=[x for x in d['servers'] if x['id']!='$id']
s.insert(0, {'id': '$id', 'title': '''$title''', 'endpoint': '$endpoint', 'transport': 'local'})
d['servers']=s"
    echo "$USER_ ALL=(root) NOPASSWD: /usr/local/sbin/awgctl" > /etc/sudoers.d/vpn-panel
    chmod 440 /etc/sudoers.d/vpn-panel
    visudo -cf /etc/sudoers.d/vpn-panel >/dev/null || { rm -f /etc/sudoers.d/vpn-panel; die "sudoers check failed"; }
    say "local VPN containers registered as server '$id'"
  fi

  cat > /usr/local/bin/vpn-panel-passwd <<EOF
#!/bin/sh
exec sudo -u $USER_ env PYTHONPATH=$PREFIX/panel:$PREFIX/panel/vendor VPN_PANEL_CONFIG=$ETC/config.json python3 -m vpnpanel set-password
EOF
  chmod 755 /usr/local/bin/vpn-panel-passwd
  install -m 644 "$PREFIX/deploy/vpn-panel.service" /etc/systemd/system/vpn-panel.service
  systemctl daemon-reload
  systemctl enable vpn-panel >/dev/null 2>&1
  if sudo -u $USER_ env PYTHONPATH=$PREFIX/panel VPN_PANEL_CONFIG=$ETC/config.json \
      python3 -c 'from vpnpanel import config, db; c=config.load(); import sys; sys.exit(0 if db.DB(c["db"]).get("admin_password") else 1)'; then
    systemctl restart vpn-panel
    say "panel is running: https://$endpoint:$port"
  else
    say "set the admin password, then the panel starts:  vpn-panel-passwd && systemctl start vpn-panel"
  fi
}

# ---------------------------------------------------------------- add-server
cmd_add_server() {
  need_root
  local id="" title="" host="" sshport=22 endpoint=""
  while [ $# -gt 0 ]; do case "$1" in
    --id) id=$2; shift 2 ;; --title) title=$2; shift 2 ;; --host) host=$2; shift 2 ;;
    --ssh-port) sshport=$2; shift 2 ;; --endpoint) endpoint=$2; shift 2 ;; *) die "unknown option $1" ;; esac; done
  [ -n "$id" ] && [ -n "$host" ] || die "--id and --host are required"
  [ -f $ETC/config.json ] || die "install the panel first: ./install.sh panel"
  title=${title:-$id}; endpoint=${endpoint:-$host}
  local me pub
  me=$(public_ip)
  pub=$(cat $ETC/ssh/id_ed25519.pub)
  say "connecting to root@$host (your own SSH key or password, once)"
  scp -P "$sshport" -q "$PREFIX/server/awgctl" "root@$host:/usr/local/sbin/awgctl"
  ssh -p "$sshport" "root@$host" "chmod 755 /usr/local/sbin/awgctl; mkdir -p /root/.ssh; chmod 700 /root/.ssh;
    touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys;
    grep -v 'vpn-panel@' /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.tmp || true;
    echo 'command=\"/usr/local/sbin/awgctl --ssh\",from=\"$me\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $pub' >> /root/.ssh/authorized_keys.tmp;
    mv /root/.ssh/authorized_keys.tmp /root/.ssh/authorized_keys"
  json_edit $ETC/config.json "
s=[x for x in d['servers'] if x['id']!='$id']
s.append({'id': '$id', 'title': '''$title''', 'endpoint': '$endpoint', 'transport': 'ssh',
          'ssh_host': '$host', 'ssh_port': $sshport, 'ssh_user': 'root', 'ssh_key': '$ETC/ssh/id_ed25519'})
d['servers']=s"
  systemctl restart vpn-panel 2>/dev/null || true
  sudo -u $USER_ env PYTHONPATH=$PREFIX/panel:$PREFIX/panel/vendor VPN_PANEL_CONFIG=$ETC/config.json \
    python3 -m vpnpanel poll-once >/dev/null && say "server '$id' connected and polled" \
    || die "server '$id' added but polling failed: check docker/awgctl on $host"
}

# ---------------------------------------------------------------- server
cmd_server() {
  need_root
  local proto="" remove=0 port=""
  while [ $# -gt 0 ]; do case "$1" in
    --proto) proto=$2; shift 2 ;; --remove) remove=1; shift ;; --port) port=$2; shift 2 ;;
    *) die "unknown option $1" ;; esac; done
  case "$proto" in
    awg3) ;;
    sstp|vless) die "protocol '$proto' is planned but not shipped yet" ;;
    *) die "--proto awg3 is required" ;;
  esac
  sync_code
  if [ "$remove" = 1 ]; then
    "$PREFIX/server/install-awg3.sh" --remove
    return
  fi
  command -v docker >/dev/null || { say "installing docker"; apt-get update -qq && apt-get install -y -qq docker.io >/dev/null; }
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    if docker pull -q "$GHCR_IMAGE" >/dev/null 2>&1; then
      docker tag "$GHCR_IMAGE" "$IMAGE"
    else
      say "no prebuilt image reachable, building locally (needs ~1 GB free)"
      docker build -q -t "$IMAGE" "$PREFIX/images/awg3" >/dev/null
    fi
  fi
  install_awgctl; install_guard
  AWG3_IMAGE=$IMAGE "$PREFIX/server/install-awg3.sh" ${port:+--port "$port"}
}

case "${1:-}" in
  panel) shift; cmd_panel "$@" ;;
  add-server) shift; cmd_add_server "$@" ;;
  server) shift; cmd_server "$@" ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
