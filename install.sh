#!/bin/bash
# VPN panel starter pack.
#
#   ./install.sh panel [--port 2053] [--id fin] [--title "Финляндия"] [--endpoint IP] [--tz Europe/Helsinki]
#       install the web panel on this host (and register this host's VPN containers, if any)
#   ./install.sh add-server --id usa --title "США" --host IP [--ssh-port 22] [--endpoint IP]
#       run on the panel host: connect another VPN server (uses your root SSH access once)
#   ./install.sh server --proto awg3|sstp|vless [--port N] [--sni HOST]
#       run on a VPN host: install a protocol in docker (awg3 / sstp / xray container) + vpnctl
#   ./install.sh server --remove --proto awg3|sstp|vless
#   Servers can also be added and protocols installed from the panel UI («Серверы»).
#   ./install.sh backup [--to HOST] [--ssh-port 22]
#       run on the panel host: nightly encrypted backup (local 7 copies; with --to also to HOST, 14 copies there)
#
# Re-running any mode is safe. Nothing secret is written into the repository directory.
set -euo pipefail

REPO=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/vpn-panel
ETC=/etc/vpn-panel
LIB=/var/lib/vpn-panel
USER_=vpnpanel
declare -A IMAGE_OF=([awg3]="awg3:3.1.20260828" [sstp]="sstp:1.14.0" [vless]="xray:26.3.27")
GHCR=${VPN_PANEL_GHCR:-ghcr.io/igruli0807}

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

install_vpnctl() {
  install -m 755 "$PREFIX/server/vpnctl" /usr/local/sbin/vpnctl
  ln -sf vpnctl /usr/local/sbin/awgctl
  install -d -m 755 /usr/local/lib/vpnctl
  install -m 755 "$PREFIX/server/install-awg3.sh" /usr/local/lib/vpnctl/install-awg3.sh
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
  # sshpass lets the panel connect a new server by root password once (the password is never stored)
  command -v sshpass >/dev/null || { say "installing sshpass"; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass >/dev/null || say "WARNING: sshpass not installed — servers can be added by key only"; }
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

  # This host runs VPN containers too -> manage them locally through sudo vpnctl.
  if command -v docker >/dev/null && docker ps --format '{{.Names}}' | grep -qE '^(awg3|sstp|xray|amnezia-(awg2?|wireguard))$' \
     || systemctl is-active --quiet accel-ppp 2>/dev/null; then
    install_vpnctl; command -v docker >/dev/null && install_guard
    id=${id:-$(hostname -s)}; title=${title:-$id}
    json_edit $ETC/config.json "
s=[x for x in d['servers'] if x['id']!='$id']
s.insert(0, {'id': '$id', 'title': '''$title''', 'endpoint': '$endpoint', 'transport': 'local'})
d['servers']=s"
    echo "$USER_ ALL=(root) NOPASSWD: /usr/local/sbin/vpnctl, /usr/local/sbin/awgctl" > /etc/sudoers.d/vpn-panel
    chmod 440 /etc/sudoers.d/vpn-panel
    visudo -cf /etc/sudoers.d/vpn-panel >/dev/null || { rm -f /etc/sudoers.d/vpn-panel; die "sudoers check failed"; }
    say "local VPN containers registered as server '$id'"
  fi

  cat > /usr/local/bin/vpn-panel-passwd <<EOF
#!/bin/sh
exec sudo -u $USER_ env PYTHONPATH=$PREFIX/panel:$PREFIX/panel/vendor VPN_PANEL_CONFIG=$ETC/config.json python3 -m vpnpanel set-password "\$@"
EOF
  chmod 755 /usr/local/bin/vpn-panel-passwd
  install -m 644 "$PREFIX/deploy/vpn-panel.service" /etc/systemd/system/vpn-panel.service
  systemctl daemon-reload
  systemctl enable vpn-panel >/dev/null 2>&1
  if sudo -u $USER_ env PYTHONPATH=$PREFIX/panel VPN_PANEL_CONFIG=$ETC/config.json \
      python3 -c 'from vpnpanel import config, db; c=config.load(); import sys; d=db.DB(c["db"]); sys.exit(0 if d.one("SELECT 1 FROM users WHERE pw_hash IS NOT NULL") else 1)'; then
    systemctl restart vpn-panel
    say "panel is running: https://$endpoint:$port"
  else
    say "set the owner password (login: admin), then the panel starts:  vpn-panel-passwd && systemctl start vpn-panel"
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
  tar -C "$PREFIX/server" -cf - vpnctl install-awg3.sh awg-guard.sh awg-guard.service awg-guard.timer | \
    ssh -p "$sshport" "root@$host" "mkdir -p /usr/local/lib/vpnctl && tar -C /usr/local/lib/vpnctl -xf - &&
      install -m 755 /usr/local/lib/vpnctl/vpnctl /usr/local/sbin/vpnctl && ln -sf vpnctl /usr/local/sbin/awgctl"
  ssh -p "$sshport" "root@$host" "mkdir -p /root/.ssh; chmod 700 /root/.ssh;
    touch /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys;
    grep -v 'vpn-panel@' /root/.ssh/authorized_keys > /root/.ssh/authorized_keys.tmp || true;
    echo 'command=\"/usr/local/sbin/vpnctl --ssh\",from=\"$me\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $pub' >> /root/.ssh/authorized_keys.tmp;
    mv /root/.ssh/authorized_keys.tmp /root/.ssh/authorized_keys"
  json_edit $ETC/config.json "
s=[x for x in d['servers'] if x['id']!='$id']
s.append({'id': '$id', 'title': '''$title''', 'endpoint': '$endpoint', 'transport': 'ssh',
          'ssh_host': '$host', 'ssh_port': $sshport, 'ssh_user': 'root', 'ssh_key': '$ETC/ssh/id_ed25519'})
d['servers']=s"
  systemctl restart vpn-panel 2>/dev/null || true
  sudo -u $USER_ env PYTHONPATH=$PREFIX/panel:$PREFIX/panel/vendor VPN_PANEL_CONFIG=$ETC/config.json \
    python3 -m vpnpanel poll-once >/dev/null && say "server '$id' connected and polled" \
    || die "server '$id' added but polling failed: check docker/vpnctl on $host"
}

# ---------------------------------------------------------------- server
cmd_server() {
  need_root
  local proto="" remove=0 port="" sni=""
  while [ $# -gt 0 ]; do case "$1" in
    --proto) proto=$2; shift 2 ;; --remove) remove=1; shift ;; --port) port=$2; shift 2 ;; --sni) sni=$2; shift 2 ;;
    *) die "unknown option $1" ;; esac; done
  [ -n "${IMAGE_OF[$proto]:-}" ] || die "--proto awg3|sstp|vless is required"
  sync_code
  install_vpnctl
  if [ "$remove" = 1 ]; then
    vpnctl uninstall "$proto"
    return
  fi
  command -v docker >/dev/null || { say "installing docker"; apt-get update -qq && apt-get install -y -qq docker.io >/dev/null; }
  local image=${IMAGE_OF[$proto]} name=${IMAGE_OF[$proto]%%:*}
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    if docker pull -q "$GHCR/$image" >/dev/null 2>&1; then
      docker tag "$GHCR/$image" "$image"
    else
      say "no prebuilt image reachable, building $name locally (needs ~1 GB free)"
      docker build -q -t "$image" "$PREFIX/images/$name" >/dev/null
    fi
  fi
  install_guard
  vpnctl install "$proto" ${port:+--port "$port"} ${sni:+--sni "$sni"}
}

# ---------------------------------------------------------------- backup
cmd_backup() {
  need_root
  local to="" sshport=22
  while [ $# -gt 0 ]; do case "$1" in
    --to) to=$2; shift 2 ;; --ssh-port) sshport=$2; shift 2 ;; *) die "unknown option $1" ;; esac; done
  [ -f $ETC/config.json ] || die "install the panel first: ./install.sh panel"
  sync_code
  install -m 755 "$PREFIX/deploy/vpn-panel-backup.sh" /usr/local/sbin/vpn-panel-backup.sh
  install -m 644 "$PREFIX/deploy/vpn-panel-backup.service" "$PREFIX/deploy/vpn-panel-backup.timer" /etc/systemd/system/
  if [ ! -f $ETC/backup.pass ]; then
    (umask 077; openssl rand -base64 48 > $ETC/backup.pass)
    say "backup passphrase created: $ETC/backup.pass — COPY IT SOMEWHERE SAFE, backups are useless without it"
  fi
  if [ -n "$to" ]; then
    [ -f $ETC/ssh/backup_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -C "vpn-panel-backup@$(hostname -s)" -f $ETC/ssh/backup_ed25519
    local me pub
    me=$(public_ip); pub=$(cat $ETC/ssh/backup_ed25519.pub)
    say "installing the receiver on root@$to (your own SSH access, once)"
    ssh -p "$sshport" "root@$to" "cat > /usr/local/sbin/vpn-backup-recv && chmod 755 /usr/local/sbin/vpn-backup-recv" < "$PREFIX/server/vpn-backup-recv"
    ssh -p "$sshport" "root@$to" "mkdir -p /root/.ssh && chmod 700 /root/.ssh && touch /root/.ssh/authorized_keys &&
      (grep -v 'vpn-panel-backup@' /root/.ssh/authorized_keys > /root/.ssh/ak.tmp || true) &&
      echo 'command=\"/usr/local/sbin/vpn-backup-recv\",from=\"$me\",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding $pub' >> /root/.ssh/ak.tmp &&
      chmod 600 /root/.ssh/ak.tmp && mv /root/.ssh/ak.tmp /root/.ssh/authorized_keys"
    printf 'BACKUP_HOST=%s\nBACKUP_PORT=%s\n' "$to" "$sshport" > $ETC/backup.env
  fi
  systemctl daemon-reload
  systemctl enable --now vpn-panel-backup.timer >/dev/null 2>&1
  /usr/local/sbin/vpn-panel-backup.sh
}

case "${1:-}" in
  panel) shift; cmd_panel "$@" ;;
  add-server) shift; cmd_add_server "$@" ;;
  server) shift; cmd_server "$@" ;;
  backup) shift; cmd_backup "$@" ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
