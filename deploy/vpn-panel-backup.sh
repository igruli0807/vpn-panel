#!/bin/bash
# Nightly encrypted backup of the panel: DB snapshot (online, sqlite backup API) + config.json + panel SSH keys.
# AES-256 (openssl, pbkdf2) with the passphrase in /etc/vpn-panel/backup.pass — keep a copy of it elsewhere,
# without it the backup cannot be decrypted. Local copies: /var/backups/vpn-panel (7 newest).
# Off-site copy: set BACKUP_HOST in /etc/vpn-panel/backup.env; the target runs vpn-backup-recv (forced command).
#
# Restore:  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:backup.pass -in FILE | tar -xz
set -euo pipefail
ETC=/etc/vpn-panel
OUT=/var/backups/vpn-panel
KEEP=7
[ -f $ETC/backup.pass ] || { echo "no $ETC/backup.pass"; exit 1; }
BACKUP_HOST="" BACKUP_PORT=22
[ -f $ETC/backup.env ] && . $ETC/backup.env
install -d -m 700 $OUT
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
DB=$(python3 -c 'import json;print(json.load(open("/etc/vpn-panel/config.json")).get("db","/var/lib/vpn-panel/panel.db"))')
python3 - "$DB" "$TMP/panel.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1]); dst = sqlite3.connect(sys.argv[2])
with dst:
    src.backup(dst)
dst.close(); src.close()
PY
cp -a $ETC/config.json "$TMP/"; cp -a $ETC/ssh "$TMP/ssh"
NAME="panel-$(hostname -s)-$(date +%Y%m%d-%H%M).tgz.enc"
tar -C "$TMP" -czf - panel.db config.json ssh | \
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass file:$ETC/backup.pass -out "$OUT/$NAME"
chmod 600 "$OUT/$NAME"
ls -1t $OUT/panel-*.tgz.enc | tail -n +$((KEEP + 1)) | xargs -r rm -f
if [ -n "$BACKUP_HOST" ]; then
  ssh -i $ETC/ssh/backup_ed25519 -p "$BACKUP_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile=$ETC/ssh/backup_known_hosts root@"$BACKUP_HOST" "vpn-backup-recv $NAME" < "$OUT/$NAME"
  echo "backup $NAME: local + $BACKUP_HOST ($(stat -c %s "$OUT/$NAME") bytes)"
else
  echo "backup $NAME: local only ($(stat -c %s "$OUT/$NAME") bytes)"
fi
