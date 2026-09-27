#!/bin/bash
# What works and what is missing — on a panel host, a VPN host, or both.
ok()   { echo "  ✅ $*"; }
warn() { echo "  ⚠️  $*"; }
bad()  { echo "  ❌ $*"; FAIL=1; }
FAIL=0
echo "Система"
free_mb=$(df -Pm / | awk 'NR==2{print $4}'); [ "$free_mb" -ge 300 ] && ok "диск: свободно ${free_mb} МБ" || warn "диск: свободно всего ${free_mb} МБ"
avail=$(free -m | awk '/^Mem/{print $7}'); swap=$(free -m | awk '/^Swap/{print $2}')
[ "$avail" -ge 60 ] && ok "память: доступно ${avail} МБ, swap ${swap} МБ" || warn "память: доступно ${avail} МБ, swap ${swap} МБ"
systemctl is-enabled netfilter-persistent >/dev/null 2>&1 && warn "включён netfilter-persistent — не делать 'netfilter-persistent save' при живых контейнерах (L0127)"

if command -v docker >/dev/null && docker ps --format '{{.Names}}' | grep -qE '^(awg3|amnezia-)'; then
  echo "VPN на этом хосте"
  command -v awgctl >/dev/null && ok "awgctl установлен" || bad "awgctl не установлен (./install.sh server --proto awg3)"
  systemctl is-active -q awg-guard.timer && ok "сторож awg-guard работает" || warn "сторож awg-guard не включён"
  if command -v awgctl >/dev/null; then
    awgctl list | python3 /dev/fd/3 3<<'PY' || bad "awgctl list не отработал"
import json, sys
for c in json.load(sys.stdin):
    mark = "✅" if c["up"] else "❌"
    tail = "" if c["up"] else " — ИНТЕРФЕЙС НЕ ПОДНЯТ"
    print("  %s %s: %s, UDP %s, клиентов %s, отключено %s%s" % (mark, c["name"], c["kind"], c["port"], c["peers"], c["disabled"], tail))
PY
  fi
fi

if [ -f /etc/vpn-panel/config.json ]; then
  echo "Панель"
  systemctl is-active -q vpn-panel && ok "служба vpn-panel работает" || bad "служба vpn-panel не запущена (journalctl -u vpn-panel)"
  port=$(python3 -c 'import json;print(json.load(open("/etc/vpn-panel/config.json")).get("port",2053))')
  ss -Hltn "sport = :$port" | grep -q . && ok "слушает TCP $port" || bad "порт $port не слушается"
  end=$(openssl x509 -enddate -noout -in /etc/vpn-panel/tls.crt 2>/dev/null | cut -d= -f2)
  [ -n "$end" ] && ok "сертификат до $end" || bad "нет сертификата /etc/vpn-panel/tls.crt"
  [ "$(stat -c %a /var/lib/vpn-panel/panel.db 2>/dev/null)" = 600 ] && ok "база панели: права 600" || warn "база панели не создана или права не 600"
  sudo -u vpnpanel env PYTHONPATH=/opt/vpn-panel/panel:/opt/vpn-panel/panel/vendor VPN_PANEL_CONFIG=/etc/vpn-panel/config.json \
    python3 -m vpnpanel poll-once 2>/dev/null | python3 /dev/fd/3 3<<'PY' || bad "опрос серверов не отработал"
import json, sys
for sid, v in json.load(sys.stdin).items():
    if not v["ok"]:
        print("  ❌ сервер %s: не отвечает" % sid)
        continue
    down = [c["container"] for c in v["containers"] if not c["up"]]
    mark = "✅" if not down else "⚠️ "
    extra = (", без интерфейса: " + ", ".join(down)) if down else ""
    print("  %s сервер %s: контейнеров %d%s" % (mark, sid, len(v["containers"]), extra))
PY
  rss=$(ps -o rss= -C python3 --sort=-rss 2>/dev/null | head -1); [ -n "$rss" ] && ok "память процесса панели: $((rss/1024)) МБ"
fi
exit $FAIL
