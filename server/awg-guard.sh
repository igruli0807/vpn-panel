#!/bin/sh
# awg-guard: раз в минуту проверяет, что в каждом VPN-контейнере Amnezia поднят интерфейс.
# Контейнер может жить без интерфейса (после перезагрузки 20.09.2026 amnezia-awg2 на finvpn
# неделю так и стоял) — тогда поднимаем его тем же awg-quick/wg-quick, что и start.sh.
for c in $(docker ps --format '{{.Names}}' | grep -E '^amnezia-(awg|wireguard)'); do
  docker exec "$c" sh -c '
    for conf in /opt/amnezia/*/*.conf; do
      [ -f "$conf" ] || continue
      ifc=$(basename "$conf" .conf)
      ip link show "$ifc" >/dev/null 2>&1 && continue
      echo "DOWN $ifc -> up"
      if command -v awg-quick >/dev/null; then awg-quick up "$conf"; else wg-quick up "$conf"; fi >/dev/null 2>&1 \
        && echo "UP $ifc ok" || echo "UP $ifc FAILED"
    done' 2>&1 | while read -r line; do logger -t awg-guard "$c: $line"; done
done
