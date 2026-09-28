#!/bin/sh
# Let's Encrypt certificate (RSA, issued by acme.sh) -> panel, SSTP container, exim.
# acme.sh runs this after every issue/renewal (install.sh domain sets it as --reloadcmd).
SRC=/etc/ssl/vpn-panel
if [ -f /etc/vpn-panel/config.json ]; then
  install -m 644 -g vpnpanel $SRC/fullchain.pem /etc/vpn-panel/tls.crt
  install -m 640 -g vpnpanel $SRC/privkey.pem /etc/vpn-panel/tls.key
  systemctl is-active --quiet vpn-panel && systemctl restart vpn-panel
fi
if [ -d /opt/sstp ]; then
  install -m 644 $SRC/fullchain.pem /opt/sstp/server.crt
  install -m 600 $SRC/privkey.pem /opt/sstp/server.key
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx sstp && docker restart sstp >/dev/null
fi
if [ -d /etc/exim4 ]; then
  install -m 644 $SRC/fullchain.pem /etc/exim4/tls.crt
  install -m 640 -g Debian-exim $SRC/privkey.pem /etc/exim4/tls.key 2>/dev/null || install -m 640 $SRC/privkey.pem /etc/exim4/tls.key
  systemctl is-active --quiet exim4 && systemctl restart exim4
fi
logger -t le-deploy "certificate deployed to panel/sstp/exim"
