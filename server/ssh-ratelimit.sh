#!/bin/sh
# Rate-limit new SSH connections: password brute force otherwise writes tens of thousands of sshd lines a day
# and pushes everything else out of the journal. Touches ONLY its own chain SSH_LIMIT (never a whole-table restore).
# Allow-list (never limited): /etc/vpnctl/ssh-allow, one address/network per line; docker and VPN nets by default.
set -e
ALLOW=/etc/vpnctl/ssh-allow
iptables -N SSH_LIMIT 2>/dev/null || iptables -F SSH_LIMIT
for net in 172.16.0.0/12 10.8.0.0/16 10.12.0.0/24 10.13.0.0/24 $(grep -v '^\s*#' "$ALLOW" 2>/dev/null); do
  iptables -A SSH_LIMIT -s "$net" -j RETURN
done
iptables -A SSH_LIMIT -m hashlimit --hashlimit-name ssh --hashlimit-mode srcip \
  --hashlimit-above 4/minute --hashlimit-burst 6 -j DROP
iptables -C INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j SSH_LIMIT 2>/dev/null \
  || iptables -I INPUT 1 -p tcp --dport 22 -m conntrack --ctstate NEW -j SSH_LIMIT
