"""Panel configuration: /etc/vpn-panel/config.json (path overridable by VPN_PANEL_CONFIG)."""
import json
import os

DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 2053,
    "tls_cert": "/etc/vpn-panel/tls.crt",
    "tls_key": "/etc/vpn-panel/tls.key",
    "db": "/var/lib/vpn-panel/panel.db",
    "run_dir": "/run/vpn-panel",
    "timezone": "UTC",
    "public_url": "",
    "share_ttl_hours": 72,
    "poll_seconds": 60,
    "online_seconds": 180,
    "retention_days": 90,
    "session_hours": 12,
    "login_max_failures": 5,
    "login_window_minutes": 15,
    "login_block_minutes": 60,
    "awgctl": "/usr/local/sbin/vpnctl",   # key name kept for old configs
    "use_sudo": True,
    # Peers that must never be disabled or deleted from the panel (e.g. an admin's own tunnel).
    "protected_pubkeys": [],
    # [{"id": "fin", "title": "Финляндия", "endpoint": "1.2.3.4", "transport": "local"},
    #  {"id": "usa", "title": "США", "endpoint": "5.6.7.8", "transport": "ssh",
    #   "ssh_host": "5.6.7.8", "ssh_port": 22, "ssh_user": "root", "ssh_key": "/etc/vpn-panel/ssh/id_ed25519"}]
    "servers": [],
}


class Config(dict):
    def server(self, sid):
        for s in self["servers"]:
            if s["id"] == sid:
                return s
        raise KeyError(sid)


def load(path=None):
    path = path or os.environ.get("VPN_PANEL_CONFIG", "/etc/vpn-panel/config.json")
    with open(path) as f:
        data = json.load(f)
    cfg = Config(DEFAULTS)
    cfg.update(data)
    ids = [s["id"] for s in cfg["servers"]]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate server id in config")
    for s in cfg["servers"]:
        if s.get("transport") not in ("local", "ssh"):
            raise ValueError(f"server {s['id']}: transport must be local or ssh")
    return cfg
