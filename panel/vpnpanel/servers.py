"""VPN servers known to the panel.

Servers come from config.json (the panel host itself, anything set up by install.sh) and from the DB (added in the
UI). Both end up in cfg["servers"], which the rest of the panel reads — the list object is updated in place.

Adding a server ("bootstrap") uses the admin's root password or private key exactly once: it copies vpnctl to the
server and installs the panel's own key restricted to `command="vpnctl --ssh"`. The credentials are never stored.
"""
import io
import json
import os
import re
import secrets
import subprocess
import tarfile
import tempfile
import time

from . import runner

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.:-]{1,253}$")
SERVER_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "server")
BUNDLE = ("vpnctl", "install-awg3.sh", "awg-guard.sh", "awg-guard.service", "awg-guard.timer")
PROTOCOLS = {"awg3": "AWG 3.1", "sstp": "SSTP", "vless": "VLESS"}
UNIT_OF = {"awg3": "awg3", "sstp": "sstp", "vless": "xray"}


class ServerError(Exception):
    pass


def refresh(cfg, db):
    """Config servers are mirrored into the DB (source='config'); cfg["servers"] becomes config + panel servers."""
    for s in cfg.get("_config_servers", cfg["servers"]):
        if not db.one("SELECT 1 FROM servers WHERE id=?", (s["id"],)):
            db.x("INSERT INTO servers(id, title, endpoint, transport, ssh_host, ssh_port, ssh_user, source, created) "
                 "VALUES(?,?,?,?,?,?,?, 'config', ?)",
                 (s["id"], s.get("title", s["id"]), s["endpoint"], s["transport"], s.get("ssh_host"),
                  s.get("ssh_port", 22), s.get("ssh_user", "root"), int(time.time())))
    cfg.setdefault("_config_servers", [dict(s) for s in cfg["servers"]])
    by_cfg = {s["id"]: s for s in cfg["_config_servers"]}
    rows = db.q("SELECT * FROM servers ORDER BY (source<>'config'), created, id")
    merged = []
    for r in rows:
        s = dict(by_cfg.get(r["id"], {}))
        s.update({k: r[k] for k in ("id", "title", "endpoint", "transport") if r[k] is not None})
        if r["transport"] == "ssh":
            s.update({"ssh_host": r["ssh_host"], "ssh_port": r["ssh_port"] or 22, "ssh_user": r["ssh_user"] or "root",
                      "ssh_key": s.get("ssh_key") or os.path.join(os.path.dirname(cfg["tls_cert"]), "ssh", "id_ed25519")})
        s["source"] = r["source"]
        s["info"] = json.loads(r["info"]) if r["info"] else None
        merged.append(s)
    cfg["servers"][:] = merged
    return merged


def panel_pubkey(cfg):
    path = os.path.join(os.path.dirname(cfg["tls_cert"]), "ssh", "id_ed25519.pub")
    with open(path) as f:
        return f.read().strip()


def _bundle():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in BUNDLE:
            tar.add(os.path.join(SERVER_DIR, name), arcname=name)
    return buf.getvalue()


class Admin:
    """One-time root access with the admin's password or key (for bootstrap / agent update only)."""

    def __init__(self, cfg, host, port, user, password=None, key_text=None):
        self.cfg, self.host, self.port, self.user = cfg, host, int(port or 22), user or "root"
        self.password, self.keyfile = password, None
        if key_text:
            fd, self.keyfile = tempfile.mkstemp(prefix="vpk-", dir=cfg["run_dir"] if os.path.isdir(cfg["run_dir"]) else None)
            with os.fdopen(fd, "w") as f:
                f.write(key_text.strip() + "\n")
            os.chmod(self.keyfile, 0o600)

    def close(self):
        if self.keyfile and os.path.exists(self.keyfile):
            os.remove(self.keyfile)
        self.password = None

    def cmd(self, remote):
        known = os.path.join(os.path.dirname(self.cfg["db"]), "known_hosts")
        base = ["ssh", "-p", str(self.port), "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new",
                "-o", f"UserKnownHostsFile={known}", "-o", "LogLevel=ERROR"]
        if self.keyfile:
            base = base + ["-i", self.keyfile, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        else:
            base = ["sshpass", "-e"] + base + ["-o", "PubkeyAuthentication=no",
                                               "-o", "PreferredAuthentications=password,keyboard-interactive"]
        return base + [f"{self.user}@{self.host}", remote]

    def run(self, remote, stdin=None, timeout=120):
        env = dict(os.environ, SSHPASS=self.password) if self.password else None
        p = subprocess.run(self.cmd(remote), input=stdin, capture_output=True, timeout=timeout, env=env)
        out = (p.stdout or b"").decode("utf-8", "replace") + (p.stderr or b"").decode("utf-8", "replace")
        if p.returncode != 0:
            if p.returncode == 5 or "Permission denied" in out:
                raise ServerError("вход не удался: неверный пароль или ключ")
            raise ServerError(out.strip()[-300:] or f"ssh exited with {p.returncode}")
        return out


def bootstrap(cfg, db, admin, sid, title, endpoint, log):
    """Copy vpnctl to the server, install the restricted panel key, check it works. Returns preflight info."""
    log(f"подключаюсь к {admin.user}@{admin.host}:{admin.port}")
    whoami = admin.run("id -u; echo ${SSH_CLIENT%% *}").split()
    if not whoami or whoami[0] != "0":
        raise ServerError("нужен вход под root (vpnctl управляет docker и сетью)")
    seen_ip = whoami[1] if len(whoami) > 1 else ""
    log(f"вход выполнен; панель видна серверу как {seen_ip or '?'}")
    log("копирую vpnctl и сторож интерфейсов")
    admin.run("mkdir -p /usr/local/lib/vpnctl && tar -C /usr/local/lib/vpnctl -xf - && "
              "install -m 755 /usr/local/lib/vpnctl/vpnctl /usr/local/sbin/vpnctl && ln -sf vpnctl /usr/local/sbin/awgctl && "
              "chmod 755 /usr/local/lib/vpnctl/install-awg3.sh && "
              "if command -v docker >/dev/null; then install -m 755 /usr/local/lib/vpnctl/awg-guard.sh /usr/local/sbin/ && "
              "install -m 644 /usr/local/lib/vpnctl/awg-guard.service /usr/local/lib/vpnctl/awg-guard.timer /etc/systemd/system/ && "
              "systemctl daemon-reload && systemctl enable --now awg-guard.timer >/dev/null 2>&1; fi; "
              "command -v python3 >/dev/null || echo NO_PYTHON",
              stdin=_bundle())
    log("ставлю ключ панели (только vpnctl, только с адреса панели)")
    line = (f'command="/usr/local/sbin/vpnctl --ssh",' + (f'from="{seen_ip}",' if seen_ip else "") +
            f"no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding {panel_pubkey(cfg)}")
    admin.run("mkdir -p /root/.ssh && chmod 700 /root/.ssh && touch /root/.ssh/authorized_keys && "
              "chmod 600 /root/.ssh/authorized_keys && (grep -v 'vpn-panel@' /root/.ssh/authorized_keys > /root/.ssh/ak.tmp || true) && "
              "cat >> /root/.ssh/ak.tmp && mv /root/.ssh/ak.tmp /root/.ssh/authorized_keys",
              stdin=(line + "\n").encode())
    server = {"id": sid, "title": title, "endpoint": endpoint, "transport": "ssh", "ssh_host": admin.host,
              "ssh_port": admin.port, "ssh_user": "root",
              "ssh_key": os.path.join(os.path.dirname(cfg["tls_cert"]), "ssh", "id_ed25519")}
    log("проверяю доступ ключом панели")
    try:
        info = runner.run(cfg, server, "preflight", timeout=60)
    except runner.CtlError as e:
        raise ServerError(f"ключ панели не работает: {e}")
    log(f"vpnctl {info.get('version')} · {info.get('os')} · docker: {'есть' if info.get('docker') else 'нет'} · "
        f"свободно {info.get('free_mb')} МБ · памяти {info.get('mem_avail_mb')} МБ")
    return server, info


def save(db, server, info, source="panel"):
    now = int(time.time())
    db.x("INSERT INTO servers(id, title, endpoint, transport, ssh_host, ssh_port, ssh_user, source, info, created) "
         "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title, endpoint=excluded.endpoint, "
         "ssh_host=excluded.ssh_host, ssh_port=excluded.ssh_port, info=excluded.info",
         (server["id"], server["title"], server["endpoint"], server["transport"], server.get("ssh_host"),
          server.get("ssh_port"), server.get("ssh_user"), source, json.dumps(info), now))


def set_info(db, sid, info):
    db.x("UPDATE servers SET info=? WHERE id=?", (json.dumps(info), sid))


def remove(cfg, db, sid):
    """Forget a panel-added server: the panel key is removed from it when reachable; clients rows are kept, marked deleted."""
    row = db.one("SELECT * FROM servers WHERE id=?", (sid,))
    if not row:
        raise ServerError("нет такого сервера")
    if row["source"] == "config":
        raise ServerError("этот сервер задан в config.json — убрать его можно только там")
    note = ""
    try:
        runner.run(cfg, cfg.server(sid), "unlink", timeout=30)
    except (runner.CtlError, KeyError) as e:
        note = f" (ключ панели с сервера снять не удалось: {e})"
    now = int(time.time())
    db.x("UPDATE clients SET deleted=COALESCE(deleted, ?) WHERE server=?", (now, sid))
    for t in ("health", "server_health"):
        db.x(f"DELETE FROM {t} WHERE server=?", (sid,))
    db.x("DELETE FROM servers WHERE id=?", (sid,))
    refresh(cfg, db)
    return note


def new_id(db, title):
    base = re.sub(r"[^a-z0-9-]+", "-", (title or "").lower()).strip("-")[:16] or "srv"
    if not ID_RE.match(base):
        base = "srv"
    sid = base
    while db.one("SELECT 1 FROM servers WHERE id=?", (sid,)):
        sid = f"{base}-{secrets.token_hex(2)}"
    return sid
