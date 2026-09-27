"""Client operations used by the web layer. Every change goes through awgctl first; the panel DB
is updated only after the server confirmed it."""
import hashlib
import ipaddress
import secrets
import time

from . import clientconf, keys, runner

# Where each container kind can be managed from the panel.
CAN_ADD = {"awg3", "awg2"}
KIND_TITLE = {"awg3": "AWG 3.1", "awg2": "AWG 2.0", "legacy": "AWG Legacy", "wireguard": "WireGuard"}


class OpError(Exception):
    pass


def _server(cfg, sid):
    try:
        return cfg.server(sid)
    except KeyError:
        raise OpError("нет такого сервера")


def container_kind(db, sid, container):
    r = db.one("SELECT kind FROM health WHERE server=? AND container=?", (sid, container))
    return r["kind"] if r else None


def create_client(cfg, db, sid, container, name, ip=None):
    s = _server(cfg, sid)
    kind = container_kind(db, sid, container)
    if kind not in CAN_ADD:
        raise OpError("в этот контейнер клиентов добавлять нельзя")
    name = (name or "").strip()[:64]
    if not name:
        raise OpError("нужно имя клиента")
    priv = keys.genkey()
    pub, psk = keys.pubkey(priv), keys.genpsk()
    if not ip:
        ip = runner.run(cfg, s, "next-ip", container)["ip"]
    try:
        runner.run(cfg, s, "add", container, "--pub", pub, "--ip", ip, "--name", name, stdin=psk + "\n")
    except runner.CtlError as e:
        raise OpError(str(e))
    cid = db.x("INSERT INTO clients(server, container, pub, name, ip, priv, psk, source, created) "
               "VALUES(?,?,?,?,?,?,?,'panel',?) ON CONFLICT(server,container,pub) DO UPDATE SET "
               "name=excluded.name, priv=excluded.priv, psk=excluded.psk, source='panel', deleted=NULL",
               (sid, container, pub, name, ip, priv, psk, int(time.time())))
    return db.one("SELECT id FROM clients WHERE server=? AND container=? AND pub=?", (sid, container, pub))["id"] or cid


def get_client(db, cid):
    c = db.one("SELECT * FROM clients WHERE id=?", (cid,))
    if not c:
        raise OpError("нет такого клиента")
    return c


def is_protected(cfg, c):
    return c["pub"] in set(cfg.get("protected_pubkeys") or [])


def _op(cfg, db, cid, action):
    c = get_client(db, cid)
    if is_protected(cfg, c):
        raise OpError("это служебный пир, его нельзя трогать из панели")
    try:
        runner.run(cfg, _server(cfg, c["server"]), action, c["container"], "--pub", c["pub"])
    except runner.CtlError as e:
        raise OpError(str(e))
    return c


def disable(cfg, db, cid):
    _op(cfg, db, cid, "disable")
    db.x("UPDATE clients SET disabled=1 WHERE id=?", (cid,))


def enable(cfg, db, cid):
    _op(cfg, db, cid, "enable")
    db.x("UPDATE clients SET disabled=0 WHERE id=?", (cid,))


def delete(cfg, db, cid):
    _op(cfg, db, cid, "remove")
    db.x("UPDATE clients SET deleted=?, priv=NULL, psk=NULL WHERE id=?", (int(time.time()), cid))
    db.x("UPDATE shares SET revoked=? WHERE client_id=? AND revoked IS NULL", (int(time.time()), cid))


def rename(cfg, db, cid, name):
    c = get_client(db, cid)
    name = (name or "").strip()[:64]
    if not name:
        raise OpError("пустое имя")
    try:
        runner.run(cfg, _server(cfg, c["server"]), "set-name", c["container"], "--pub", c["pub"], "--name", name)
    except runner.CtlError as e:
        raise OpError(str(e))
    db.x("UPDATE clients SET name=? WHERE id=?", (name, cid))


def migrate(cfg, db, cid, target_sid, target_container):
    """New AWG 3.1 client with the same name (and the same last octet when it is free)."""
    c = get_client(db, cid)
    if container_kind(db, target_sid, target_container) != "awg3":
        raise OpError("переезд только в контейнер AWG 3.1")
    ip = None
    try:
        last = ipaddress.ip_interface(c["ip"].split(",")[0].strip()).ip.packed[-1]
        taken = {r["ip"] for r in db.q("SELECT ip FROM clients WHERE server=? AND container=? AND deleted IS NULL",
                                       (target_sid, target_container))}
        params = runner.run(cfg, _server(cfg, target_sid), "params", target_container)
        net = ipaddress.ip_interface(params["subnet"]).network
        cand = f"{net.network_address + last}/32"
        if last not in (0, 1, 255) and cand not in taken:
            ip = cand
    except (ValueError, IndexError, runner.CtlError):
        ip = None
    try:
        new_id = create_client(cfg, db, target_sid, target_container, c["name"] or f"client-{cid}", ip)
    except OpError:
        if ip is None:
            raise
        new_id = create_client(cfg, db, target_sid, target_container, c["name"] or f"client-{cid}")
    db.x("UPDATE clients SET migrated_to=? WHERE id=?", (new_id, cid))
    return new_id


def client_config(cfg, db, c):
    if not c.get("priv"):
        raise OpError("у этого клиента нет ключа в панели (он создан в приложении Amnezia) — "
                      "выдайте ему новый конфиг через «Перевести на AWG 3.1»")
    s = _server(cfg, c["server"])
    params = runner.run(cfg, s, "params", c["container"])
    return clientconf.render(params, private_key=c["priv"], address=c["ip"], preshared_key=c["psk"],
                             endpoint_host=s["endpoint"]), params["kind"]


# ---------- share links ----------

def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_share(cfg, db, cid, hours=None, one_time=False):
    c = get_client(db, cid)
    if not c.get("priv") or c.get("deleted"):
        raise OpError("для этого клиента нельзя сделать ссылку")
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    hours = int(hours or cfg["share_ttl_hours"])
    hours = max(1, min(hours, 24 * 30))
    db.x("INSERT INTO shares(client_id, token_hash, created, expires, one_time) VALUES(?,?,?,?,?)",
         (cid, _h(token), now, now + hours * 3600, 1 if one_time else 0))
    return token


def open_share(db, token):
    """-> client row or None. One-time links are consumed here."""
    if not token or len(token) > 100:
        return None
    now = int(time.time())
    with db.tx():
        s = db.conn.execute("SELECT * FROM shares WHERE token_hash=?", (_h(token),)).fetchone()
        if not s or s["revoked"] or s["expires"] < now or (s["one_time"] and s["used_at"]):
            return None
        db.conn.execute("UPDATE shares SET used_at=COALESCE(used_at, ?) WHERE id=?", (now, s["id"]))
        c = db.conn.execute("SELECT * FROM clients WHERE id=? AND deleted IS NULL", (s["client_id"],)).fetchone()
        return dict(c) if c else None


def revoke_share(db, share_id):
    db.x("UPDATE shares SET revoked=? WHERE id=? AND revoked IS NULL", (int(time.time()), share_id))
