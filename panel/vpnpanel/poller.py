"""Every poll_seconds: `awgctl dump` on each server -> peer state, hourly traffic, container health.

Counters in `awg show dump` are cumulative since the interface came up; a smaller value than
last time means the interface restarted, so the new value itself is the delta.
"""
import logging
import threading
import time

from . import runner

log = logging.getLogger("vpnpanel.poller")


def _delta(cur, prev):
    return cur - prev if cur >= prev else cur


def poll_server(cfg, db, server):
    now = int(time.time())
    hour = now - now % 3600
    try:
        dump = runner.run(cfg, server, "dump")
    except runner.CtlError as e:
        db.x("INSERT INTO server_health(server, ok, checked, error) VALUES(?,?,?,?) "
             "ON CONFLICT(server) DO UPDATE SET ok=0, checked=excluded.checked, error=excluded.error",
             (server["id"], 0, now, str(e)))
        log.warning("poll %s failed: %s", server["id"], e)
        return False
    online_cut = now - cfg["online_seconds"]
    with db.tx():
        db.conn.execute("INSERT INTO server_health(server, ok, checked, error) VALUES(?,1,?,NULL) "
                        "ON CONFLICT(server) DO UPDATE SET ok=1, checked=excluded.checked, error=NULL",
                        (server["id"], now))
        db.conn.execute("DELETE FROM health WHERE server=?", (server["id"],))
        for container, info in dump.items():
            peers = info.get("peers", [])
            online = sum(1 for p in peers if p["latest_handshake"] >= online_cut)
            last_hs = max([p["latest_handshake"] for p in peers] or [0])
            db.conn.execute("INSERT INTO health VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                            (server["id"], container, info.get("kind"), info.get("port"),
                             1 if info.get("up") else 0, len(peers), online, last_hs, now))
            for p in peers:
                _sync_client(db, server["id"], container, p, now)
                prev = db.conn.execute("SELECT rx, tx FROM peer_state WHERE server=? AND container=? AND pub=?",
                                       (server["id"], container, p["pub"])).fetchone()
                seen = p["latest_handshake"]
                if prev is not None and (p["rx"] or p["tx"]):
                    drx, dtx = _delta(p["rx"], prev["rx"]), _delta(p["tx"], prev["tx"])
                    if drx or dtx:
                        # traffic since the last poll = the client was here, even if the protocol reports no
                        # timestamp (VLESS online list is empty once the connection closed; SSTP between sessions)
                        seen = max(seen, now)
                        db.conn.execute(
                            "INSERT INTO traffic VALUES(?,?,?,?,?,?) ON CONFLICT(server,container,pub,hour) "
                            "DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
                            (server["id"], container, p["pub"], hour, drx, dtx))
                db.conn.execute(
                    "INSERT INTO peer_state VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(server,container,pub) DO UPDATE SET "
                    "rx=excluded.rx, tx=excluded.tx, hs=MAX(hs, excluded.hs), "
                    "endpoint=COALESCE(excluded.endpoint, endpoint), seen=excluded.seen",
                    (server["id"], container, p["pub"], p["rx"], p["tx"], seen,
                     p["endpoint"], now))
            present = [p["pub"] for p in peers]
            marks = ",".join("?" * len(present)) or "''"
            db.conn.execute(f"UPDATE clients SET deleted=? WHERE server=? AND container=? AND deleted IS NULL "
                            f"AND pub NOT IN ({marks})", (now, server["id"], container, *present))
    return True


def _sync_client(db, sid, container, p, now):
    """Peers that exist on the server but not in the panel are imported (no private key)."""
    row = db.conn.execute("SELECT id, name, disabled, deleted FROM clients WHERE server=? AND container=? AND pub=?",
                          (sid, container, p["pub"])).fetchone()
    if row is None:
        db.conn.execute("INSERT INTO clients(server, container, pub, name, ip, source, created, disabled) "
                        "VALUES(?,?,?,?,?,'imported',?,?)",
                        (sid, container, p["pub"], p.get("name") or "", p.get("ip") or "", now,
                         1 if p.get("disabled") else 0))
        return
    upd = {"disabled": 1 if p.get("disabled") else 0, "ip": p.get("ip") or ""}
    if row["deleted"]:
        upd["deleted"] = None  # came back on the server (e.g. re-added in the Amnezia app)
    if p.get("name") and not row["name"]:
        upd["name"] = p["name"]
    sets = ", ".join(f"{k}=?" for k in upd)
    db.conn.execute(f"UPDATE clients SET {sets} WHERE id=?", (*upd.values(), row["id"]))


def cleanup(cfg, db):
    cut = int(time.time()) - cfg["retention_days"] * 86400
    db.x("DELETE FROM traffic WHERE hour < ?", (cut,))
    db.x("DELETE FROM logins WHERE ts < ?", (int(time.time()) - 30 * 86400,))
    db.x("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))
    db.x("DELETE FROM shares WHERE expires < ? AND created < ?", (cut, cut))


def poll_all(cfg, db):
    for s in cfg["servers"]:
        try:
            poll_server(cfg, db, s)
        except Exception:  # keep polling other servers
            log.exception("poll %s crashed", s["id"])


def start(cfg, db):
    def loop():
        n = 0
        while True:
            poll_all(cfg, db)
            n += 1
            if n % 60 == 1:
                cleanup(cfg, db)
            time.sleep(cfg["poll_seconds"])
    t = threading.Thread(target=loop, name="poller", daemon=True)
    t.start()
    return t
