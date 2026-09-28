"""Alerts to the owners' Telegram (the panel's own bot): one message when a problem starts (after a grace period),
one when it is over. State lives in the DB, so restarts do not repeat messages.

Checked every poll: server unreachable, VPN interface down inside a container.
Checked hourly: certificates (panel, SSTP) expiring in < 14 days, less than 300 MB free on a server.
"""
import logging
import os
import ssl
import tempfile
import time

from . import runner

log = logging.getLogger("vpnpanel.alerts")
GRACE = 120            # seconds a problem must last before anyone is woken up
CERT_DAYS = 14
DISK_MB = 300

SCHEMA = """CREATE TABLE IF NOT EXISTS alerts (
  key TEXT PRIMARY KEY, text TEXT NOT NULL, since INTEGER NOT NULL, notified INTEGER NOT NULL DEFAULT 0
)"""


def _cert_expiry(pem_text=None, path=None):
    """-> unix time of notAfter, or None."""
    tmp = None
    try:
        if pem_text:
            fd, tmp = tempfile.mkstemp()
            with os.fdopen(fd, "w") as f:
                f.write(pem_text)
            path = tmp
        info = ssl._ssl._test_decode_cert(path)  # stdlib, no network
        return int(ssl.cert_time_to_seconds(info["notAfter"]))
    except (OSError, ValueError, KeyError, ssl.SSLError):
        return None
    finally:
        if tmp:
            os.remove(tmp)


def _send(db, text):
    from . import delivery
    token = db.get("tg_token")
    if not token:
        return 0
    n = 0
    for u in db.q("SELECT login, tg_chat_id FROM users WHERE role='owner' AND disabled=0 AND tg_chat_id IS NOT NULL"):
        try:
            delivery.tg_call(token, "sendMessage", {"chat_id": u["tg_chat_id"], "text": text})
            n += 1
        except delivery.DeliveryError as e:
            log.warning("alert to %s: %s", u["login"], e)
    return n


def current_problems(cfg, db, hourly):
    """-> {key: text} of problems that exist right now."""
    titles = {s["id"]: s.get("title", s["id"]) for s in cfg["servers"]}
    probs = {}
    down = set()
    for sh in db.q("SELECT * FROM server_health WHERE ok=0"):
        if sh["server"] in titles:
            down.add(sh["server"])
            probs[f"srv:{sh['server']}"] = f"сервер «{titles[sh['server']]}» не отвечает: {sh['error'] or 'нет ответа'}"
    for h in db.q("SELECT * FROM health WHERE up=0"):
        if h["server"] in titles and h["server"] not in down:
            probs[f"down:{h['server']}:{h['container']}"] = (
                f"{titles[h['server']]} / {h['container']}: VPN-интерфейс не поднят — клиенты не подключаются")
    if hourly:
        _hourly_checks(cfg, db, titles)
    for k, text in (db.get_json("alert_hourly") or {}).items():
        probs[k] = text
    return probs


def _hourly_checks(cfg, db, titles):
    found = {}
    now = time.time()
    exp = _cert_expiry(path=cfg.get("tls_cert"))
    if exp and exp - now < CERT_DAYS * 86400:
        found["cert:panel"] = f"сертификат панели истекает {time.strftime('%d.%m.%Y', time.localtime(exp))} — автопродление не сработало?"
    for s in cfg["servers"]:
        try:
            info = runner.run(cfg, s, "preflight", timeout=60)
        except runner.CtlError:
            continue  # unreachable is reported by the poll check
        from . import servers
        servers.set_info(db, s["id"], info)
        if info.get("free_mb") is not None and info["free_mb"] < DISK_MB:
            found[f"disk:{s['id']}"] = f"на сервере «{titles.get(s['id'], s['id'])}» свободно {info['free_mb']} МБ диска"
        for unit in ("sstp", "sstp-host"):
            if unit in (info.get("units") or []):
                try:
                    p = runner.run(cfg, s, "params", unit, timeout=60)
                except runner.CtlError:
                    continue
                if not p.get("self_signed"):
                    exp = _cert_expiry(pem_text=p.get("cert_pem"))
                    if exp and exp - now < CERT_DAYS * 86400:
                        found[f"cert:{s['id']}:{unit}"] = (
                            f"сертификат SSTP на «{titles.get(s['id'], s['id'])}» истекает "
                            f"{time.strftime('%d.%m.%Y', time.localtime(exp))}")
    db.set_json("alert_hourly", found)


def evaluate(cfg, db, hourly=False):
    db.x(SCHEMA)
    now = int(time.time())
    probs = current_problems(cfg, db, hourly)
    active = {r["key"]: r for r in db.q("SELECT * FROM alerts")}
    for key, text in probs.items():
        a = active.get(key)
        if not a:
            db.x("INSERT INTO alerts(key, text, since) VALUES(?,?,?)", (key, text, now))
            a = {"key": key, "text": text, "since": now, "notified": 0}
        if not a["notified"] and now - a["since"] >= GRACE:
            _send(db, "🔴 " + text)
            db.x("UPDATE alerts SET notified=1, text=? WHERE key=?", (text, key))
            db.event("тревога: " + text)
    for key, a in active.items():
        if key not in probs:
            if a["notified"]:
                mins = max(1, (now - a["since"]) // 60)
                _send(db, f"✅ снова в порядке ({mins} мин): {a['text']}")
                db.event("восстановлено: " + a["text"])
            db.x("DELETE FROM alerts WHERE key=?", (key,))
