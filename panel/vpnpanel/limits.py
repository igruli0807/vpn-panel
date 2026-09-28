"""Per-client expiry date and traffic quota: automatic disable, warnings, monthly re-enable.

Runs after every poll. A client switched off here carries auto_off = 'expired' | 'quota'; extending the date or
raising the quota in the card switches it back on. Monthly quotas start again on the 1st (panel timezone).
"""
import logging
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from . import service

log = logging.getLogger("vpnpanel.limits")
GB = 1024 ** 3
WARN_DAYS = 3


def period_start(cfg, period, created):
    if period == "total":
        return 0
    now = datetime.now(ZoneInfo(cfg["timezone"]))
    return int(now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())


def period_key(cfg, period):
    return "total" if period == "total" else datetime.now(ZoneInfo(cfg["timezone"])).strftime("%Y-%m")


def usage(cfg, db, c):
    since = period_start(cfg, c.get("quota_period") or "month", c["created"])
    r = db.one("SELECT COALESCE(SUM(rx+tx),0) b FROM traffic WHERE server=? AND container=? AND pub=? AND hour>=?",
               (c["server"], c["container"], c["pub"], since - since % 3600))
    return r["b"]


def _tell_client(db, c, text):
    from . import delivery
    token = db.get("tg_token")
    if token and c.get("tg_chat_id"):
        try:
            delivery.tg_call(token, "sendMessage", {"chat_id": c["tg_chat_id"], "text": text})
        except delivery.DeliveryError as e:
            log.warning("limit message to client %s: %s", c["id"], e)


def _tell_owners(db, text):
    from . import alerts
    alerts._send(db, text)


def _switch_off(cfg, db, c, reason, why):
    try:
        service.disable(cfg, db, c["id"])
    except service.OpError as e:
        log.warning("auto-disable %s failed: %s", c["id"], e)
        return
    db.x("UPDATE clients SET auto_off=? WHERE id=?", (reason, c["id"]))
    db.event(f"клиент «{c['name']}» отключён автоматически: {why}", None, None, c["server"])
    _tell_client(db, c, f"Доступ к VPN приостановлен: {why}. Напишите администратору, если он нужен дальше.")
    _tell_owners(db, f"⏸ «{c['name']}» отключён автоматически: {why}")


def switch_on(cfg, db, c, why):
    service.enable(cfg, db, c["id"])
    db.x("UPDATE clients SET auto_off=NULL WHERE id=?", (c["id"],))
    db.event(f"клиент «{c['name']}» снова включён: {why}", None, None, c["server"])
    _tell_client(db, c, f"Доступ к VPN снова включён ({why}).")


def enforce(cfg, db):
    now = int(time.time())
    rows = db.q("""SELECT * FROM clients WHERE deleted IS NULL AND (expires IS NOT NULL OR quota_gb IS NOT NULL)""")
    prot = set(cfg.get("protected_pubkeys") or [])
    for c in rows:
        if c["pub"] in prot:
            continue
        try:
            _one(cfg, db, c, now)
        except Exception:
            log.exception("limits for client %s", c["id"])


def _one(cfg, db, c, now):
    exp, quota = c["expires"], c["quota_gb"]
    used = usage(cfg, db, c) if quota else 0
    if c["disabled"]:
        # monthly quota: a new month brings the client back automatically
        if (c["auto_off"] == "quota" and (c["quota_period"] or "month") == "month" and quota and used < quota * GB
                and not (exp and exp <= now)):
            switch_on(cfg, db, c, "новый месяц, лимит обнулился")
        return
    if exp and exp <= now:
        return _switch_off(cfg, db, c, "expired", "закончился срок доступа")
    if quota and used >= quota * GB:
        per = "в этом месяце" if (c["quota_period"] or "month") == "month" else ""
        return _switch_off(cfg, db, c, "quota", f"исчерпан лимит трафика {quota:g} ГБ {per}".strip())
    if exp and exp - now < WARN_DAYS * 86400 and c["warn_exp"] != exp:
        days = max(1, (exp - now) // 86400)
        _tell_client(db, c, f"Доступ к VPN закончится через {days} дн. Если он нужен дальше — напишите администратору.")
        db.x("UPDATE clients SET warn_exp=? WHERE id=?", (exp, c["id"]))
    key = period_key(cfg, c["quota_period"] or "month")
    if quota and used >= 0.9 * quota * GB and c["warn_quota"] != key:
        _tell_client(db, c, f"Использовано 90% лимита трафика ({used / GB:.1f} из {quota:g} ГБ).")
        db.x("UPDATE clients SET warn_quota=? WHERE id=?", (key, c["id"]))


def set_limits(cfg, db, c, expires, quota_gb, period):
    """From the client card. Extending the date / raising the quota turns an auto-disabled client back on."""
    db.x("UPDATE clients SET expires=?, quota_gb=?, quota_period=? WHERE id=?",
         (expires, quota_gb, period, c["id"]))
    c = db.one("SELECT * FROM clients WHERE id=?", (c["id"],))
    now = int(time.time())
    if c["disabled"] and c["auto_off"]:
        still_expired = c["expires"] and c["expires"] <= now
        over = c["quota_gb"] and usage(cfg, db, c) >= c["quota_gb"] * GB
        if not still_expired and not over:
            switch_on(cfg, db, c, "срок или лимит продлён")
            return True
    return False
