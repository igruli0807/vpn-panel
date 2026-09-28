"""Self-service VPN requests through the Telegram bot, approved by a person.

Anyone can press «Запросить доступ» in the bot; nothing is created until an owner approves the request — with a
button in Telegram (owners who linked their Telegram in «Настройки») or on the «Заявки» page. Approving creates a
client on the chosen server/protocol and the bot sends the config right away.
"""
import json
import time

from . import access, service

KIND_LABEL = {"awg3": "AWG 3.1", "awg2": "AWG 2.0", "vless": "VLESS", "sstp": "SSTP"}
ORDER = {"awg3": 0, "vless": 1, "awg2": 2, "sstp": 3}
MAX_PENDING = 50
REJECT_COOLDOWN = 24 * 3600


class RequestError(Exception):
    pass


def targets(cfg, db, me=None):
    """[(server, container, label)] where a client can be created now (unit up, protocol supports adding)."""
    titles = {s["id"]: s.get("title", s["id"]) for s in cfg["servers"]}
    allowed = set(access.servers(cfg, me)) if me else set(titles)
    rows = db.q("SELECT server, container, kind, port FROM health WHERE up=1")
    out = []
    for r in sorted(rows, key=lambda r: (ORDER.get(r["kind"], 9), r["server"])):
        if r["kind"] in service.CAN_ADD and r["server"] in allowed and r["server"] in titles:
            label = f"{KIND_LABEL.get(r['kind'], r['kind'])} · {titles[r['server']]}"
            if r["container"] == "sstp-host":
                label += " (системный)"
            out.append((r["server"], r["container"], label))
    return out


def create(db, chat_id, username, full_name):
    """-> (request row, is_new). Guards: one open request per chat, a pause after a refusal, a global cap."""
    now = int(time.time())
    open_ = db.one("SELECT * FROM tg_requests WHERE chat_id=? AND status='pending'", (chat_id,))
    if open_:
        return open_, False
    last = db.one("SELECT * FROM tg_requests WHERE chat_id=? AND status='rejected' ORDER BY decided DESC LIMIT 1", (chat_id,))
    if last and now - (last["decided"] or 0) < REJECT_COOLDOWN:
        raise RequestError("Прошлую заявку отклонили. Попробуйте позже.")
    if db.one("SELECT COUNT(*) n FROM tg_requests WHERE status='pending'")["n"] >= MAX_PENDING:
        raise RequestError("Сейчас слишком много заявок. Попробуйте позже.")
    rid = db.x("INSERT INTO tg_requests(chat_id, username, full_name, status, created) VALUES(?,?,?, 'pending', ?)",
               (chat_id, (username or "")[:64], (full_name or "")[:128], now))
    return db.one("SELECT * FROM tg_requests WHERE id=?", (rid,)), True


def get(db, rid):
    r = db.one("SELECT * FROM tg_requests WHERE id=?", (rid,))
    if not r:
        raise RequestError("нет такой заявки")
    return r


def display_name(r):
    name = r["full_name"] or (("@" + r["username"]) if r["username"] else f"tg {r['chat_id']}")
    return name + (f" (@{r['username']})" if r["username"] and r["full_name"] else "")


def approve(cfg, db, rid, sid, container, user_id, me=None):
    """Create the client, bind the requester's chat, send the config. -> client id."""
    from . import delivery
    r = get(db, rid)
    if r["status"] != "pending":
        raise RequestError("заявка уже рассмотрена")
    if me is not None and not access.can(cfg, me, sid):
        raise RequestError("нет доступа к этому серверу")
    if (sid, container) not in [(t[0], t[1]) for t in targets(cfg, db)]:
        raise RequestError("этот протокол сейчас недоступен на сервере")
    name = (r["full_name"] or r["username"] or f"tg {r['chat_id']}")[:48] + " (Telegram)"
    cid = service.create_client(cfg, db, sid, container, name)
    db.x("UPDATE clients SET tg_chat_id=?, created_by=? WHERE id=?", (r["chat_id"], user_id, cid))
    db.x("UPDATE tg_requests SET status='approved', decided=?, decided_by=?, client_id=? WHERE id=? AND status='pending'",
         (int(time.time()), user_id, cid, rid))
    c = db.one("SELECT * FROM clients WHERE id=?", (cid,))
    delivery.tg_send_client(cfg, db, c, r["chat_id"])
    db.event(f"заявка #{rid} ({display_name(r)}) одобрена → клиент «{name}»", None, user_id, sid)
    return cid


def reject(db, rid, user_id):
    from . import delivery
    r = get(db, rid)
    if r["status"] != "pending":
        raise RequestError("заявка уже рассмотрена")
    db.x("UPDATE tg_requests SET status='rejected', decided=?, decided_by=? WHERE id=?", (int(time.time()), user_id, rid))
    token = db.get("tg_token")
    if token:
        try:
            delivery.tg_call(token, "sendMessage", {"chat_id": r["chat_id"], "text": "Заявку на VPN отклонили."})
        except delivery.DeliveryError:
            pass
    db.event(f"заявка #{rid} ({display_name(r)}) отклонена", None, user_id)


def pending_count(db):
    return db.one("SELECT COUNT(*) n FROM tg_requests WHERE status='pending'")["n"]


def save_targets(db, rid, tl):
    db.x("UPDATE tg_requests SET targets=? WHERE id=?", (json.dumps(tl, ensure_ascii=False), rid))
