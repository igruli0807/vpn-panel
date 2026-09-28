"""Panel management from Telegram for linked panel users (owners and admins) — the same actions as the web UI.

/start (or /menu) in a chat linked to a panel account opens the menu: clients (list, card, config here, link for the
person, disable/enable, +1 month, delete), new client (server/protocol -> name), requests, servers.
Admins see only their servers, exactly like in the web UI. Navigation edits the menu message instead of spamming.
"""
import json
import time

from . import access, delivery, limits, requests as rq, service

PAGE = 8
STATE_TTL = 900
STATUS = {"on": "🟢", "off": "⚪", "dis": "🔴"}


def _me(db, chat):
    u = db.one("SELECT * FROM users WHERE tg_chat_id=? AND disabled=0", (chat,))
    if not u:
        return None
    return {"user_id": u["id"], "login": u["login"], "name": u["name"], "role": u["role"], "servers": u["servers"]}


def _state(db, chat):
    db.x("CREATE TABLE IF NOT EXISTS tg_state (chat_id INTEGER PRIMARY KEY, state TEXT, data TEXT, updated INTEGER)")
    r = db.one("SELECT * FROM tg_state WHERE chat_id=?", (chat,))
    if not r or time.time() - r["updated"] > STATE_TTL:
        return None, {}
    return r["state"], json.loads(r["data"] or "{}")


def _set_state(db, chat, state, data=None):
    db.x("CREATE TABLE IF NOT EXISTS tg_state (chat_id INTEGER PRIMARY KEY, state TEXT, data TEXT, updated INTEGER)")
    if state is None:
        db.x("DELETE FROM tg_state WHERE chat_id=?", (chat,))
    else:
        db.x("INSERT INTO tg_state VALUES(?,?,?,?) ON CONFLICT(chat_id) DO UPDATE SET state=excluded.state, "
             "data=excluded.data, updated=excluded.updated", (chat, state, json.dumps(data or {}), int(time.time())))


def _show(token, chat, text, rows, msg_id=None):
    fields = {"chat_id": chat, "text": text[:4000], "reply_markup": delivery._kb(rows), "disable_web_page_preview": "true"}
    if msg_id:
        try:
            return delivery.tg_call(token, "editMessageText", dict(fields, message_id=msg_id))
        except delivery.DeliveryError as e:
            if "not modified" in str(e):
                return None
    return delivery.tg_call(token, "sendMessage", fields)


def _size(n):
    n = float(n or 0)
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or u == "ТБ":
            return f"{n:.0f} {u}" if u in ("Б", "КБ") else f"{n:.1f} {u}"
        n /= 1024


def _ago(ts):
    if not ts:
        return "никогда"
    d = int(time.time() - ts)
    return "только что" if d < 60 else f"{d // 60} мин назад" if d < 3600 else f"{d // 3600} ч назад" if d < 86400 else f"{d // 86400} дн назад"


def _rows(cfg, db, me, where="1=1", args=()):
    from .web import client_rows
    acc, acc_args = access.sql(cfg, me)
    return client_rows(cfg, db, f"{acc} AND {where}", (*acc_args, *args))


def _titles(cfg):
    return {s["id"]: s.get("title", s["id"]) for s in cfg["servers"]}


def _dot(c):
    if c["disabled"]:
        return STATUS["dis"]
    return STATUS["on"] if c["hs"] and time.time() - c["hs"] < 180 else STATUS["off"]


# ---------------------------------------------------------------- screens

def home(cfg, db, token, chat, me, msg_id=None):
    n_req = rq.pending_count(db)
    clients = _rows(cfg, db, me, "c.deleted IS NULL")
    online = sum(1 for c in clients if not c["disabled"] and c["hs"] and time.time() - c["hs"] < 180)
    text = (f"🛡 VPN-панель · {me['name'] or me['login']}\n\nКлиентов: {len(clients)}, в сети: {online}"
            + (f"\nЗаявок ждут решения: {n_req}" if n_req else ""))
    rows = [[("👥 Клиенты", "m:cl:0"), ("➕ Новый клиент", "m:new")],
            [(f"📨 Заявки ({n_req})" if n_req else "📨 Заявки", "m:rq"), ("🖥 Серверы", "m:srv")]]
    _show(token, chat, text, rows, msg_id)


def clients_list(cfg, db, token, chat, me, page=0, sid="", msg_id=None):
    where, args = "c.deleted IS NULL", ()
    if sid:
        where, args = where + " AND c.server=?", (sid,)
    rows = _rows(cfg, db, me, where, args)
    titles = _titles(cfg)
    total = len(rows)
    page = max(0, min(page, (total - 1) // PAGE if total else 0))
    chunk = rows[page * PAGE:(page + 1) * PAGE]
    kb = [[(f"{_dot(c)} {(c['name'] or '(без имени)')[:28]} · {titles.get(c['server'], c['server'])}", f"m:c:{c['id']}")]
          for c in chunk]
    nav = []
    if page > 0:
        nav.append(("◀", f"m:cl:{page - 1}:{sid}"))
    if (page + 1) * PAGE < total:
        nav.append(("▶", f"m:cl:{page + 1}:{sid}"))
    if nav:
        kb.append(nav)
    servers = access.servers(cfg, me)
    if len(servers) > 1:
        kb.append([(("• " if s == sid else "") + titles[s], f"m:cl:0:{s}") for s in servers[:4]] +
                  ([("все", "m:cl:0:")] if sid else []))
    kb.append([("🏠 Меню", "m:home")])
    head = f"👥 Клиенты{(' · ' + titles.get(sid, sid)) if sid else ''}: {total}" + (
        f" (стр. {page + 1}/{(total - 1) // PAGE + 1})" if total > PAGE else "")
    _show(token, chat, head + "\n🟢 в сети · ⚪ не в сети · 🔴 отключён", kb, msg_id)


def client_card(cfg, db, token, chat, me, cid, msg_id=None, note=""):
    rows = _rows(cfg, db, me, "c.id=?", (cid,))
    if not rows:
        return _show(token, chat, "Нет такого клиента.", [[("👥 Клиенты", "m:cl:0")]], msg_id)
    c = rows[0]
    titles = _titles(cfg)
    kind = service.KIND_TITLE.get(c["kind"] or "", c["container"])
    lim = []
    if c.get("expires"):
        lim.append("до " + time.strftime("%d.%m.%Y", time.localtime(c["expires"])))
    if c.get("quota_gb"):
        lim.append(f"лимит {c['quota_gb']:g} ГБ/{'мес' if (c.get('quota_period') or 'month') == 'month' else 'всего'}")
    if c.get("auto_off"):
        lim.append("⏸ отключён автоматически: " + ("срок истёк" if c["auto_off"] == "expired" else "лимит"))
    text = (f"{_dot(c)} {c['name'] or '(без имени)'}\n{titles.get(c['server'], c['server'])} · {kind}"
            f"\nПоследнее подключение: {_ago(c['hs'])}{(' · ' + c['endpoint']) if c.get('endpoint') else ''}"
            f"\nТрафик: 24 ч {_size(c['d1'])} · 30 дн {_size(c['d30'])}"
            + (f"\n{' · '.join(lim)}" if lim else "")
            + ("\n🔒 служебный — изменения запрещены" if c["protected"] else "")
            + (f"\n\n{note}" if note else ""))
    kb = []
    if service.has_config(c) and not c["deleted"]:
        kb.append([("📄 Конфиг сюда", f"m:cf:{cid}"), ("🔗 Ссылка для человека", f"m:lk:{cid}")])
    if not c["protected"] and not c["deleted"]:
        kb.append([(("▶ Включить", f"m:on:{cid}") if c["disabled"] else ("⏸ Отключить", f"m:off:{cid}")),
                   ("⏳ +1 месяц", f"m:ext:{cid}")])
        kb.append([("🗑 Удалить", f"m:del:{cid}")])
    kb.append([("👥 Клиенты", "m:cl:0"), ("🏠 Меню", "m:home")])
    _show(token, chat, text, kb, msg_id)


def new_client(cfg, db, token, chat, me, msg_id=None):
    tl = rq.targets(cfg, db, me)
    if not tl:
        return _show(token, chat, "Нет доступных протоколов: установите их в «Серверах» панели.", [[("🏠 Меню", "m:home")]], msg_id)
    _set_state(db, chat, "pick_target", {"targets": [list(t) for t in tl]})
    kb = [[(t[2], f"m:nt:{i}")] for i, t in enumerate(tl[:10])] + [[("✖ Отмена", "m:home")]]
    _show(token, chat, "➕ Новый клиент — выберите сервер и протокол:", kb, msg_id)


def requests_list(cfg, db, token, chat, me, msg_id=None):
    pend = db.q("SELECT * FROM tg_requests WHERE status='pending' ORDER BY id LIMIT 10")
    if not pend:
        return _show(token, chat, "📨 Новых заявок нет.", [[("🏠 Меню", "m:home")]], msg_id)
    kb = [[(f"#{r['id']} {rq.display_name(r)[:40]}", f"m:rv:{r['id']}")] for r in pend] + [[("🏠 Меню", "m:home")]]
    _show(token, chat, f"📨 Заявки: {len(pend)}", kb, msg_id)


def request_view(cfg, db, token, chat, me, rid, msg_id=None):
    r = rq.get(db, rid)
    tl = [list(t) for t in rq.targets(cfg, db, me)]
    rq.save_targets(db, rid, tl)
    kb = [[(t[2], f"ap:{rid}:{i}")] for i, t in enumerate(tl[:8])] + [[("✖ Отклонить", f"rj:{rid}")], [("📨 Заявки", "m:rq")]]
    _show(token, chat, f"📨 Заявка #{rid}\n{rq.display_name(r)}\nTelegram id {r['chat_id']}\n\nЧто выдать?", kb, msg_id)


def servers_view(cfg, db, token, chat, me, msg_id=None):
    titles = _titles(cfg)
    lines = []
    for sid in access.servers(cfg, me):
        sh = db.one("SELECT * FROM server_health WHERE server=?", (sid,))
        state = "🔴 не отвечает" if sh and not sh["ok"] else "🟢"
        lines.append(f"\n{state} {titles[sid]}")
        for h in db.q("SELECT * FROM health WHERE server=? ORDER BY container", (sid,)):
            kind = service.KIND_TITLE.get(h["kind"], h["kind"])
            lines.append(f"   {'✅' if h['up'] else '❌'} {kind} ({h['container']}) · в сети {h['online']} из {h['peers']}")
    _show(token, chat, "🖥 Серверы" + "\n".join(lines), [[("🔄 Обновить", "m:srv"), ("🏠 Меню", "m:home")]], msg_id)


# ---------------------------------------------------------------- dispatch

def handle_callback(cfg, db, token, cq, me):
    """-> short answer text for answerCallbackQuery ('' = none)."""
    data = cq.get("data") or ""
    msg = cq.get("message") or {}
    chat, mid = (msg.get("chat") or {}).get("id"), msg.get("message_id")
    p = data.split(":")
    act = p[1] if len(p) > 1 else "home"

    def own(cid):
        rows = _rows(cfg, db, me, "c.id=?", (cid,))
        return rows[0] if rows else None
    try:
        if act == "home":
            _set_state(db, chat, None)
            home(cfg, db, token, chat, me, mid)
        elif act == "cl":
            clients_list(cfg, db, token, chat, me, int(p[2] or 0), p[3] if len(p) > 3 else "", mid)
        elif act == "c":
            client_card(cfg, db, token, chat, me, int(p[2]), mid)
        elif act in ("cf", "lk", "off", "on", "ext", "del", "delok"):
            cid = int(p[2])
            c = own(cid)
            if not c:
                return "нет доступа"
            if act == "cf":
                delivery.tg_send_client(cfg, db, db.one("SELECT * FROM clients WHERE id=?", (cid,)), chat)
                db.event(f"конфиг «{c['name']}» отправлен себе в Telegram", None, me["user_id"], c["server"])
                return "отправлено"
            if act == "lk":
                link = delivery.tg_link(db, cid)
                delivery.tg_call(token, "sendMessage", {"chat_id": chat, "disable_web_page_preview": "true",
                                                        "text": f"Перешлите человеку «{c['name']}» (72 часа, один раз):\n{link}"})
                db.event(f"ссылка на бота для «{c['name']}» (из Telegram)", None, me["user_id"], c["server"])
                return ""
            if c["protected"]:
                return "служебный — нельзя"
            if act == "off":
                service.disable(cfg, db, cid)
                note = "⏸ Отключён."
            elif act == "on":
                if c.get("auto_off"):
                    return "отключён по сроку/лимиту — нажмите «+1 месяц»"
                service.enable(cfg, db, cid)
                note = "▶ Включён."
            elif act == "ext":
                base = max(c.get("expires") or 0, int(time.time()))
                on = limits.set_limits(cfg, db, db.one("SELECT * FROM clients WHERE id=?", (cid,)), base + 30 * 86400,
                                       c.get("quota_gb"), c.get("quota_period") or "month")
                note = "⏳ Срок продлён до " + time.strftime("%d.%m.%Y", time.localtime(base + 30 * 86400)) + (" · снова включён" if on else "")
            elif act == "del":
                return _show(token, chat, f"Удалить «{c['name']}»? Его VPN перестанет работать.",
                             [[("🗑 Да, удалить", f"m:delok:{cid}"), ("Отмена", f"m:c:{cid}")]], mid) and ""
            else:  # delok
                service.delete(cfg, db, cid)
                db.event(f"удалён клиент «{c['name']}» (из Telegram)", None, me["user_id"], c["server"])
                return clients_list(cfg, db, token, chat, me, 0, "", mid) or "удалён"
            db.event(f"«{c['name']}»: {note} (из Telegram)", None, me["user_id"], c["server"])
            client_card(cfg, db, token, chat, me, cid, mid, note)
        elif act == "new":
            new_client(cfg, db, token, chat, me, mid)
        elif act == "nt":
            st, data_ = _state(db, chat)
            tl = data_.get("targets") or []
            if st != "pick_target" or int(p[2]) >= len(tl):
                return "начните заново"
            t = tl[int(p[2])]
            _set_state(db, chat, "await_name", {"target": t})
            _show(token, chat, f"➕ {t[2]}\n\nНапишите имя клиента сообщением (например: «Иван, телефон»).",
                  [[("✖ Отмена", "m:home")]], mid)
        elif act == "rq":
            requests_list(cfg, db, token, chat, me, mid)
        elif act == "rv":
            if me["role"] != "owner":
                return "одобряют владельцы"
            request_view(cfg, db, token, chat, me, int(p[2]), mid)
        elif act == "srv":
            servers_view(cfg, db, token, chat, me, mid)
    except (service.OpError, rq.RequestError, delivery.DeliveryError, ValueError, IndexError) as e:
        return f"Ошибка: {e}"[:190]
    return ""


def handle_text(cfg, db, token, chat, text, me):
    """Free text from a linked user: the client name while creating one; anything else opens the menu."""
    st, data = _state(db, chat)
    if st == "await_name" and not text.startswith("/"):
        sid, container, label = data["target"]
        name = text.strip()[:64]
        _set_state(db, chat, None)
        if not access.can(cfg, me, sid):
            return delivery.tg_call(token, "sendMessage", {"chat_id": chat, "text": "Нет доступа к этому серверу."})
        try:
            cid = service.create_client(cfg, db, sid, container, name)
        except service.OpError as e:
            return delivery.tg_call(token, "sendMessage", {"chat_id": chat, "text": f"Не создан: {e}"})
        db.x("UPDATE clients SET created_by=? WHERE id=?", (me["user_id"], cid))
        db.event(f"создан клиент «{name}» ({sid}/{container}) из Telegram", None, me["user_id"], sid)
        delivery.tg_send_client(cfg, db, db.one("SELECT * FROM clients WHERE id=?", (cid,)), chat)
        return client_card(cfg, db, token, chat, me, cid, None, "✅ Создан. Конфиг выше — перешлите его или нажмите «Ссылка для человека».")
    _set_state(db, chat, None)
    home(cfg, db, token, chat, me)
