"""Sending a client its config: the panel's own Telegram bot and e-mail (SMTP).

Telegram: the admin gets a one-time link t.me/<bot>?start=<token> (72 h) and forwards it any way they like; when the
person presses Start, the bot remembers their chat for this client and sends the QR / file / login data + app links.
Later sends to the same client go straight to that chat.
Secrets (bot token, SMTP password) live in the panel DB (file mode 600) and are never shown back in full.
"""
import email.utils
import hashlib
import html
import json
import logging
import secrets
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage

from . import clientconf, service

log = logging.getLogger("vpnpanel.delivery")
TG_API = "https://api.telegram.org"
SMTP_KEYS = ("smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_from", "smtp_security")


class DeliveryError(Exception):
    pass


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def mask(v):
    v = v or ""
    return (v[:4] + "…" + v[-3:]) if len(v) > 10 else ("•" * len(v))


# ---------------------------------------------------------------- Telegram

def tg_call(token, method, fields=None, files=None, timeout=30):
    """Bot API call; files = {name: (filename, bytes, mime)} -> multipart."""
    url = f"{TG_API}/bot{token}/{method}"
    if files:
        boundary = uuid.uuid4().hex
        body = b""
        for k, v in (fields or {}).items():
            body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
        for k, (fname, data, mime) in files.items():
            body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{fname}\"\r\n"
                     f"Content-Type: {mime}\r\n\r\n").encode() + data + b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    else:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(fields or {}).encode())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            data = json.load(e)
        except Exception:
            raise DeliveryError(f"Telegram: HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError) as e:
        raise DeliveryError(f"Telegram недоступен: {e}")
    if not data.get("ok"):
        raise DeliveryError(f"Telegram: {data.get('description', 'ошибка')}")
    return data["result"]


def tg_check(token):
    me = tg_call(token, "getMe")
    return me.get("username")


def tg_save(db, token):
    token = (token or "").strip()
    if not token:
        db.x("DELETE FROM settings WHERE key IN ('tg_token','tg_username','tg_offset')")
        return None
    username = tg_check(token)
    db.set("tg_token", token)
    db.set("tg_username", username)
    return username


def tg_link(db, cid, hours=72):
    username = db.get("tg_username")
    if not username:
        raise DeliveryError("бот не настроен: «Настройки» → Telegram")
    token = secrets.token_urlsafe(24)
    now = int(time.time())
    db.x("INSERT INTO tg_links(client_id, token_hash, created, expires) VALUES(?,?,?,?)",
         (cid, _h(token), now, now + hours * 3600))
    return f"https://t.me/{username}?start={token}"


def _apps_text(kind):
    links = clientconf.app_links(kind)
    out = []
    for pid, title in clientconf.PLATFORMS:
        items = ", ".join(f'<a href="{html.escape(url)}">{html.escape(name)}</a>' for name, url, _, _ in links[pid][:3])
        out.append(f"<b>{html.escape(title)}:</b> {items}")
    return "\n".join(out)


def tg_send_client(cfg, db, c, chat_id):
    token = db.get("tg_token")
    if not token:
        raise DeliveryError("бот не настроен")
    b = service.client_config(cfg, db, c)
    name = html.escape(c.get("name") or "VPN")
    intro = f"🔐 <b>Ваш VPN: {name}</b>\n\n1. Установите приложение:\n{_apps_text(b['kind'])}\n\n"
    if b["kind"] == "sstp":
        fields = "\n".join(f"{html.escape(k)}: <code>{html.escape(v)}</code>" for k, v in b["fields"])
        tg_call(token, "sendMessage", {"chat_id": chat_id, "parse_mode": "HTML", "disable_web_page_preview": "true",
                                       "text": intro + "2. Создайте VPN-подключение типа <b>SSTP</b>:\n" + fields})
        if b.get("cert_pem"):
            tg_call(token, "sendDocument", {"chat_id": chat_id, "caption": "Сертификат сервера — установите в доверенные "
                                            "корневые (Windows) или включите «не проверять сертификат»."},
                    {"document": (b["cert_name"], b["cert_pem"].encode(), "application/x-x509-ca-cert")})
    else:
        step2 = ("2. Отсканируйте QR с другого устройства или откройте файл в приложении."
                 if b["kind"] != "vless" else "2. Отсканируйте QR или скопируйте ссылку ниже и импортируйте в приложении.")
        tg_call(token, "sendMessage", {"chat_id": chat_id, "parse_mode": "HTML", "disable_web_page_preview": "true",
                                       "text": intro + step2})
        tg_call(token, "sendPhoto", {"chat_id": chat_id}, {"photo": ("qr.png", clientconf.qr_png(b["qr"]), "image/png")})
        if b["kind"] == "vless":
            tg_call(token, "sendMessage", {"chat_id": chat_id, "parse_mode": "HTML", "text": f"<code>{html.escape(b['text'])}</code>"})
        else:
            tg_call(token, "sendDocument", {"chat_id": chat_id},
                    {"document": (b["filename"], b["text"].encode(), "text/plain")})
    tg_call(token, "sendMessage", {"chat_id": chat_id, "text": "Это ваши личные данные для входа — не пересылайте их."})


def tg_admin_link(db, user_id, hours=1):
    """One-time link that binds a panel user's Telegram (request notifications + approve buttons)."""
    username = db.get("tg_username")
    if not username:
        raise DeliveryError("бот не настроен")
    token = "a_" + secrets.token_urlsafe(20)
    now = int(time.time())
    db.x("INSERT INTO tg_admin_links(user_id, token_hash, created, expires) VALUES(?,?,?,?)",
         (user_id, _h(token), now, now + hours * 3600))
    return f"https://t.me/{username}?start={token}"


def _kb(rows):
    return json.dumps({"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows]},
                      ensure_ascii=False)


def _approvers(db):
    return db.q("SELECT id, login, tg_chat_id FROM users WHERE role='owner' AND disabled=0 AND tg_chat_id IS NOT NULL")


def _bound_client(db, chat):
    return db.one("SELECT * FROM clients WHERE tg_chat_id=? AND deleted IS NULL AND disabled=0 ORDER BY id DESC LIMIT 1",
                  (chat,))


def _notify_approvers(cfg, db, token, r):
    from . import requests as rq
    tl = [list(t) for t in rq.targets(cfg, db)]
    rq.save_targets(db, r["id"], tl)
    rows = [[(t[2], f"ap:{r['id']}:{i}")] for i, t in enumerate(tl[:8])] + [[("✖ Отклонить", f"rj:{r['id']}")]]
    text = (f"📨 Заявка на VPN #{r['id']}\n{rq.display_name(r)}\nTelegram id {r['chat_id']}\n\n"
            + ("Выберите, что выдать:" if tl else "Нет доступных протоколов — одобрить можно в панели после установки."))
    sent = 0
    for a in _approvers(db):
        try:
            tg_call(token, "sendMessage", {"chat_id": a["tg_chat_id"], "text": text, "reply_markup": _kb(rows)})
            sent += 1
        except DeliveryError as e:
            log.warning("notify approver %s: %s", a["login"], e)
    return sent


def _start(cfg, db, token, chat, arg, frm):
    if arg.startswith("a_"):
        link = db.one("SELECT * FROM tg_admin_links WHERE token_hash=? AND used_at IS NULL AND expires>?",
                      (_h(arg), int(time.time())))
        if not link:
            tg_call(token, "sendMessage", {"chat_id": chat, "text": "Ссылка привязки недействительна или истекла."})
            return
        db.x("UPDATE tg_admin_links SET used_at=? WHERE id=?", (int(time.time()), link["id"]))
        db.x("UPDATE users SET tg_chat_id=? WHERE id=?", (chat, link["user_id"]))
        u = db.one("SELECT login FROM users WHERE id=?", (link["user_id"],))
        tg_call(token, "sendMessage", {"chat_id": chat, "text": f"✅ Telegram привязан к учётке {u['login']}. "
                                                                "Сюда будут приходить заявки на VPN с кнопками одобрения."})
        db.event(f"Telegram привязан к учётке {u['login']}", None, link["user_id"])
        return
    if arg:
        link = db.one("SELECT * FROM tg_links WHERE token_hash=? AND used_at IS NULL AND expires>?",
                      (_h(arg), int(time.time())))
        c = db.one("SELECT * FROM clients WHERE id=? AND deleted IS NULL", (link["client_id"],)) if link else None
        if not c:
            tg_call(token, "sendMessage", {"chat_id": chat, "text": "Ссылка недействительна: истекла или уже использована. "
                                                                    "Попросите новую у того, кто её прислал."})
            return
        db.x("UPDATE tg_links SET used_at=? WHERE id=?", (int(time.time()), link["id"]))
        db.x("UPDATE clients SET tg_chat_id=? WHERE id=?", (chat, c["id"]))
        _send_or_apologise(cfg, db, token, c, chat, "по ссылке")
        return
    rows = [[("🔑 Запросить доступ к VPN", "req")]]
    if _bound_client(db, chat):
        rows.insert(0, [("📄 Прислать мои настройки ещё раз", "resend")])
    tg_call(token, "sendMessage", {"chat_id": chat, "reply_markup": _kb(rows),
                                   "text": "Здравствуйте! Этот бот выдаёт настройки VPN. Доступ выдаётся после одобрения администратора."})


def _send_or_apologise(cfg, db, token, c, chat, how):
    try:
        tg_send_client(cfg, db, c, chat)
        db.event(f"конфиг «{c['name']}» отправлен в Telegram ({how})", None, None, c["server"])
    except Exception as e:  # server unreachable, etc.
        log.warning("tg send failed: %s", e)
        tg_call(token, "sendMessage", {"chat_id": chat, "text": "Не получилось собрать настройки — сервер недоступен. "
                                                                "Попробуйте позже или напишите администратору."})


def _callback(cfg, db, token, cq):
    from . import requests as rq
    data = cq.get("data") or ""
    chat = ((cq.get("message") or {}).get("chat") or {}).get("id")
    frm = cq.get("from") or {}
    answer = ""
    try:
        if data == "req":
            full = " ".join(x for x in (frm.get("first_name"), frm.get("last_name")) if x)
            r, new = rq.create(db, chat, frm.get("username"), full)
            if new:
                n = _notify_approvers(cfg, db, token, r)
                db.event(f"заявка #{r['id']} от {rq.display_name(r)} в Telegram", None)
                tg_call(token, "sendMessage", {"chat_id": chat, "text": "Заявка отправлена. Как только администратор одобрит, "
                                                                        "бот пришлёт настройки сюда."})
                if not n:
                    log.warning("request %s: no approver has linked Telegram", r["id"])
            else:
                answer = "Заявка уже на рассмотрении"
        elif data == "resend":
            c = _bound_client(db, chat)
            if c:
                _send_or_apologise(cfg, db, token, c, chat, "повторно по просьбе")
            else:
                answer = "Настроек для вас нет"
        elif data.startswith(("ap:", "rj:")):
            u = db.one("SELECT * FROM users WHERE tg_chat_id=? AND role='owner' AND disabled=0", (chat,))
            if not u:
                answer = "Одобрять могут только владельцы панели"
            else:
                parts = data.split(":")
                rid = int(parts[1])
                r = rq.get(db, rid)
                if data.startswith("rj:"):
                    rq.reject(db, rid, u["id"])
                    result = f"✖ Отклонено ({u['login']})"
                else:
                    tl = json.loads(r["targets"] or "[]")
                    sid, container, label = tl[int(parts[2])]
                    rq.approve(cfg, db, rid, sid, container, u["id"])
                    result = f"✅ Выдано: {label} ({u['login']})"
                msg = cq.get("message") or {}
                try:
                    tg_call(token, "editMessageText", {"chat_id": chat, "message_id": msg.get("message_id"),
                                                       "text": (msg.get("text") or "").split("\n\n")[0] + "\n\n" + result})
                except DeliveryError:
                    pass
    except rq.RequestError as e:
        answer = str(e)
    except (service.OpError, DeliveryError, ValueError, IndexError) as e:
        answer = f"Ошибка: {e}"[:190]
    try:
        tg_call(token, "answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": answer[:190]})
    except DeliveryError:
        pass


def _handle_update(cfg, db, token, upd):
    if upd.get("callback_query"):
        return _callback(cfg, db, token, upd["callback_query"])
    msg = upd.get("message") or {}
    chat = (msg.get("chat") or {}).get("id")
    text = (msg.get("text") or "").strip()
    if not chat or not text or (msg.get("chat") or {}).get("type", "private") != "private":
        return
    if text.startswith("/start"):
        return _start(cfg, db, token, chat, text[6:].strip(), msg.get("from") or {})
    tg_call(token, "sendMessage", {"chat_id": chat, "reply_markup": _kb([[("🔑 Запросить доступ к VPN", "req")]]),
                                   "text": "Этот бот выдаёт настройки VPN после одобрения администратора."})


def bot_loop(cfg, db):
    while True:
        token = db.get("tg_token")
        if not token:
            time.sleep(20)
            continue
        try:
            offset = int(db.get("tg_offset") or 0)
            updates = tg_call(token, "getUpdates", {"offset": offset, "timeout": 50,
                                                    "allowed_updates": '["message","callback_query"]'},
                              timeout=65)
            for upd in updates:
                db.set("tg_offset", str(upd["update_id"] + 1))
                try:
                    _handle_update(cfg, db, token, upd)
                except Exception:
                    log.exception("telegram update failed")
        except DeliveryError as e:
            log.warning("telegram polling: %s", e)
            time.sleep(15)
        except Exception:
            log.exception("telegram polling crashed")
            time.sleep(15)


def start_bot(cfg, db):
    t = threading.Thread(target=bot_loop, args=(cfg, db), name="tg-bot", daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------- e-mail

def smtp_settings(db):
    return {k: db.get(k) or "" for k in SMTP_KEYS}


def smtp_save(db, form):
    for k in SMTP_KEYS:
        v = (form.get(k) or "").strip()
        if k == "smtp_pass" and not v:
            continue  # empty field = keep the stored password
        db.set(k, v)


def smtp_ready(db):
    s = smtp_settings(db)
    return bool(s["smtp_host"] and s["smtp_from"])


def _smtp(db):
    s = smtp_settings(db)
    if not (s["smtp_host"] and s["smtp_from"]):
        raise DeliveryError("почта не настроена: «Настройки» → Почта")
    port = int(s["smtp_port"] or (465 if s["smtp_security"] == "ssl" else 587))
    ctx = ssl.create_default_context()
    try:
        if s["smtp_security"] == "ssl":
            conn = smtplib.SMTP_SSL(s["smtp_host"], port, context=ctx, timeout=20)
        else:
            conn = smtplib.SMTP(s["smtp_host"], port, timeout=20)
            if s["smtp_security"] != "none":
                conn.starttls(context=ctx)
        if s["smtp_user"]:
            conn.login(s["smtp_user"], s["smtp_pass"])
    except (OSError, smtplib.SMTPException) as e:
        raise DeliveryError(f"SMTP: {e}")
    return conn, s["smtp_from"]


def send_mail(db, to, subject, text, html_body=None, inline_png=None, attachments=()):
    if "@" not in (to or "") or any(ch in to for ch in "\r\n,;<> "):
        raise DeliveryError("неверный адрес почты")
    conn, sender = _smtp(db)
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    msg["Date"], msg["Message-ID"] = email.utils.formatdate(localtime=True), email.utils.make_msgid()
    msg.set_content(text)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
        if inline_png:
            msg.get_payload()[1].add_related(inline_png, maintype="image", subtype="png", cid="<qr>")
    for fname, data, mime in attachments:
        main, sub = mime.split("/", 1)
        msg.add_attachment(data, maintype=main, subtype=sub, filename=fname)
    try:
        conn.send_message(msg)
    except smtplib.SMTPException as e:
        raise DeliveryError(f"SMTP: {e}")
    finally:
        try:
            conn.quit()
        except Exception:
            pass


def mail_client(cfg, db, c, to):
    b = service.client_config(cfg, db, c)
    name = c.get("name") or "VPN"
    links = clientconf.app_links(b["kind"])
    apps_txt = "\n".join(f"{title}: " + ", ".join(f"{n} — {u}" for n, u, _, _ in links[pid][:3])
                         for pid, title in clientconf.PLATFORMS)
    apps_html = "".join(f"<p><b>{html.escape(title)}:</b> " +
                        ", ".join(f'<a href="{html.escape(u)}">{html.escape(n)}</a>' for n, u, _, _ in links[pid][:3]) + "</p>"
                        for pid, title in clientconf.PLATFORMS)
    attachments, png = [], None
    if b["kind"] == "sstp":
        body_txt = "\n".join(f"{k}: {v}" for k, v in b["fields"])
        body_html = "<table>" + "".join(f"<tr><td>{html.escape(k)}</td><td><code>{html.escape(v)}</code></td></tr>"
                                         for k, v in b["fields"]) + "</table>"
        step = "Создайте VPN-подключение типа SSTP:"
        if b.get("cert_pem"):
            attachments.append((b["cert_name"], b["cert_pem"].encode(), "application/x-x509-ca-cert"))
    else:
        png = clientconf.qr_png(b["qr"])
        step = "Отсканируйте QR-код в приложении" + (" или импортируйте ссылку:" if b["kind"] == "vless" else " или откройте вложенный файл.")
        body_txt = b["text"] if b["kind"] == "vless" else "(файл во вложении)"
        body_html = '<p><img src="cid:qr" alt="QR" width="260" height="260"></p>' + (
            f"<p><code>{html.escape(b['text'])}</code></p>" if b["kind"] == "vless" else "")
        if b["kind"] != "vless":
            attachments.append((b["filename"], b["text"].encode(), "text/plain"))
    text = (f"Ваш VPN: {name}\n\n1. Установите приложение:\n{apps_txt}\n\n2. {step}\n{body_txt}\n\n"
            "Это ваши личные данные для входа — не пересылайте их.\n")
    html_body = (f"<h2>Ваш VPN: {html.escape(name)}</h2><p>1. Установите приложение:</p>{apps_html}"
                 f"<p>2. {html.escape(step)}</p>{body_html}<p style=\"color:#666\">Это ваши личные данные для входа — "
                 f"не пересылайте их.</p>")
    send_mail(db, to, f"Настройки VPN: {name}", text, html_body, png, attachments)
    db.x("UPDATE clients SET email=? WHERE id=?", (to, c["id"]))
