"""HTTP(S) server on the standard library: routing, cookies, CSRF, per-user access, security headers."""
import http.cookies
import logging
import os
import re
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import access, accounts, auth, clientconf, delivery, jobs, limits, requests, runner, servers, service, views
from .accounts import AccountError
from .service import OpError

log = logging.getLogger("vpnpanel.web")
STATIC = os.path.join(os.path.dirname(__file__), "static")
COOKIE = "vpsess"
MAX_BODY = 64 * 1024

_params_cache = {}
_params_lock = threading.Lock()


def cached_config(cfg, db, c):
    """clientconf.build() with container params cached for 5 minutes (saves SSH round trips).
    -> (bundle, kind)."""
    key = (c["server"], c["container"])
    with _params_lock:
        hit = _params_cache.get(key)
    if hit and time.time() - hit[0] < 300:
        params = hit[1]
    else:
        params = runner.run(cfg, cfg.server(c["server"]), "params", c["container"])
        with _params_lock:
            _params_cache[key] = (time.time(), params)
    if not service.has_config(c):
        raise OpError("у клиента нет ключа в панели")
    return clientconf.build(params, c, cfg.server(c["server"])["endpoint"]), params["kind"]


def forget_params(sid=None):
    with _params_lock:
        for k in [k for k in _params_cache if sid is None or k[0] == sid]:
            _params_cache.pop(k, None)


def client_rows(cfg, db, where="1=1", args=()):
    now = int(time.time())
    rows = db.q(f"""
      SELECT c.*, h.kind, p.hs, p.endpoint,
        (SELECT COALESCE(SUM(rx+tx),0) FROM traffic t WHERE t.server=c.server AND t.container=c.container
           AND t.pub=c.pub AND t.hour >= ?) AS d1,
        (SELECT COALESCE(SUM(rx+tx),0) FROM traffic t WHERE t.server=c.server AND t.container=c.container
           AND t.pub=c.pub AND t.hour >= ?) AS d30,
        (SELECT COALESCE(SUM(rx+tx),0) FROM traffic t WHERE t.server=c.server AND t.container=c.container
           AND t.pub=c.pub) AS dall
      FROM clients c
      LEFT JOIN peer_state p ON p.server=c.server AND p.container=c.container AND p.pub=c.pub
      LEFT JOIN health h ON h.server=c.server AND h.container=c.container
      WHERE {where}
      ORDER BY (p.hs IS NULL), p.hs DESC, c.name""", (now - 86400, now - 30 * 86400, *args))
    prot = set(cfg.get("protected_pubkeys") or [])
    for r in rows:
        r["protected"] = r["pub"] in prot
    return rows


def delivery_state(cfg, db, c):
    token = db.get("tg_token")
    return {"tg_ready": bool(token), "tg_username": db.get("tg_username") or "", "tg_bound": bool(c.get("tg_chat_id")),
            "smtp_ready": delivery.smtp_ready(db)}


def protected_units(cfg, db):
    """{server: {container}} of units that carry a protected peer (the admin's own tunnel): never uninstall these."""
    prot = list(cfg.get("protected_pubkeys") or [])
    if not prot:
        return {}
    rows = db.q(f"SELECT DISTINCT server, container FROM clients WHERE pub IN ({','.join('?' * len(prot))})", prot)
    out = {}
    for r in rows:
        out.setdefault(r["server"], set()).add(r["container"])
    return out


def selfsigned_url(cfg):
    """True when the panel is reached by a bare IP (self-signed certificate, browsers warn)."""
    import ipaddress
    host = urllib.parse.urlsplit(cfg.get("public_url") or "").hostname or ""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return not host


class App:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db
        self.fmt = views.Fmt(cfg["timezone"])


def make_handler(app):
    cfg, db, fmt = app.cfg, app.db, app.fmt

    def visible_servers(me):
        ids = set(access.servers(cfg, me))
        return [s for s in cfg["servers"] if s["id"] in ids]

    def visible_health(me):
        where, args = access.sql(cfg, me, "server")
        return db.q(f"SELECT * FROM health WHERE {where} ORDER BY server, container", args)

    class H(BaseHTTPRequestHandler):
        server_version = "vpn-panel"
        sys_version = ""
        timeout = 20  # per-connection socket timeout (also bounds the TLS handshake)

        def log_message(self, fmt_, *args):
            log.info("%s %s", self.client_address[0], fmt_ % args)

        # ---- helpers ----
        @property
        def ip(self):
            return self.client_address[0]

        def cookie(self):
            c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return c[COOKIE].value if COOKIE in c else None

        def sess(self):
            return auth.session(db, self.cookie())

        def event(self, me, text, server=None):
            db.event(text, self.ip, me["user_id"] if me else None, server)

        def send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
                             "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def redirect(self, where, headers=None):
            h = {"Location": where}
            h.update(headers or {})
            self.send(303, "", headers=h)

        def set_cookie(self, token):
            return {"Set-Cookie": f"{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; "
                                  f"Max-Age={cfg['session_hours'] * 3600}"}

        def form(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self.multi = {}
                return {}
            raw = self.rfile.read(n).decode("utf-8", "replace")
            self.multi = urllib.parse.parse_qs(raw, keep_blank_values=True)
            return {k: v[0] for k, v in self.multi.items()}

        def nf(self, me, msg="Нет такой страницы."):
            self.send(404, views.not_found(msg, me))

        # ---- routing ----
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            path, qs = url.path, {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            try:
                if path.startswith("/static/"):
                    return self.static(path[len("/static/"):])
                if path == "/favicon.ico":
                    return self.static("favicon.svg")
                if path == "/login":
                    return self.send(200, views.login_page())
                m = re.fullmatch(r"/s/([A-Za-z0-9_-]{20,100})", path)
                if m:
                    return self.share(m.group(1))
                m = re.fullmatch(r"/invite/([A-Za-z0-9_-]{20,100})", path)
                if m:
                    u = auth.invite_user(db, m.group(1))
                    return self.send(200, views.invite_page(u)) if u else self.send(404, views.link_invalid())
                me = self.sess()
                if not me:
                    return self.redirect("/login")
                if path == "/":
                    return self.dashboard(me, qs)
                if path == "/new":
                    return self.send(200, views.new_page(me, visible_servers(me), visible_health(me)))
                if path == "/log":
                    return self.journal(me)
                if path == "/me":
                    return self.profile(me)
                m = re.fullmatch(r"/client/(\d+)", path)
                if m:
                    return self.client(me, int(m.group(1)), notice=self.notice(qs))
                m = re.fullmatch(r"/jobs/(\d+)", path)
                if m and access.is_owner(me):
                    job = db.one("SELECT * FROM jobs WHERE id=?", (int(m.group(1)),))
                    if not job:
                        return self.nf(me)
                    title = next((x["title"] for x in cfg["servers"] if x["id"] == job["server"]), job["server"] or "")
                    return self.send(200, views.job_page(me, fmt, job, title))
                if path.startswith("/servers") and access.is_owner(me):
                    if path == "/servers":
                        return self.servers_view(me, notice=self.notice(qs))
                    if path == "/servers/new":
                        return self.send(200, views.server_form_page(me))
                    m = re.fullmatch(r"/servers/([a-z0-9-]+)/update", path)
                    if m:
                        s_ = next((x for x in cfg["servers"] if x["id"] == m.group(1) and x.get("transport") == "ssh"), None)
                        return self.send(200, views.server_form_page(me, s_)) if s_ else self.nf(me)
                if path == "/settings" and access.is_owner(me):
                    return self.settings_view(me)
                if path == "/requests":
                    return self.requests_view(me)
                if path.startswith("/users"):
                    if not access.is_owner(me):
                        return self.nf(me)
                    if path == "/users":
                        return self.users(me)
                    if path == "/users/new":
                        return self.send(200, views.user_form_page(me, fmt, None, cfg["servers"]))
                    m = re.fullmatch(r"/users/(\d+)", path)
                    if m:
                        return self.user_form(me, int(m.group(1)))
                self.nf(me)
            except Exception:
                log.exception("GET %s", path)
                self.send(500, views.not_found("Внутренняя ошибка панели, подробности в журнале сервера."))

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            f = self.form()
            try:
                if path == "/login":
                    return self.login(f)
                m = re.fullmatch(r"/invite/([A-Za-z0-9_-]{20,100})", path)
                if m:
                    return self.invite(m.group(1), f)
                me = self.sess()
                if not me:
                    return self.redirect("/login")
                if not auth.csrf_ok(me, f.get("csrf")):
                    return self.send(403, views.not_found("Форма устарела, обновите страницу.", me))
                if path == "/logout":
                    auth.logout(db, self.cookie())
                    return self.redirect("/login", {"Set-Cookie": f"{COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict"})
                if path == "/new":
                    return self.create(me, f)
                if path.startswith("/me/"):
                    return self.profile_post(me, path[4:], f)
                m = re.fullmatch(r"/client/(\d+)/(disable|enable|delete|rename|share|migrate)", path)
                if m:
                    return self.action(me, int(m.group(1)), m.group(2), f)
                m = re.fullmatch(r"/client/(\d+)/limits", path)
                if m:
                    return self.limits_post(me, int(m.group(1)), f)
                m = re.fullmatch(r"/client/(\d+)/(tg-link|tg-send|email)", path)
                if m:
                    return self.deliver(me, int(m.group(1)), m.group(2), f)
                m = re.fullmatch(r"/requests/(\d+)/(approve|reject)", path)
                if m:
                    return self.request_post(me, int(m.group(1)), m.group(2), f)
                if path.startswith("/servers") and access.is_owner(me):
                    return self.servers_post(me, path, f)
                if path.startswith("/settings/") and access.is_owner(me):
                    return self.settings_post(me, path[len("/settings/"):], f)
                m = re.fullmatch(r"/share/(\d+)/revoke", path)
                if m:
                    return self.revoke(me, int(m.group(1)))
                if path.startswith("/users"):
                    if not access.is_owner(me):
                        return self.nf(me)
                    return self.users_post(me, path, f)
                self.nf(me)
            except Exception:
                log.exception("POST %s", path)
                self.send(500, views.not_found("Внутренняя ошибка панели, подробности в журнале сервера."))

        # ---- auth ----
        def static(self, name):
            types = {"app.css": "text/css; charset=utf-8", "app.js": "application/javascript; charset=utf-8",
                     "favicon.svg": "image/svg+xml"}
            if name not in types:
                return self.send(404, "not found", "text/plain")
            with open(os.path.join(STATIC, name), "rb") as fh:
                data = fh.read()
            ctype = types[name]
            self.send(200, data, ctype)

        def login(self, f):
            login_name = (f.get("login") or "").strip()[:64]
            r = auth.login(cfg, db, self.ip, login_name, f.get("password", ""))
            if r == "blocked":
                db.event(f"вход заблокирован на час: {login_name or '—'}", self.ip)
                return self.send(429, views.login_page(locked=True, login=login_name))
            if not r:
                db.event(f"неудачный вход: {login_name or '—'}", self.ip)
                return self.send(401, views.login_page("Неверный логин или пароль.", login=login_name))
            me = auth.session(db, r)
            self.event(me, "вход в панель")
            self.redirect("/", self.set_cookie(r))

        def invite(self, token, f):
            u = auth.invite_user(db, token)
            if not u:
                return self.send(404, views.link_invalid())
            if f.get("password") != f.get("password2"):
                return self.send(400, views.invite_page(u, "пароли не совпали"))
            try:
                u, sess_token = auth.use_invite(cfg, db, token, f.get("password", ""), self.ip)
            except ValueError as ex:
                return self.send(400, views.invite_page(u, str(ex)))
            db.event(f"пароль задан по приглашению: {u['login']}", self.ip, u["id"])
            self.redirect("/", self.set_cookie(sess_token))

        # ---- clients ----
        def own_client(self, me, cid):
            """Client row if it exists and is on one of this user's servers; else None (-> 404)."""
            rows = client_rows(cfg, db, "c.id=?", (cid,))
            if not rows or not access.can(cfg, me, rows[0]["server"]):
                return None
            return rows[0]

        @staticmethod
        def notice(qs):
            return {"created": "Клиент создан. Покажите QR-код, создайте ссылку или отправьте в Telegram / на почту.",
                    "removed": "Сервер убран из панели.",
                    "approved": "Заявка одобрена: клиент создан, бот отправил ему настройки."}.get(qs.get("ok", ""), "")

        def dashboard(self, me, qs):
            filters = {k: (qs.get(k) or "").strip()[:64] for k in ("server", "container", "status", "q")}
            acc, acc_args = access.sql(cfg, me)
            where, args = [acc], list(acc_args)
            if filters["server"]:
                where.append("c.server=?"); args.append(filters["server"])
            if filters["container"]:
                where.append("c.container=?"); args.append(filters["container"])
            now = int(time.time())
            st = filters["status"]
            if st == "deleted":
                where.append("c.deleted IS NOT NULL")
            else:
                where.append("c.deleted IS NULL")
                if st == "online":
                    where.append("p.hs >= ? AND c.disabled=0"); args.append(now - cfg["online_seconds"])
                elif st == "offline":
                    where.append("(p.hs IS NULL OR p.hs < ?) AND c.disabled=0"); args.append(now - cfg["online_seconds"])
                elif st == "disabled":
                    where.append("c.disabled=1")
                elif st == "migrated":
                    where.append("c.migrated_to IS NOT NULL")
            if filters["q"]:
                where.append("(c.name LIKE ? OR c.ip LIKE ?)"); args += [f"%{filters['q']}%"] * 2
            rows = client_rows(cfg, db, " AND ".join(where), args)
            sh_where, sh_args = access.sql(cfg, me, "server")
            self.send(200, views.dashboard(me, fmt, visible_servers(me), visible_health(me),
                                           db.q(f"SELECT * FROM server_health WHERE {sh_where}", sh_args),
                                           rows, filters, now))

        def client(self, me, cid, error="", new_link="", notice="", tg_link=""):
            c = self.own_client(me, cid)
            if not c:
                return self.nf(me, "Нет такого клиента.")
            server = cfg.server(c["server"])
            bundle = qr = None
            kind = c["kind"]
            if service.has_config(c) and not c["deleted"]:
                try:
                    bundle, kind = cached_config(cfg, db, c)
                    qr = clientconf.qr_svg(bundle["qr"]) if bundle["qr"] else None
                except (OpError, runner.CtlError) as ex:
                    error = error or f"Конфиг не собрать: {ex}"
            shares = db.q("SELECT * FROM shares WHERE client_id=? ORDER BY id DESC LIMIT 20", (cid,))
            points = [(r["hour"], r["rx"], r["tx"]) for r in db.q(
                "SELECT hour, rx, tx FROM traffic WHERE server=? AND container=? AND pub=? AND hour >= ?",
                (c["server"], c["container"], c["pub"], int(time.time()) - 7 * 86400))]
            titles = {x["id"]: x.get("title", x["id"]) for x in cfg["servers"]}
            targets = [{"server": h["server"], "container": h["container"],
                        "title": f"{titles.get(h['server'], h['server'])} — AWG 3.1 (UDP {h['port']})"}
                       for h in visible_health(me) if h["kind"] == "awg3" and h["up"]]
            send_html = views.send_block(me, c, delivery_state(cfg, db, c), tg_link) if bundle else ""
            used = limits.usage(cfg, db, c) if c.get("quota_gb") else 0
            self.send(200, views.client_page(me, fmt, c, server, bundle, kind, qr, shares, points, targets,
                                             c["protected"], error, new_link, notice, selfsigned_url(cfg), send_html, used))

        def create(self, me, f):
            try:
                sid, container = (f.get("target") or "|").split("|", 1)
                if not access.can(cfg, me, sid):
                    raise OpError("нет доступа к этому серверу")
                cid = service.create_client(cfg, db, sid, container, f.get("name"), login=f.get("login"))
                db.x("UPDATE clients SET created_by=? WHERE id=?", (me["user_id"], cid))
                term = (f.get("term") or "").strip()
                q = (f.get("quota_gb") or "").strip().replace(",", ".")
                if term.isdigit() or q:
                    exp = int(time.time()) + int(term) * 86400 if term.isdigit() else None
                    try:
                        quota = float(q) if q else None
                    except ValueError:
                        quota = None
                    db.x("UPDATE clients SET expires=?, quota_gb=?, quota_period='month' WHERE id=?", (exp, quota, cid))
            except (OpError, runner.CtlError, ValueError) as ex:
                return self.send(400, views.new_page(me, visible_servers(me), visible_health(me), str(ex)))
            self.event(me, f"создан клиент «{f.get('name')}» ({sid}/{container})", sid)
            self.redirect(f"/client/{cid}?ok=created")

        def action(self, me, cid, act, f):
            c = self.own_client(me, cid)
            if not c:
                return self.nf(me, "Нет такого клиента.")
            label = c["name"] or c["pub"][:8]
            try:
                if act == "disable":
                    service.disable(cfg, db, cid)
                elif act == "enable":
                    if c.get("auto_off"):
                        raise OpError("клиент отключён по сроку или лимиту — продлите их в блоке «Срок и лимит», он включится сам")
                    service.enable(cfg, db, cid)
                elif act == "delete":
                    service.delete(cfg, db, cid)
                elif act == "rename":
                    service.rename(cfg, db, cid, f.get("name"))
                elif act == "migrate":
                    sid, container = (f.get("target") or "|").split("|", 1)
                    if not access.can(cfg, me, sid):
                        raise OpError("нет доступа к этому серверу")
                    new_id = service.migrate(cfg, db, cid, sid, container)
                    db.x("UPDATE clients SET created_by=? WHERE id=?", (me["user_id"], new_id))
                    self.event(me, f"клиент «{label}» переведён на AWG 3.1 ({sid})", sid)
                    return self.redirect(f"/client/{new_id}?ok=created")
                elif act == "share":
                    token = service.create_share(cfg, db, cid, f.get("hours"), f.get("one_time") == "1")
                    base = cfg.get("public_url") or f"https://{self.headers.get('Host', '')}"
                    hours = f.get("hours") or cfg["share_ttl_hours"]
                    kind = "одноразовая" if f.get("one_time") == "1" else "многоразовая"
                    self.event(me, f"ссылка для «{label}» ({hours} ч, {kind})", c["server"])
                    return self.client(me, cid, new_link=f"{base.rstrip('/')}/s/{token}")
            except (OpError, runner.CtlError, ValueError) as ex:
                return self.client(me, cid, error=str(ex))
            words = {"disable": "отключён", "enable": "включён", "delete": "удалён", "rename": "переименован"}
            self.event(me, f"{words[act]} клиент «{label}»", c["server"])
            self.redirect(f"/client/{cid}" if act != "delete" else "/")

        def revoke(self, me, share_id):
            s = db.one("SELECT client_id FROM shares WHERE id=?", (share_id,))
            c = self.own_client(me, s["client_id"]) if s else None
            if not c:
                return self.nf(me)
            service.revoke_share(db, share_id)
            self.event(me, f"отозвана ссылка для «{c['name']}»", c["server"])
            self.redirect(f"/client/{c['id']}")

        def share(self, token):
            c = service.open_share(db, token)
            if not c:
                return self.send(404, views.link_invalid())
            try:
                bundle, kind = cached_config(cfg, db, c)
            except (OpError, runner.CtlError):
                return self.send(503, views.server_down())
            db.event(f"открыта ссылка клиента «{c['name']}»", self.ip, None, c["server"])
            qr = clientconf.qr_svg(bundle["qr"]) if bundle["qr"] else None
            self.send(200, views.share_page(c, bundle, kind, qr, clientconf.platform_of(self.headers.get("User-Agent"))))

        # ---- limits ----
        def limits_post(self, me, cid, f):
            c = self.own_client(me, cid)
            if not c or c["protected"]:
                return self.nf(me, "Нет такого клиента.")
            import datetime as _dt
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(cfg["timezone"])
            try:
                if f.get("extend"):
                    days = int(f["extend"])
                    base = max(c["expires"] or 0, int(time.time()))
                    expires, quota, period = base + days * 86400, c["quota_gb"], c["quota_period"] or "month"
                else:
                    d = (f.get("expires") or "").strip()
                    expires = (int(_dt.datetime.strptime(d, "%Y-%m-%d").replace(hour=23, minute=59, tzinfo=tz).timestamp())
                               if d else None)
                    q = (f.get("quota_gb") or "").strip().replace(",", ".")
                    quota = float(q) if q else None
                    if quota is not None and not 0 < quota < 100000:
                        raise ValueError("лимит — число гигабайт больше нуля")
                    period = f.get("quota_period") if f.get("quota_period") in ("month", "total") else "month"
                back_on = limits.set_limits(cfg, db, c, expires, quota, period)
            except ValueError as ex:
                return self.client(me, cid, error=f"Не сохранено: {ex}")
            except (OpError, runner.CtlError) as ex:
                return self.client(me, cid, error=str(ex))
            what = (f"срок до {fmt.dt(expires)}" if expires else "срок без ограничения") + ", " + (
                f"лимит {quota:g} ГБ" if quota else "без лимита")
            self.event(me, f"«{c['name']}»: {what}", c["server"])
            return self.client(me, cid, notice="Сохранено." + (" Клиент снова включён." if back_on else ""))

        # ---- delivery ----
        def deliver(self, me, cid, act, f):
            c = self.own_client(me, cid)
            if not c:
                return self.nf(me, "Нет такого клиента.")
            try:
                if act == "tg-link":
                    link = delivery.tg_link(db, cid)
                    self.event(me, f"ссылка на Telegram-бота для «{c['name']}»", c["server"])
                    return self.client(me, cid, tg_link=link)
                if act == "tg-send":
                    if not c.get("tg_chat_id"):
                        raise delivery.DeliveryError("человек ещё не открывал бота — сначала отправьте ему ссылку на бота")
                    delivery.tg_send_client(cfg, db, c, c["tg_chat_id"])
                    self.event(me, f"конфиг «{c['name']}» отправлен в Telegram", c["server"])
                    return self.client(me, cid, notice="Отправлено в Telegram.")
                if act == "email":
                    to = (f.get("email") or "").strip()
                    delivery.mail_client(cfg, db, c, to)
                    self.event(me, f"конфиг «{c['name']}» отправлен на {to}", c["server"])
                    return self.client(me, cid, notice=f"Письмо отправлено на {to}.")
            except (delivery.DeliveryError, OpError, runner.CtlError) as ex:
                return self.client(me, cid, error=str(ex))
            self.nf(me)

        # ---- settings (owner) ----
        def settings_view(self, me, error="", ok="", admin_link=""):
            token = db.get("tg_token")
            linked = db.one("SELECT tg_chat_id FROM users WHERE id=?", (me["user_id"],))["tg_chat_id"]
            st = {"tg_ready": bool(token), "tg_username": db.get("tg_username") or "", "tg_masked": delivery.mask(token),
                  "me_linked": bool(linked)}
            self.send(400 if error else 200, views.settings_page(me, st, delivery.smtp_settings(db), error, ok, admin_link))

        def requests_view(self, me, error="", ok=""):
            pending = db.q("SELECT * FROM tg_requests WHERE status='pending' ORDER BY id")
            history = db.q("""SELECT r.*, u.login AS decider FROM tg_requests r LEFT JOIN users u ON u.id=r.decided_by
                              WHERE r.status<>'pending' ORDER BY r.decided DESC LIMIT 50""")
            if not access.is_owner(me):  # admins see decisions on their servers only
                mine = set(access.servers(cfg, me))
                history = [h for h in history if h["client_id"] and
                           (db.one("SELECT server FROM clients WHERE id=?", (h["client_id"],)) or {}).get("server") in mine]
            linked = db.one("SELECT tg_chat_id FROM users WHERE id=?", (me["user_id"],))["tg_chat_id"]
            self.send(400 if error else 200, views.requests_page(me, fmt, pending, history, requests.targets(cfg, db, me),
                                                                 bool(db.get("tg_token")), bool(linked), error, ok))

        def request_post(self, me, rid, act, f):
            try:
                if act == "reject":
                    requests.reject(db, rid, me["user_id"])
                    return self.requests_view(me, ok=f"Заявка #{rid} отклонена.")
                sid, container = (f.get("target") or "|").split("|", 1)
                cid = requests.approve(cfg, db, rid, sid, container, me["user_id"], me)
                return self.redirect(f"/client/{cid}?ok=approved")
            except (requests.RequestError, OpError, runner.CtlError, delivery.DeliveryError, ValueError) as ex:
                return self.requests_view(me, error=str(ex))

        def settings_post(self, me, what, f):
            try:
                if what == "telegram":
                    username = delivery.tg_save(db, f.get("tg_token"))
                    self.event(me, "Telegram-бот " + (f"@{username} подключён" if username else "отключён"))
                    return self.settings_view(me, ok=(f"Бот @{username} подключён." if username else "Бот отключён."))
                if what == "tg-admin":
                    link = delivery.tg_admin_link(db, me["user_id"])
                    return self.settings_view(me, admin_link=link)
                if what == "smtp":
                    delivery.smtp_save(db, f)
                    self.event(me, "изменены настройки почты")
                    to = (f.get("test_to") or "").strip()
                    if to:
                        delivery.send_mail(db, to, "VPN-панель: проверка почты", "Если вы это читаете — почта настроена.")
                        return self.settings_view(me, ok=f"Сохранено. Тестовое письмо отправлено на {to}.")
                    return self.settings_view(me, ok="Сохранено.")
            except delivery.DeliveryError as ex:
                return self.settings_view(me, error=str(ex))
            self.nf(me)

        # ---- servers (owner) ----
        def servers_view(self, me, error="", ok="", notice=""):
            running = {r["server"]: r["id"] for r in db.q("SELECT server, id FROM jobs WHERE status='running'")}
            self.send(400 if error else 200, views.servers_page(
                me, fmt, cfg["servers"], db.q("SELECT * FROM health ORDER BY server, container"),
                db.q("SELECT * FROM server_health"), running, protected_units(cfg, db), error, ok or notice))

        def admin_from_form(self, f, host=None, port=None):
            host = (host or f.get("host") or "").strip()
            if not servers.HOST_RE.match(host):
                raise servers.ServerError("неверный SSH-адрес")
            if not (f.get("password") or f.get("key", "").strip()):
                raise servers.ServerError("нужен пароль root или приватный ключ")
            return servers.Admin(cfg, host, port or f.get("port") or 22, (f.get("user") or "root").strip(),
                                 password=f.get("password") or None, key_text=f.get("key") or None)

        def servers_post(self, me, path, f):
            if path == "/servers/new":
                try:
                    admin = self.admin_from_form(f)
                except servers.ServerError as ex:
                    return self.send(400, views.server_form_page(me, error=str(ex)))
                title = (f.get("title") or "").strip()[:40] or admin.host
                endpoint = (f.get("endpoint") or "").strip() or admin.host
                sid = servers.new_id(db, title)

                def work(log):
                    try:
                        server, info = servers.bootstrap(cfg, db, admin, sid, title, endpoint, log)
                    finally:
                        admin.close()
                    servers.save(db, server, info)
                    servers.refresh(cfg, db)
                    from . import poller
                    poller.poll_server(cfg, db, cfg.server(sid))
                    log(f"сервер «{title}» добавлен в панель")
                    return {"server": sid}
                jid = jobs.start(db, sid, f"Подключение сервера «{title}»", work, me["user_id"])
                self.event(me, f"подключение сервера «{title}» ({admin.host})", sid)
                return self.redirect(f"/jobs/{jid}")
            m = re.fullmatch(r"/servers/([a-z0-9-]+)/(install|uninstall|check|update|remove)", path)
            if not m:
                return self.nf(me)
            sid, act = m.group(1), m.group(2)
            try:
                srv = cfg.server(sid)
            except KeyError:
                return self.nf(me, "Нет такого сервера.")
            try:
                if act == "check":
                    info = runner.run(cfg, srv, "preflight", timeout=60)
                    servers.set_info(db, sid, info)
                    servers.refresh(cfg, db)
                    from . import poller
                    poller.poll_server(cfg, db, srv)
                    return self.servers_view(me, ok=f"«{srv['title']}» на связи: vpnctl {info.get('version')}, свободно {info.get('free_mb')} МБ.")
                if act == "remove":
                    note = servers.remove(cfg, db, sid)
                    forget_params(sid)
                    self.event(me, f"сервер «{srv['title']}» убран из панели{note}")
                    return self.servers_view(me, ok=f"Сервер «{srv['title']}» убран из панели.{note}")
                if act == "update":
                    admin = self.admin_from_form(f, srv.get("ssh_host"), srv.get("ssh_port"))

                    def upd(log):
                        try:
                            server, info = servers.bootstrap(cfg, db, admin, sid, srv["title"], srv["endpoint"], log)
                        finally:
                            admin.close()
                        servers.set_info(db, sid, info)
                        servers.refresh(cfg, db)
                        return {"server": sid}
                    jid = jobs.start(db, sid, f"Обновление агента на «{srv['title']}»", upd, me["user_id"])
                    self.event(me, f"обновление агента на «{srv['title']}»", sid)
                    return self.redirect(f"/jobs/{jid}")
                proto = f.get("proto")
                if proto not in servers.PROTOCOLS:
                    raise servers.ServerError("нет такого протокола")
                if act == "install":
                    args = ["install", proto]
                    port = (f.get("port") or "").strip()
                    if port:
                        if not port.isdigit() or not 1 <= int(port) <= 65535:
                            raise servers.ServerError("порт — число от 1 до 65535")
                        args += ["--port", port]
                    sni = (f.get("sni") or "").strip()
                    if proto == "vless" and sni:
                        if not servers.HOST_RE.match(sni):
                            raise servers.ServerError("неверный SNI")
                        args += ["--sni", sni]
                    title = f"Установка {servers.PROTOCOLS[proto]} на «{srv['title']}»"
                else:
                    if servers.UNIT_OF[proto] in protected_units(cfg, db).get(sid, set()):
                        raise servers.ServerError("на этом протоколе служебный туннель администратора — удалять нельзя")
                    args = ["uninstall", proto]
                    title = f"Удаление {servers.PROTOCOLS[proto]} с «{srv['title']}»"

                def run_proto(log):
                    res = runner.stream(cfg, srv, *args, on_line=log)
                    forget_params(sid)
                    from . import poller
                    poller.poll_server(cfg, db, srv)
                    try:
                        servers.set_info(db, sid, runner.run(cfg, srv, "preflight", timeout=60))
                        servers.refresh(cfg, db)
                    except runner.CtlError:
                        pass
                    return res
                jid = jobs.start(db, sid, title, run_proto, me["user_id"])
                self.event(me, title.lower(), sid)
                return self.redirect(f"/jobs/{jid}")
            except (servers.ServerError, runner.CtlError, jobs.Busy) as ex:
                if act == "update":
                    return self.send(400, views.server_form_page(me, srv, str(ex)))
                return self.servers_view(me, error=str(ex))

        # ---- journal ----
        def journal(self, me):
            if access.is_owner(me):
                where, args = "1=1", ()
            else:
                acc, acc_args = access.sql(cfg, me, "e.server")
                where, args = f"({acc} OR e.user_id=?)", (*acc_args, me["user_id"])
            events = db.q(f"""SELECT e.*, COALESCE(u.name, u.login) AS who FROM events e LEFT JOIN users u ON u.id=e.user_id
                              WHERE {where} ORDER BY e.id DESC LIMIT 300""", args)
            self.send(200, views.log_page(me, fmt, events))

        # ---- profile ----
        def profile(self, me, error="", ok=""):
            user = db.one("SELECT * FROM users WHERE id=?", (me["user_id"],))
            n = db.one("SELECT COUNT(*) n FROM sessions WHERE user_id=? AND expires>?", (me["user_id"], int(time.time())))["n"]
            self.send(400 if error else 200, views.me_page(me, fmt, user, n, error, ok))

        def profile_post(self, me, what, f):
            if what == "password":
                user = db.one("SELECT * FROM users WHERE id=?", (me["user_id"],))
                if not auth.check_password(user["pw_hash"] or "", f.get("current", "")):
                    return self.profile(me, error="Текущий пароль неверный.")
                if f.get("password") != f.get("password2"):
                    return self.profile(me, error="Новые пароли не совпали.")
                try:
                    auth.set_password(db, me["user_id"], f.get("password", ""), keep_token=self.cookie())
                except ValueError as ex:
                    return self.profile(me, error=f"Пароль не сменён: {ex}.")
                self.event(me, "сменён свой пароль")
                return self.profile(me, ok="Пароль сменён. Другие сеансы закрыты.")
            if what == "profile":
                try:
                    accounts.rename_self(db, me, f.get("login"), f.get("name"))
                except AccountError as ex:
                    return self.profile(me, error=str(ex))
                self.event(me, "изменены логин/имя в профиле")
                return self.profile(auth.session(db, self.cookie()), ok="Сохранено.")
            if what == "logout-others":
                auth.logout_others(db, me["user_id"], keep_token=self.cookie())
                self.event(me, "закрыты другие сеансы")
                return self.profile(me, ok="Другие сеансы закрыты.")
            self.nf(me)

        # ---- accounts (owner) ----
        def users(self, me, error="", ok="", invite_link="", invite_for=""):
            users = db.q("SELECT * FROM users ORDER BY role DESC, login")
            self.send(400 if error else 200, views.users_page(me, fmt, users, cfg["servers"], error, ok, invite_link, invite_for))

        def user_form(self, me, uid, error="", invite_link=""):
            try:
                u = accounts.get(db, uid)
            except AccountError:
                return self.nf(me, "Нет такой учётки.")
            self.send(400 if error else 200, views.user_form_page(me, fmt, u, cfg["servers"], error, invite_link))

        def invite_url(self, token):
            base = cfg.get("public_url") or f"https://{self.headers.get('Host', '')}"
            return f"{base.rstrip('/')}/invite/{token}"

        def users_post(self, me, path, f):
            servers = self.multi.get("servers", [])
            if path == "/users/new":
                try:
                    uid, token = accounts.create(cfg, db, me, f.get("login"), f.get("name"), f.get("role"), servers)
                except AccountError as ex:
                    return self.send(400, views.user_form_page(me, fmt, None, cfg["servers"], str(ex)))
                self.event(me, f"создана учётка {f.get('login', '').strip().lower()} ({accounts.ROLES[f.get('role')]})")
                return self.user_form(me, uid, invite_link=self.invite_url(token))
            m = re.fullmatch(r"/users/(\d+)/(update|reset|disable|enable|delete)", path)
            if not m:
                return self.nf(me)
            uid, act = int(m.group(1)), m.group(2)
            try:
                u = accounts.get(db, uid)
                if act == "update":
                    accounts.update(cfg, db, me, uid, f.get("name"), f.get("role"), servers)
                    self.event(me, f"изменена учётка {u['login']}")
                    return self.user_form(me, uid)
                if act == "reset":
                    token = accounts.reset(db, uid)
                    self.event(me, f"сброшен пароль учётки {u['login']}")
                    return self.user_form(me, uid, invite_link=self.invite_url(token))
                if act in ("disable", "enable"):
                    accounts.set_disabled(db, me, uid, act == "disable")
                    self.event(me, f"учётка {u['login']} {'отключена' if act == 'disable' else 'включена'}")
                    return self.user_form(me, uid)
                if act == "delete":
                    accounts.delete(db, me, uid)
                    self.event(me, f"удалена учётка {u['login']}")
                    return self.users(me, ok=f"Учётка {u['login']} удалена.")
            except AccountError as ex:
                return self.user_form(me, uid, error=str(ex))
            self.nf(me)

    return H


def serve(cfg, db):
    servers.refresh(cfg, db)
    jobs.reap(db)
    delivery.start_bot(cfg, db)
    httpd = ThreadingHTTPServer((cfg["listen"], cfg["port"]), make_handler(App(cfg, db)))
    httpd.daemon_threads = True
    if cfg.get("tls_cert"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cfg["tls_cert"], cfg["tls_key"])
        # handshake happens lazily in the handler thread, so a slow client cannot stall accept()
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    log.info("listening on %s:%s", cfg["listen"], cfg["port"])
    httpd.serve_forever()
