"""HTTP(S) server on the standard library: routing, cookies, CSRF, security headers."""
import http.cookies
import logging
import os
import re
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import auth, clientconf, runner, service, views
from .service import KIND_TITLE, OpError

log = logging.getLogger("vpnpanel.web")
STATIC = os.path.join(os.path.dirname(__file__), "static")
COOKIE = "vpsess"
MAX_BODY = 64 * 1024

_params_cache = {}
_params_lock = threading.Lock()


def cached_config(cfg, db, c):
    """client_config() with container params cached for 5 minutes (saves SSH round trips)."""
    key = (c["server"], c["container"])
    with _params_lock:
        hit = _params_cache.get(key)
    if hit and time.time() - hit[0] < 300:
        params = hit[1]
    else:
        params = runner.run(cfg, cfg.server(c["server"]), "params", c["container"])
        with _params_lock:
            _params_cache[key] = (time.time(), params)
    if not c.get("priv"):
        raise OpError("у клиента нет ключа в панели")
    s = cfg.server(c["server"])
    return clientconf.render(params, private_key=c["priv"], address=c["ip"], preshared_key=c["psk"],
                             endpoint_host=s["endpoint"]), params["kind"]


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


class App:
    def __init__(self, cfg, db):
        self.cfg, self.db = cfg, db
        self.fmt = views.Fmt(cfg["timezone"])


def make_handler(app):
    cfg, db, fmt = app.cfg, app.db, app.fmt

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

        def form(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return {}
            raw = self.rfile.read(n).decode("utf-8", "replace")
            return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

        def need_login(self):
            s = self.sess()
            if not s:
                self.redirect("/login")
            return s

        # ---- routing ----
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            path, qs = url.path, {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            try:
                if path.startswith("/static/"):
                    return self.static(path[len("/static/"):])
                if path == "/login":
                    return self.send(200, views.login_page())
                m = re.fullmatch(r"/s/([A-Za-z0-9_-]{20,100})", path)
                if m:
                    return self.share(m.group(1))
                s = self.need_login()
                if not s:
                    return
                if path == "/":
                    return self.dashboard(s, qs)
                if path == "/new":
                    return self.send(200, views.new_page(s, cfg["servers"], db.q("SELECT * FROM health")))
                if path == "/log":
                    return self.send(200, views.log_page(s, fmt, db.q("SELECT * FROM events ORDER BY id DESC LIMIT 300")))
                m = re.fullmatch(r"/client/(\d+)", path)
                if m:
                    return self.client(s, int(m.group(1)))
                self.send(404, views.not_found("Нет такой страницы."))
            except Exception:
                log.exception("GET %s", path)
                self.send(500, views.not_found("Внутренняя ошибка панели, подробности в журнале сервера."))

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            f = self.form()
            try:
                if path == "/login":
                    return self.login(f)
                s = self.sess()
                if not s:
                    return self.redirect("/login")
                if not auth.csrf_ok(s, f.get("csrf")):
                    return self.send(403, views.not_found("Форма устарела, обновите страницу."))
                if path == "/logout":
                    auth.logout(db, self.cookie())
                    return self.redirect("/login", {"Set-Cookie": f"{COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict"})
                if path == "/new":
                    return self.create(s, f)
                m = re.fullmatch(r"/client/(\d+)/(disable|enable|delete|rename|share|migrate)", path)
                if m:
                    return self.action(s, int(m.group(1)), m.group(2), f)
                m = re.fullmatch(r"/share/(\d+)/revoke", path)
                if m:
                    service.revoke_share(db, int(m.group(1)))
                    db.event(f"ссылка #{m.group(1)} отозвана", self.ip)
                    return self.redirect(f"/client/{int(f.get('client') or 0)}")
                self.send(404, views.not_found("Нет такой страницы."))
            except Exception:
                log.exception("POST %s", path)
                self.send(500, views.not_found("Внутренняя ошибка панели, подробности в журнале сервера."))

        # ---- pages ----
        def static(self, name):
            if name not in ("app.css", "app.js"):
                return self.send(404, "not found", "text/plain")
            with open(os.path.join(STATIC, name), "rb") as fh:
                data = fh.read()
            ctype = "text/css; charset=utf-8" if name.endswith(".css") else "application/javascript; charset=utf-8"
            self.send(200, data, ctype)

        def login(self, f):
            r = auth.login(cfg, db, self.ip, f.get("password", ""))
            if r == "blocked":
                return self.send(429, views.login_page("Слишком много неудачных попыток. Попробуйте через час."))
            if not r:
                return self.send(401, views.login_page("Неверный пароль."))
            token, _ = r
            db.event("вход в панель", self.ip)
            self.redirect("/", {"Set-Cookie": f"{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; "
                                              f"Max-Age={cfg['session_hours'] * 3600}"})

        def dashboard(self, s, qs):
            filters = {k: (qs.get(k) or "").strip()[:64] for k in ("server", "container", "status", "q")}
            where, args = ["1=1"], []
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
            health = db.q("SELECT * FROM health ORDER BY server, container")
            self.send(200, views.dashboard(s, fmt, cfg["servers"], health, db.q("SELECT * FROM server_health"),
                                           rows, filters, now))

        def client(self, s, cid, error="", new_link=""):
            rows = client_rows(cfg, db, "c.id=?", (cid,))
            if not rows:
                return self.send(404, views.not_found("Нет такого клиента."))
            c = rows[0]
            server = cfg.server(c["server"])
            conf = qr = None
            kind = c["kind"]
            if c.get("priv") and not c["deleted"]:
                try:
                    conf, kind = cached_config(cfg, db, c)
                    qr = clientconf.qr_svg(conf)
                except (OpError, runner.CtlError) as ex:
                    error = error or f"Конфиг не собрать: {ex}"
            shares = db.q("SELECT * FROM shares WHERE client_id=? ORDER BY id DESC LIMIT 20", (cid,))
            points = [(r["hour"], r["rx"], r["tx"]) for r in db.q(
                "SELECT hour, rx, tx FROM traffic WHERE server=? AND container=? AND pub=? AND hour >= ?",
                (c["server"], c["container"], c["pub"], int(time.time()) - 7 * 86400))]
            titles = {x["id"]: x.get("title", x["id"]) for x in cfg["servers"]}
            targets = [{"server": h["server"], "container": h["container"],
                        "title": f"{titles.get(h['server'], h['server'])} — AWG 3.1"}
                       for h in db.q("SELECT * FROM health WHERE kind='awg3' AND up=1")]
            self.send(200, views.client_page(s, fmt, c, server, conf, kind, qr, shares, points, targets,
                                             c["protected"], error, new_link))

        def create(self, s, f):
            try:
                sid, container = (f.get("target") or "|").split("|", 1)
                cid = service.create_client(cfg, db, sid, container, f.get("name"))
            except (OpError, runner.CtlError, ValueError) as ex:
                return self.send(400, views.new_page(s, cfg["servers"], db.q("SELECT * FROM health"), str(ex)))
            db.event(f"создан клиент «{f.get('name')}» ({sid}/{container})", self.ip)
            self.redirect(f"/client/{cid}")

        def action(self, s, cid, act, f):
            try:
                c = service.get_client(db, cid)
                label = c["name"] or c["pub"][:8]
                if act == "disable":
                    service.disable(cfg, db, cid)
                elif act == "enable":
                    service.enable(cfg, db, cid)
                elif act == "delete":
                    service.delete(cfg, db, cid)
                elif act == "rename":
                    service.rename(cfg, db, cid, f.get("name"))
                elif act == "migrate":
                    sid, container = (f.get("target") or "|").split("|", 1)
                    new_id = service.migrate(cfg, db, cid, sid, container)
                    db.event(f"«{label}» переведён на AWG 3.1 ({sid})", self.ip)
                    return self.redirect(f"/client/{new_id}")
                elif act == "share":
                    token = service.create_share(cfg, db, cid, f.get("hours"), f.get("one_time") == "1")
                    base = cfg.get("public_url") or f"https://{self.headers.get('Host', '')}"
                    db.event(f"ссылка для «{label}»", self.ip)
                    return self.client(s, cid, new_link=f"{base.rstrip('/')}/s/{token}")
            except (OpError, runner.CtlError, ValueError) as ex:
                return self.client(s, cid, error=str(ex))
            db.event(f"{ {'disable': 'отключён', 'enable': 'включён', 'delete': 'удалён', 'rename': 'переименован'}[act]} клиент «{label}»", self.ip)
            self.redirect(f"/client/{cid}" if act != "delete" else "/")

        def share(self, token):
            c = service.open_share(db, token)
            if not c:
                return self.send(404, views.not_found())
            try:
                conf, kind = cached_config(cfg, db, c)
            except (OpError, runner.CtlError):
                return self.send(503, views.not_found("Сервер временно недоступен, попробуйте позже."))
            db.event(f"открыта ссылка клиента «{c['name']}»", self.ip)
            self.send(200, views.share_page(c, conf, kind, clientconf.qr_svg(conf)))

    return H


def serve(cfg, db):
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
