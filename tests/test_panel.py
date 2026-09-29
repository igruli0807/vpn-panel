"""Panel tests without VPN servers: awgctl is replaced by an in-memory fake per server, the web server runs
for real over HTTPS with a throw-away self-signed certificate.

    python3 -m unittest discover -s tests -p 'test_*.py'
"""
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "panel"), os.path.join(ROOT, "panel", "vendor")]

from vpnpanel import alerts, auth, config, delivery, jobs, keys, limits, poller, runner, servers, service, web  # noqa: E402
from vpnpanel.db import DB  # noqa: E402

AGENT_PUB = keys.pubkey(keys.genkey())
OWNER_PW = "correct horse battery"


def return_error(msg):
    raise runner.CtlError(f"fake: {msg}")


class FakeCtl:
    """Behaves like awgctl on one server."""

    def __init__(self, containers):
        self.containers = containers

    def run(self, args, stdin=""):
        cmd, rest = args[0], list(args[1:])
        if cmd == "dump":
            return {n: {"kind": c["kind"], "up": c["up"], "port": c["port"], "at": int(time.time()),
                        "peers": [{"pub": k, "name": v["name"], "ip": v["ip"], "disabled": v["disabled"],
                                   "endpoint": "1.2.3.4:5555" if v["hs"] else None, "latest_handshake": v["hs"],
                                   "rx": v["rx"], "tx": v["tx"]} for k, v in c["peers"].items()]}
                    for n, c in self.containers.items()}
        if cmd == "preflight":
            return {"version": "2.0.0", "os": "Debian 12", "docker": True, "free_mb": 3000, "mem_avail_mb": 400,
                    "units": list(self.containers)}
        if cmd == "unlink":
            self.unlinked = True
            return {"ok": True, "removed": 1}
        c = self.containers[rest[0]]
        opts = dict(zip(rest[1::2], rest[2::2]))
        if cmd == "params" and c["kind"] == "sstp":
            return {"kind": "sstp", "port": c["port"], "cert_pem": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
                    "self_signed": True}
        if cmd == "params" and c["kind"] == "vless":
            return {"kind": "vless", "port": c["port"], "public_key": "PBKtest", "short_id": "ab12cd34",
                    "sni": "www.apple.com", "flow": "xtls-rprx-vision", "fp": "chrome"}
        if cmd == "next-ip" and c["kind"] in ("sstp", "vless"):
            return {"ip": ""}
        if cmd == "params":
            return {"kind": c["kind"], "server_public_key": AGENT_PUB, "port": c["port"], "subnet": c["subnet"],
                    "shared": {"S1": 20, "S2": 30, "S3": 14, "S4": 16, "H1": "1-2", "H2": "3-4", "H3": "5-6", "H4": "7-8"},
                    "client_side": {"Jc": 4, "Jmin": 10, "Jmax": 50},
                    "header_protection_key": "HPK" if c["kind"] == "awg3" else None,
                    "mtu": 1280, "dns": "1.1.1.1", "keepalive": 25}
        if cmd == "next-ip":
            used = {p["ip"] for p in c["peers"].values()}
            for i in range(2, 250):
                ip = f"10.8.3.{i}/32"
                if ip not in used:
                    return {"ip": ip}
        pub = opts.get("--pub")
        if cmd == "add":
            if pub in c["peers"]:
                return_error("peer already exists")
            c["peers"][pub] = {"name": opts.get("--name", ""), "ip": opts.get("--ip", ""), "disabled": False,
                               "rx": 0, "tx": 0, "hs": 0, "psk": stdin.strip()}
            return {"ok": True, "ip": opts.get("--ip", "")}
        if pub not in c["peers"]:
            return_error("no such peer")
        if cmd == "remove":
            del c["peers"][pub]
        elif cmd == "disable":
            c["peers"][pub]["disabled"] = True
        elif cmd == "enable":
            c["peers"][pub]["disabled"] = False
        elif cmd == "set-name":
            c["peers"][pub]["name"] = opts["--name"]
        return {"ok": True}


FAKES = {
    "fin": FakeCtl({
        "awg3": {"kind": "awg3", "port": 43000, "up": True, "subnet": "10.8.3.1/24", "peers": {}},
        "amnezia-awg": {"kind": "legacy", "port": 49000, "up": True, "subnet": "10.8.1.0/24", "peers": {
            AGENT_PUB: {"name": "agent", "ip": "10.8.1.6/32", "disabled": False, "rx": 0, "tx": 0, "hs": 0},
            keys.pubkey(keys.genkey()): {"name": "Old phone", "ip": "10.8.1.20/32", "disabled": False,
                                         "rx": 1000, "tx": 500, "hs": int(time.time())},
        }},
    }),
    "usa": FakeCtl({
        "awg3": {"kind": "awg3", "port": 44000, "up": True, "subnet": "10.8.3.1/24", "peers": {
            keys.pubkey(keys.genkey()): {"name": "USA client", "ip": "10.8.3.9/32", "disabled": False,
                                         "rx": 0, "tx": 0, "hs": 0},
        }},
        "sstp": {"kind": "sstp", "port": 45000, "up": True, "subnet": "", "peers": {}},
        "xray": {"kind": "vless", "port": 46000, "up": True, "subnet": "", "peers": {}},
    }),
    "nl": FakeCtl({"xray": {"kind": "vless", "port": 47000, "up": True, "subnet": "", "peers": {}}}),
}
AGENT3_PUB = keys.pubkey(keys.genkey())
FAKES["fin"].containers["awg3"]["peers"][AGENT3_PUB] = {"name": "agent awg3", "ip": "10.8.3.250/32", "disabled": False,
                                                        "rx": 0, "tx": 0, "hs": 0}


def fake_run(cfg, server, *args, stdin="", timeout=40):
    return FAKES[server["id"]].run(args, stdin)


class PanelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=test",
                        "-keyout", f"{cls.tmp}/tls.key", "-out", f"{cls.tmp}/tls.crt"], check=True, capture_output=True)
        cfgfile = f"{cls.tmp}/config.json"
        with open(cfgfile, "w") as fh:
            json.dump({"listen": "127.0.0.1", "port": 0, "db": f"{cls.tmp}/panel.db", "timezone": "Asia/Krasnoyarsk",
                       "protected_pubkeys": [AGENT_PUB, AGENT3_PUB], "public_url": "https://panel.test:2053",
                       "servers": [{"id": "fin", "title": "Финляндия", "endpoint": "198.51.100.7", "transport": "local"},
                                   {"id": "usa", "title": "США", "endpoint": "198.51.100.8", "transport": "local"}]}, fh)
        cls.cfg = config.load(cfgfile)
        # an install from before accounts: one password in settings -> must become owner "admin"
        old = DB(cls.cfg["db"])
        old.set("admin_password", auth.hash_password(OWNER_PW))
        old.conn.close()
        cls.db = DB(cls.cfg["db"])
        servers.refresh(cls.cfg, cls.db)
        runner.run = fake_run
        service.runner.run = fake_run
        web.runner.run = fake_run
        poller.runner.run = fake_run
        poller.poll_all(cls.cfg, cls.db)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{cls.tmp}/tls.crt", f"{cls.tmp}/tls.key")
        httpd = web.PanelServer(("127.0.0.1", 0), web.make_handler(web.App(cls.cfg, cls.db)), ssl_ctx=ctx)
        cls.httpd = httpd
        cls.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp)

    # ---- http helpers ----
    def req(self, method, path, form=None, cookie=None, ua=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ssl._create_unverified_context(), timeout=10)
        headers, body = ({"User-Agent": ua} if ua else {}), None
        if form is not None:
            body = urllib.parse.urlencode(form, doseq=True)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = f"vpsess={cookie}"
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read().decode()
        conn.close()
        return r.status, dict(r.getheaders()), data

    @staticmethod
    def token_of(h):
        return re.search(r"vpsess=([^;]+)", h["Set-Cookie"]).group(1)

    def csrf_of(self, token):
        _, _, page = self.req("GET", "/me", cookie=token)
        return re.search(r'name="csrf" value="([^"]+)"', page).group(1)

    def login(self, login="admin", password=OWNER_PW):
        st, h, _ = self.req("POST", "/login", {"login": login, "password": password})
        self.assertEqual(st, 303, f"login {login} failed")
        token = self.token_of(h)
        return token, self.csrf_of(token)

    def cid(self, name):
        return self.db.one("SELECT id FROM clients WHERE name=? AND deleted IS NULL", (name,))["id"]

    # ---- tests ----
    def test_00_migration_made_owner_admin(self):
        u = self.db.one("SELECT * FROM users WHERE login='admin'")
        self.assertEqual(u["role"], "owner")
        self.assertIsNone(self.db.get("admin_password"))

    def test_01_requires_login(self):
        st, h, _ = self.req("GET", "/")
        self.assertEqual((st, h["Location"]), (303, "/login"))

    def test_02_security_headers(self):
        _, h, page = self.req("GET", "/login")
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertNotIn('style="', page, "CSP forbids inline styles")

    def test_03_login_cookie_flags_and_wrong_login(self):
        _, h, _ = self.req("POST", "/login", {"login": "admin", "password": OWNER_PW})
        for flag in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(flag, h["Set-Cookie"])
        st, _, page = self.req("POST", "/login", {"login": "nobody", "password": OWNER_PW})
        self.assertEqual(st, 401)
        self.assertIn("Неверный логин или пароль", page)

    def test_04_dashboard_all_servers_and_protected(self):
        token, _ = self.login()
        _, _, page = self.req("GET", "/", cookie=token)
        for s in ("Old phone", "USA client", "служебный", "b-awg3", "Учётки"):
            self.assertIn(s, page)
        self.assertNotIn('style="', page)

    def test_05_csrf_required(self):
        token, _ = self.login()
        self.assertEqual(self.req("POST", "/new", {"name": "x", "target": "fin|awg3"}, cookie=token)[0], 403)
        self.assertEqual(self.req("POST", "/users/new", {"login": "x1", "role": "owner"}, cookie=token)[0], 403)

    def test_06_create_client_config_share_and_revoke(self):
        token, csrf = self.login()
        st, h, _ = self.req("POST", "/new", {"csrf": csrf, "name": "Иван <script>", "target": "fin|awg3"}, cookie=token)
        self.assertEqual(st, 303)
        cid = int(re.search(r"/client/(\d+)", h["Location"]).group(1))
        _, _, page = self.req("GET", h["Location"], cookie=token)
        self.assertIn("Клиент создан", page)
        self.assertIn("<svg", page)
        self.assertIn("HeaderProtectionKey = HPK", page)
        self.assertIn("Endpoint = 198.51.100.7:43000", page)
        self.assertNotIn("Иван <script>", page)
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        self.assertEqual(keys.pubkey(c["priv"]), c["pub"])
        self.assertEqual(c["created_by"], self.db.one("SELECT id FROM users WHERE login='admin'")["id"])

        _, _, page = self.req("POST", f"/client/{cid}/share", {"csrf": csrf, "hours": "24", "one_time": "1"}, cookie=token)
        link = re.search(r'value="https://[^"]+(/s/[A-Za-z0-9_-]+)"', page).group(1)
        self.assertEqual(self.req("GET", link)[0], 200)
        self.assertEqual(self.req("GET", link)[0], 404, "one-time link must not open twice")

        _, _, page = self.req("POST", f"/client/{cid}/share", {"csrf": csrf, "hours": "24"}, cookie=token)
        link2 = re.search(r'value="https://[^"]+(/s/[A-Za-z0-9_-]+)"', page).group(1)
        sid = self.db.one("SELECT id FROM shares WHERE client_id=? ORDER BY id DESC", (cid,))["id"]
        self.req("POST", f"/share/{sid}/revoke", {"csrf": csrf}, cookie=token)
        self.assertEqual(self.req("GET", link2)[0], 404, "revoked link must not open")

    def test_07_disable_enable_delete(self):
        token, csrf = self.login()
        _, h, _ = self.req("POST", "/new", {"csrf": csrf, "name": "Temp", "target": "fin|awg3"}, cookie=token)
        cid = int(re.search(r"/client/(\d+)", h["Location"]).group(1))
        pub = self.db.one("SELECT pub FROM clients WHERE id=?", (cid,))["pub"]
        peers = FAKES["fin"].containers["awg3"]["peers"]
        self.req("POST", f"/client/{cid}/disable", {"csrf": csrf}, cookie=token)
        self.assertTrue(peers[pub]["disabled"])
        self.req("POST", f"/client/{cid}/enable", {"csrf": csrf}, cookie=token)
        self.assertFalse(peers[pub]["disabled"])
        self.req("POST", f"/client/{cid}/delete", {"csrf": csrf}, cookie=token)
        self.assertNotIn(pub, peers)

    def test_08_protected_peer_untouchable(self):
        token, csrf = self.login()
        cid = self.db.one("SELECT id FROM clients WHERE pub=?", (AGENT_PUB,))["id"]
        _, _, page = self.req("POST", f"/client/{cid}/delete", {"csrf": csrf}, cookie=token)
        self.assertIn("служебный", page)
        self.assertIn(AGENT_PUB, FAKES["fin"].containers["amnezia-awg"]["peers"])

    def test_09_migrate_keeps_name_and_octet(self):
        token, csrf = self.login()
        old = self.db.one("SELECT * FROM clients WHERE name='Old phone'")
        _, h, _ = self.req("POST", f"/client/{old['id']}/migrate", {"csrf": csrf, "target": "fin|awg3"}, cookie=token)
        new_id = int(re.search(r"/client/(\d+)", h["Location"]).group(1))
        new = self.db.one("SELECT * FROM clients WHERE id=?", (new_id,))
        self.assertEqual((new["name"], new["ip"]), ("Old phone", "10.8.3.20/32"))

    def test_10_poller_traffic_and_counter_reset(self):
        c = FAKES["fin"].containers["amnezia-awg"]["peers"]
        pub = next(k for k, v in c.items() if v["name"] == "Old phone")
        c[pub].update(rx=5000, tx=1500)
        poller.poll_all(self.cfg, self.db)
        c[pub].update(rx=200, tx=100)
        poller.poll_all(self.cfg, self.db)
        tot = self.db.one("SELECT SUM(rx) rx, SUM(tx) tx FROM traffic WHERE pub=?", (pub,))
        self.assertEqual((tot["rx"], tot["tx"]), (4000 + 200, 1000 + 100))

    def test_10b_traffic_marks_last_seen(self):
        c = FAKES["usa"].containers["xray"]["peers"]
        uid = "11111111-2222-3333-4444-555555555555"
        c[uid] = {"name": "vless seen", "ip": "", "disabled": False, "rx": 100, "tx": 100, "hs": 0}
        poller.poll_all(self.cfg, self.db)
        c[uid].update(rx=5000, tx=9000)
        poller.poll_all(self.cfg, self.db)
        hs = self.db.one("SELECT hs FROM peer_state WHERE pub=?", (uid,))["hs"]
        self.assertGreater(hs, time.time() - 60, "traffic without a protocol timestamp still counts as seen")
        del c[uid]

    def test_11_peer_removed_outside_panel_is_marked_deleted(self):
        c = FAKES["fin"].containers["amnezia-awg"]["peers"]
        gone = keys.pubkey(keys.genkey())
        c[gone] = {"name": "Temp app client", "ip": "10.8.1.9/32", "disabled": False, "rx": 0, "tx": 0, "hs": 0}
        poller.poll_all(self.cfg, self.db)
        del c[gone]
        poller.poll_all(self.cfg, self.db)
        self.assertIsNotNone(self.db.one("SELECT deleted FROM clients WHERE pub=?", (gone,))["deleted"])

    def test_12_app_links_platform_first(self):
        token, csrf = self.login()
        _, h, _ = self.req("POST", "/new", {"csrf": csrf, "name": "Apps test", "target": "fin|awg3"}, cookie=token)
        cid = int(re.search(r"/client/(\d+)", h["Location"]).group(1))
        _, _, card = self.req("GET", f"/client/{cid}", cookie=token)
        self.assertIn("Приложения для клиента", card)
        self.assertIn("play.google.com/store/apps/details?id=org.amnezia.vpn", card)
        links = []
        for _ in range(2):
            _, _, page = self.req("POST", f"/client/{cid}/share", {"csrf": csrf, "hours": "24"}, cookie=token)
            links.append(re.search(r'value="https://[^"]+(/s/[A-Za-z0-9_-]+)"', page).group(1))
        iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15"
        android = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/128 Mobile"
        _, _, p_ios = self.req("GET", links[0], ua=iphone)
        self.assertLess(p_ios.index("apps.apple.com"), p_ios.index("play.google.com"), "iPhone: App Store first")
        self.assertIn("DefaultVPN", p_ios)
        self.assertIn("нет в российском App Store", p_ios)
        self.assertIn("AWG 3.1", p_ios)
        self.assertIn('rel="noopener noreferrer"', p_ios)
        _, _, p_and = self.req("GET", links[1], ua=android)
        self.assertLess(p_and.index("play.google.com"), p_and.index("apps.apple.com"), "Android: Google Play first")
        self.assertNotIn('style="', p_and)

    def test_20_admin_account_sees_only_its_servers(self):
        token, csrf = self.login()
        _, _, page = self.req("POST", "/users/new", {"csrf": csrf, "login": "Petrov", "name": "Пётр", "role": "admin",
                                                     "servers": ["usa"]}, cookie=token)
        invite = re.search(r'value="https://panel\.test:2053(/invite/[A-Za-z0-9_-]+)"', page).group(1)
        self.assertEqual(self.req("GET", invite)[0], 200)
        st, _, page = self.req("POST", invite, {"password": "short", "password2": "short"})
        self.assertEqual(st, 400)
        st, h, _ = self.req("POST", invite, {"password": "petrov-pass-123", "password2": "petrov-pass-123"})  # gitleaks:allow (test fixture password)
        self.assertEqual(st, 303, "invite should log the colleague in")
        adm = self.token_of(h)
        self.assertEqual(self.req("GET", invite)[0], 404, "invite link is one-time")
        _, _, page = self.req("GET", "/", cookie=adm)
        self.assertIn("USA client", page)
        self.assertNotIn("Old phone", page)
        self.assertNotIn("Учётки", page)
        fin_client = self.cid("Old phone")
        self.assertEqual(self.req("GET", f"/client/{fin_client}", cookie=adm)[0], 404)
        acsrf = self.csrf_of(adm)
        self.assertEqual(self.req("POST", f"/client/{fin_client}/disable", {"csrf": acsrf}, cookie=adm)[0], 404)
        self.assertEqual(self.req("GET", "/users", cookie=adm)[0], 404)
        _, _, page = self.req("GET", "/new", cookie=adm)
        self.assertIn("США", page)
        self.assertNotIn("Финляндия", page)
        st, _, page = self.req("POST", "/new", {"csrf": acsrf, "name": "Hack", "target": "fin|awg3"}, cookie=adm)
        self.assertEqual(st, 400)
        _, h, _ = self.req("POST", "/new", {"csrf": acsrf, "name": "Колле клиент", "target": "usa|awg3"}, cookie=adm)
        self.assertEqual(h["Location"].split("?")[0].rsplit("/", 1)[0], "/client")
        _, _, page = self.req("GET", "/log", cookie=adm)
        self.assertIn("Колле клиент", page)
        self.assertNotIn("Иван", page, "admin must not see events of other servers")
        self.assertEqual(self.req("POST", "/login", {"login": "petrov", "password": "petrov-pass-123"})[0], 303,  # gitleaks:allow (test fixture password)
                         "logins are case-insensitive")

    def test_21_password_change_closes_other_sessions(self):
        a, csrf = self.login()
        b, _ = self.login()
        st, _, page = self.req("POST", "/me/password", {"csrf": csrf, "current": "wrong", "password": "x" * 12,
                                                        "password2": "x" * 12}, cookie=a)
        self.assertIn("Текущий пароль неверный", page)
        new = "new owner password 1"
        _, _, page = self.req("POST", "/me/password", {"csrf": csrf, "current": OWNER_PW, "password": new,
                                                       "password2": new}, cookie=a)
        self.assertIn("Пароль сменён", page)
        self.assertEqual(self.req("GET", "/", cookie=b)[0], 303, "other session must be closed")
        self.assertEqual(self.req("GET", "/", cookie=a)[0], 200, "own session stays")
        self.req("POST", "/me/password", {"csrf": csrf, "current": new, "password": OWNER_PW, "password2": OWNER_PW},
                 cookie=a)

    def test_22_last_owner_is_protected(self):
        token, csrf = self.login()
        me_id = self.db.one("SELECT id FROM users WHERE login='admin'")["id"]
        _, _, page = self.req("POST", f"/users/{me_id}/delete", {"csrf": csrf}, cookie=token)
        self.assertIn("нельзя удалить самого себя", page)
        _, _, page = self.req("POST", f"/users/{me_id}/update", {"csrf": csrf, "name": "x", "role": "admin",
                                                                 "servers": ["fin"]}, cookie=token)
        self.assertIn("нельзя понизить самого себя", page)
        self.assertEqual(self.db.one("SELECT role FROM users WHERE id=?", (me_id,))["role"], "owner")

    def test_23_reset_and_disable_account(self):
        token, csrf = self.login()
        uid = self.db.one("SELECT id FROM users WHERE login='petrov'")["id"]
        adm, _ = self.login("petrov", "petrov-pass-123")
        _, _, page = self.req("POST", f"/users/{uid}/reset", {"csrf": csrf}, cookie=token)
        self.assertIn("/invite/", page)
        self.assertEqual(self.req("GET", "/", cookie=adm)[0], 303, "reset closes the colleague's sessions")
        self.assertEqual(self.req("POST", "/login", {"login": "petrov", "password": "petrov-pass-123"})[0], 401,  # gitleaks:allow (test fixture password)
                         "old password stops working after reset")
        inv = self.db.one("SELECT id FROM invites WHERE user_id=? AND used_at IS NULL", (uid,))
        self.db.x("UPDATE invites SET expires=? WHERE id=?", (int(time.time()) - 1, inv["id"]))
        link = re.search(r'(/invite/[A-Za-z0-9_-]+)', page).group(1)
        self.assertEqual(self.req("GET", link)[0], 404, "expired invite")
        self.req("POST", f"/users/{uid}/disable", {"csrf": csrf}, cookie=token)
        self.assertEqual(self.db.one("SELECT disabled FROM users WHERE id=?", (uid,))["disabled"], 1)
        _, _, page = self.req("POST", f"/users/{uid}/delete", {"csrf": csrf}, cookie=token)
        self.assertIn("удалена", page)

    def test_24_lockout_by_login_across_ips(self):
        now = int(time.time())
        for i in range(5):
            self.db.x("INSERT INTO logins(ts, ip, ok, login) VALUES(?,?,0,'victim')", (now - i, f"203.0.113.{i}"))
        self.assertTrue(auth.blocked(self.cfg, self.db, "198.51.100.99", "victim"))
        self.assertFalse(auth.blocked(self.cfg, self.db, "198.51.100.99", "someone"))

    def _new_client(self, token, csrf, name, target, **extra):
        form = {"csrf": csrf, "name": name, "target": target}
        form.update(extra)
        st, h, page = self.req("POST", "/new", form, cookie=token)
        self.assertEqual(st, 303, page[:500])
        return int(re.search(r"/client/(\d+)", h["Location"]).group(1))

    def test_30_vless_client(self):
        token, csrf = self.login()
        cid = self._new_client(token, csrf, "Мария VLESS", "usa|xray")
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        self.assertRegex(c["pub"], r"^[0-9a-f-]{36}$")
        self.assertIn(c["pub"], FAKES["usa"].containers["xray"]["peers"])
        _, _, page = self.req("GET", f"/client/{cid}", cookie=token)
        self.assertIn(f"vless://{c['pub']}@198.51.100.8:46000?", page)
        for part in ("pbk=PBKtest", "sid=ab12cd34", "sni=www.apple.com", "security=reality", "<svg", "Hiddify"):
            self.assertIn(part, page)
        _, _, page = self.req("POST", f"/client/{cid}/share", {"csrf": csrf, "hours": "24"}, cookie=token)
        link = re.search(r'value="https://[^"]+(/s/[A-Za-z0-9_-]+)"', page).group(1)
        _, _, pub = self.req("GET", link, ua="Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)")
        self.assertIn("Shadowrocket", pub)
        self.assertIn("Копировать ссылку", pub)

    def test_31_sstp_client(self):
        token, csrf = self.login()
        cid = self._new_client(token, csrf, "Офис Windows", "usa|sstp", login="office.win")
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        self.assertEqual(c["pub"], "office.win")
        self.assertEqual(len(c["secret"]), 16)
        self.assertEqual(FAKES["usa"].containers["sstp"]["peers"]["office.win"]["psk"], c["secret"])
        _, _, page = self.req("GET", f"/client/{cid}", cookie=token)
        for part in ("198.51.100.8:45000", "office.win", c["secret"], "Скачать сертификат", "Open SSTP Client"):
            self.assertIn(part, page)
        cid2 = self._new_client(token, csrf, "Авто логин", "usa|sstp")
        self.assertRegex(self.db.one("SELECT pub FROM clients WHERE id=?", (cid2,))["pub"], r"^u[a-z0-9]{7}$")

    def _wait_job(self, jid, token):
        for _ in range(50):
            job = self.db.one("SELECT * FROM jobs WHERE id=?", (jid,))
            if job["status"] != "running":
                return job
            time.sleep(0.1)
        self.fail("job did not finish")

    def test_32_install_job_and_protected_uninstall(self):
        token, csrf = self.login()
        _, _, page = self.req("GET", "/servers", cookie=token)
        self.assertIn("Установить SSTP", page)  # fin has no sstp
        calls = []

        def fake_stream(cfg, server, *args, on_line=None, timeout=1500):
            calls.append((server["id"], args))
            on_line("[vpnctl] pulling image")
            on_line("[vpnctl] SSTP is running on TCP 51000")
            return {"ok": True, "unit": "sstp", "port": 51000}
        orig = runner.stream
        runner.stream = web.runner.stream = fake_stream
        try:
            st, h, _ = self.req("POST", "/servers/fin/install", {"csrf": csrf, "proto": "sstp", "port": "51000"}, cookie=token)
            self.assertEqual(st, 303)
            jid = int(h["Location"].rsplit("/", 1)[1])
            job = self._wait_job(jid, token)
            self.assertEqual(job["status"], "ok")
            self.assertEqual(calls[-1], ("fin", ("install", "sstp", "--port", "51000")))
            _, _, jp = self.req("GET", f"/jobs/{jid}", cookie=token)
            self.assertIn("SSTP is running on TCP 51000", jp)
            _, _, page = self.req("POST", "/servers/fin/uninstall", {"csrf": csrf, "proto": "awg3"}, cookie=token)
            self.assertIn("служебный туннель", page)
            self.assertNotIn(("fin", ("uninstall", "awg3")), calls)
            _, _, page = self.req("POST", "/servers/fin/install", {"csrf": csrf, "proto": "vless", "port": "99999"}, cookie=token)
            self.assertIn("порт", page)
        finally:
            runner.stream = web.runner.stream = orig

    def test_33_add_and_remove_server(self):
        token, csrf = self.login()
        seen = []

        def fake_admin_run(self_, remote, stdin=None, timeout=120):
            seen.append((remote, stdin))
            if remote.startswith("id -u"):
                return "0 198.51.100.5\n"
            return ""
        orig_run, orig_new, orig_pub = servers.Admin.run, servers.new_id, servers.panel_pubkey
        servers.Admin.run = fake_admin_run
        servers.new_id = lambda db, title: "nl"
        servers.panel_pubkey = lambda cfg: "ssh-ed25519 AAAAtest vpn-panel@test"
        try:
            st, h, page = self.req("POST", "/servers/new", {"csrf": csrf, "title": "Нидерланды", "host": "203.0.113.20",
                                                            "port": "22", "user": "root", "password": "x"}, cookie=token)
            self.assertEqual(st, 303, page[:300])
            job = self._wait_job(int(h["Location"].rsplit("/", 1)[1]), token)
            self.assertEqual(job["status"], "ok", job["log"])
        finally:
            servers.Admin.run, servers.new_id, servers.panel_pubkey = orig_run, orig_new, orig_pub
        keyline = next(sd for r, sd in seen if "authorized_keys" in r).decode()
        self.assertIn('command="/usr/local/sbin/vpnctl --ssh"', keyline)
        self.assertIn('from="198.51.100.5"', keyline)
        self.assertIn("no-pty", keyline)
        self.assertTrue(any(isinstance(sd, bytes) and len(sd) > 1000 for r, sd in seen if "tar -C" in r), "vpnctl bundle uploaded")
        self.assertIn("nl", [x["id"] for x in self.cfg["servers"]])
        _, _, page = self.req("GET", "/servers", cookie=token)
        self.assertIn("Нидерланды", page)
        _, _, page = self.req("POST", "/servers/nl/remove", {"csrf": csrf}, cookie=token)
        self.assertIn("убран из панели", page)
        self.assertTrue(getattr(FAKES["nl"], "unlinked", False), "panel key removed from the server")
        self.assertNotIn("nl", [x["id"] for x in self.cfg["servers"]])
        _, _, page = self.req("POST", "/servers/fin/remove", {"csrf": csrf}, cookie=token)
        self.assertIn("config.json", page, "the panel host itself cannot be removed from the UI")

    def test_34_telegram_delivery(self):
        token, csrf = self.login()
        sent = []

        def fake_tg(tok, method, fields=None, files=None, timeout=30):
            sent.append((method, fields or {}, files or {}))
            return {"username": "vpn_test_bot"} if method == "getMe" else {}
        orig = delivery.tg_call
        delivery.tg_call = fake_tg
        try:
            _, _, page = self.req("POST", "/settings/telegram", {"csrf": csrf, "tg_token": "123:ABCDEFGHIJKLMNOP"}, cookie=token)
            self.assertIn("@vpn_test_bot", page)
            self.assertNotIn("123:ABCDEFGHIJKLMNOP", page, "token is never shown back in full")
            cid = self._new_client(token, csrf, "Телеграм клиент", "fin|awg3")
            _, _, page = self.req("POST", f"/client/{cid}/tg-link", {"csrf": csrf}, cookie=token)
            m = re.search(r"https://t\.me/vpn_test_bot\?start=([A-Za-z0-9_-]+)", page)
            self.assertIsNotNone(m, "deep link shown")
            upd = {"update_id": 1, "message": {"chat": {"id": 777}, "text": f"/start {m.group(1)}"}}
            delivery._handle_update(self.cfg, self.db, "123:ABCDEFGHIJKLMNOP", upd)
            methods = [x[0] for x in sent]
            self.assertIn("sendPhoto", methods)
            self.assertIn("sendDocument", methods)
            doc = next(x for x in sent if x[0] == "sendDocument")
            self.assertIn(b"HeaderProtectionKey", doc[2]["document"][1])
            self.assertEqual(self.db.one("SELECT tg_chat_id FROM clients WHERE id=?", (cid,))["tg_chat_id"], 777)
            sent.clear()
            delivery._handle_update(self.cfg, self.db, "123:ABCDEFGHIJKLMNOP", dict(upd, update_id=2))
            self.assertIn("недействительна", sent[-1][1]["text"], "deep link is one-time")
            sent.clear()
            _, _, page = self.req("POST", f"/client/{cid}/tg-send", {"csrf": csrf}, cookie=token)
            self.assertIn("Отправлено в Telegram", page)
            self.assertTrue(all(x[1].get("chat_id") == 777 for x in sent))
        finally:
            delivery.tg_call = orig

    def test_35_email_delivery(self):
        token, csrf = self.login()
        box = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None, context=None):
                box.append(("connect", host, port))

            def starttls(self, context=None):
                box.append(("starttls",))

            def login(self, user, pw):
                box.append(("login", user))

            def send_message(self, msg):
                box.append(("send", msg))

            def quit(self):
                pass
        import smtplib
        orig = smtplib.SMTP
        smtplib.SMTP = FakeSMTP
        delivery.smtplib.SMTP = FakeSMTP
        try:
            _, _, page = self.req("POST", "/settings/smtp", {"csrf": csrf, "smtp_host": "smtp.example.com", "smtp_port": "587",
                                                             "smtp_security": "starttls", "smtp_user": "vpn@example.com",
                                                             "smtp_pass": "mail-secret-1", "smtp_from": "VPN <vpn@example.com>"},
                                  cookie=token)
            self.assertIn("Сохранено", page)
            self.assertNotIn("mail-secret-1", page)
            cid = self._new_client(token, csrf, "Почтовый клиент", "fin|awg3")
            _, _, page = self.req("POST", f"/client/{cid}/email", {"csrf": csrf, "email": "ivan@example.org"}, cookie=token)
            self.assertIn("Письмо отправлено на ivan@example.org", page)
            msg = next(x[1] for x in box if x[0] == "send")
            self.assertEqual(msg["To"], "ivan@example.org")
            names = [p.get_filename() for p in msg.iter_attachments()]
            self.assertTrue(any(n and n.endswith(".conf") for n in names), names)
            self.assertIn("image/png", [p.get_content_type() for p in msg.walk()])
            _, _, page = self.req("POST", f"/client/{cid}/email", {"csrf": csrf, "email": "bad\r\nBcc: x@y"}, cookie=token)
            self.assertIn("неверный адрес", page)
        finally:
            smtplib.SMTP = orig
            delivery.smtplib.SMTP = orig

    def test_36_telegram_requests_with_approval(self):
        token, csrf = self.login()
        sent = []

        def fake_tg(tok, method, fields=None, files=None, timeout=30):
            sent.append((method, fields or {}, files or {}))
            return {"username": "vpn_test_bot"} if method == "getMe" else {}
        orig = delivery.tg_call
        delivery.tg_call = fake_tg
        T = "123:ABCDEFGHIJKLMNOP"
        try:
            self.req("POST", "/settings/telegram", {"csrf": csrf, "tg_token": T}, cookie=token)
            _, _, page = self.req("POST", "/settings/tg-admin", {"csrf": csrf}, cookie=token)
            link = re.search(r"start=(a_[A-Za-z0-9_-]+)", page).group(1)
            delivery._handle_update(self.cfg, self.db, T, {"update_id": 10, "message": {"chat": {"id": 1001, "type": "private"}, "text": f"/start {link}"}})
            self.assertEqual(self.db.one("SELECT tg_chat_id FROM users WHERE login='admin'")["tg_chat_id"], 1001)
            sent.clear()
            # a stranger asks for access
            delivery._handle_update(self.cfg, self.db, T, {"update_id": 11, "message": {"chat": {"id": 555, "type": "private"}, "text": "/start"}})
            self.assertIn("Запросить доступ", sent[-1][1]["reply_markup"])
            sent.clear()
            cb = lambda chat, data, uid=12: {"update_id": uid, "callback_query": {"id": "q", "data": data, "from": {"first_name": "Пётр", "username": "petr"},
                                                                                "message": {"chat": {"id": chat}, "message_id": 7, "text": "📨 Заявка\n\nВыберите"}}}
            delivery._handle_update(self.cfg, self.db, T, cb(555, "req"))
            r = self.db.one("SELECT * FROM tg_requests WHERE chat_id=555")
            self.assertEqual(r["status"], "pending")
            to_owner = [x for x in sent if x[0] == "sendMessage" and x[1].get("chat_id") == 1001]
            self.assertTrue(to_owner and "ap:" in to_owner[0][1]["reply_markup"], "owner gets approve buttons")
            self.assertEqual(self.db.q("SELECT id FROM clients WHERE tg_chat_id=555"), [], "nothing is issued before approval")
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, cb(555, "req", 13))
            self.assertIn("уже", sent[-1][1]["text"], "one open request per chat")
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, cb(555, f"ap:{r['id']}:0", 14))
            self.assertIn("только владельцы", sent[-1][1]["text"], "a stranger cannot approve")
            tl = json.loads(self.db.one("SELECT targets FROM tg_requests WHERE id=?", (r["id"],))["targets"])
            i = next(i for i, t in enumerate(tl) if t[1] == "xray")
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, cb(1001, f"ap:{r['id']}:{i}", 15))
            c = self.db.one("SELECT * FROM clients WHERE tg_chat_id=555")
            self.assertIsNotNone(c, "approved -> client created")
            self.assertEqual((c["server"], c["container"]), ("usa", "xray"))
            self.assertTrue(any(x[0] == "sendPhoto" and x[1].get("chat_id") == 555 for x in sent), "config sent to the requester")
            self.assertTrue(any(x[0] == "editMessageText" and "Выдано" in x[1].get("text", "") for x in sent))
            self.assertEqual(self.db.one("SELECT status FROM tg_requests WHERE id=?", (r["id"],))["status"], "approved")
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, {"update_id": 16, "message": {"chat": {"id": 555, "type": "private"}, "text": "/start"}})
            self.assertIn("resend", sent[-1][1]["reply_markup"], "known user can ask for the settings again")
            # second person: rejected from the panel, then cooldown
            delivery._handle_update(self.cfg, self.db, T, cb(666, "req", 17))
            r2 = self.db.one("SELECT * FROM tg_requests WHERE chat_id=666")
            _, _, page = self.req("GET", "/requests", cookie=token)
            self.assertIn("Пётр", page)
            _, _, page = self.req("POST", f"/requests/{r2['id']}/reject", {"csrf": csrf}, cookie=token)
            self.assertIn("отклонена", page)
            self.assertTrue(any(x[1].get("chat_id") == 666 and "отклонили" in x[1].get("text", "") for x in sent))
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, cb(666, "req", 18))
            self.assertTrue(any("Попробуйте позже" in (x[1].get("text") or "") for x in sent), "cooldown after refusal")
            # third person approved in the panel
            delivery._handle_update(self.cfg, self.db, T, cb(777, "req", 19))
            r3 = self.db.one("SELECT * FROM tg_requests WHERE chat_id=777")
            st, h, _ = self.req("POST", f"/requests/{r3['id']}/approve", {"csrf": csrf, "target": "fin|awg3"}, cookie=token)
            self.assertEqual(st, 303)
            self.assertIn("ok=approved", h["Location"])
        finally:
            delivery.tg_call = orig

    def test_37_bot_admin_menu(self):
        sent = []

        def fake_tg(tok, method, fields=None, files=None, timeout=30):
            sent.append((method, fields or {}, files or {}))
            return {"message_id": 99}
        orig = delivery.tg_call
        delivery.tg_call = fake_tg
        T = "123:X"
        try:
            self.db.set("tg_token", T)
            self.db.set("tg_username", "vpn_test_bot")
            self.db.x("UPDATE users SET tg_chat_id=3003 WHERE login='admin'")
            msg = lambda chat, text, uid: {"update_id": uid, "message": {"chat": {"id": chat, "type": "private"}, "text": text}}
            cb = lambda chat, data, uid: {"update_id": uid, "callback_query": {"id": "q", "data": data, "from": {},
                                                                              "message": {"chat": {"id": chat}, "message_id": 5, "text": ""}}}
            last = lambda: [x for x in sent if x[0] != "answerCallbackQuery"][-1]
            delivery._handle_update(self.cfg, self.db, T, msg(3003, "/start", 100))
            self.assertIn("Клиенты", sent[-1][1]["reply_markup"])
            self.assertNotIn("Запросить доступ", sent[-1][1]["reply_markup"], "owner gets the menu, not the request button")
            delivery._handle_update(self.cfg, self.db, T, cb(3003, "m:cl:0", 101))
            self.assertEqual(last()[0], "editMessageText")
            self.assertIn("Old phone", last()[1]["reply_markup"])
            delivery._handle_update(self.cfg, self.db, T, cb(3003, "m:new", 102))
            tl = json.loads(self.db.one("SELECT data FROM tg_state WHERE chat_id=3003")["data"])["targets"]
            i = next(i for i, t in enumerate(tl) if t[:2] == ["fin", "awg3"])
            delivery._handle_update(self.cfg, self.db, T, cb(3003, f"m:nt:{i}", 103))
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, msg(3003, "Бот клиент", 104))
            c = self.db.one("SELECT * FROM clients WHERE name='Бот клиент'")
            self.assertIsNotNone(c, "client created from Telegram")
            self.assertTrue(any(x[0] == "sendPhoto" and x[1]["chat_id"] == 3003 for x in sent), "config sent to the owner")
            self.assertTrue(any("Создан" in x[1].get("text", "") for x in sent))
            peers = FAKES["fin"].containers["awg3"]["peers"]
            delivery._handle_update(self.cfg, self.db, T, cb(3003, f"m:off:{c['id']}", 105))
            self.assertTrue(peers[c["pub"]]["disabled"])
            delivery._handle_update(self.cfg, self.db, T, cb(3003, f"m:on:{c['id']}", 106))
            self.assertFalse(peers[c["pub"]]["disabled"])
            delivery._handle_update(self.cfg, self.db, T, cb(3003, f"m:ext:{c['id']}", 107))
            self.assertGreater(self.db.one("SELECT expires FROM clients WHERE id=?", (c["id"],))["expires"], time.time() + 29 * 86400)
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, cb(3003, f"m:lk:{c['id']}", 108))
            self.assertIn("t.me/vpn_test_bot?start=", sent[0][1]["text"])
            delivery._handle_update(self.cfg, self.db, T, cb(3003, f"m:del:{c['id']}", 109))
            self.assertIn("Удалить", last()[1]["text"])
            self.assertIn(c["pub"], peers, "delete asks for confirmation first")
            delivery._handle_update(self.cfg, self.db, T, cb(3003, f"m:delok:{c['id']}", 110))
            self.assertNotIn(c["pub"], peers)
            # stranger cannot use the menu
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, cb(9999, "m:cl:0", 111))
            self.assertIn("Нет доступа", sent[-1][1]["text"])
            # admin account limited to USA
            uid = self.db.x("INSERT INTO users(login, name, role, pw_hash, servers, created, tg_chat_id) VALUES('botadm','','admin','x','[\"usa\"]',?,4004)",
                            (int(time.time()),))
            sent.clear()
            delivery._handle_update(self.cfg, self.db, T, cb(4004, "m:cl:0", 112))
            kb = last()[1]["reply_markup"]
            self.assertIn("USA client", kb)
            self.assertNotIn("Old phone", kb)
            self.db.x("DELETE FROM users WHERE id=?", (uid,))
        finally:
            delivery.tg_call = orig
            self.db.x("DELETE FROM settings WHERE key IN ('tg_token','tg_username')")

    def test_40_alerts_to_owner(self):
        sent = []
        orig = delivery.tg_call
        delivery.tg_call = lambda tok, m, fields=None, files=None, timeout=30: sent.append((m, fields or {})) or {}
        try:
            self.db.set("tg_token", "123:X")
            self.db.x("UPDATE users SET tg_chat_id=4242 WHERE login='admin'")
            self.db.x("INSERT OR REPLACE INTO server_health(server, ok, checked, error) VALUES('usa', 0, ?, 'timeout')", (int(time.time()),))
            alerts.evaluate(self.cfg, self.db)
            self.assertEqual([x for x in sent if "🔴" in x[1].get("text", "")], [], "no alert inside the grace period")
            self.db.x("UPDATE alerts SET since=since-300")
            alerts.evaluate(self.cfg, self.db)
            red = [x for x in sent if "🔴" in x[1].get("text", "")]
            self.assertEqual(len(red), 1)
            self.assertIn("США", red[0][1]["text"])
            self.assertEqual(red[0][1]["chat_id"], 4242)
            alerts.evaluate(self.cfg, self.db)
            self.assertEqual(len([x for x in sent if "🔴" in x[1].get("text", "")]), 1, "sent once, not every poll")
            self.db.x("UPDATE server_health SET ok=1 WHERE server='usa'")
            alerts.evaluate(self.cfg, self.db)
            self.assertTrue(any("✅" in x[1].get("text", "") and "США" in x[1]["text"] for x in sent))
            # hourly: low disk
            orig_pf = FAKES["fin"].run
            FAKES["fin"].run = lambda args, stdin="": ({"version": "2", "free_mb": 120, "units": []} if args[0] == "preflight" else orig_pf(args, stdin))
            try:
                alerts.evaluate(self.cfg, self.db, hourly=True)
                self.db.x("UPDATE alerts SET since=since-300")
                alerts.evaluate(self.cfg, self.db)
            finally:
                FAKES["fin"].run = orig_pf
            self.assertTrue(any("120 МБ" in x[1].get("text", "") for x in sent))
            alerts.evaluate(self.cfg, self.db, hourly=True)
        finally:
            delivery.tg_call = orig
            self.db.x("DELETE FROM settings WHERE key='tg_token'")

    def test_41_expiry_and_quota(self):
        token, csrf = self.login()
        cid = self._new_client(token, csrf, "Лимитный", "fin|awg3", term="30", quota_gb="1")
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        self.assertGreater(c["expires"], time.time() + 29 * 86400)
        self.assertEqual(c["quota_gb"], 1.0)
        peers = FAKES["fin"].containers["awg3"]["peers"]
        # expiry
        self.db.x("UPDATE clients SET expires=? WHERE id=?", (int(time.time()) - 10, cid))
        limits.enforce(self.cfg, self.db)
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        self.assertEqual((c["disabled"], c["auto_off"]), (1, "expired"))
        self.assertTrue(peers[c["pub"]]["disabled"])
        _, _, page = self.req("GET", "/", cookie=token)
        self.assertIn("срок истёк", page)
        _, _, page = self.req("POST", f"/client/{cid}/enable", {"csrf": csrf}, cookie=token)
        self.assertIn("продлите", page, "manual enable refused while the limit still applies")
        _, _, page = self.req("POST", f"/client/{cid}/limits", {"csrf": csrf, "extend": "30"}, cookie=token)
        self.assertIn("снова включён", page)
        self.assertFalse(peers[c["pub"]]["disabled"])
        # quota: 2 GB used this month over a 1 GB limit
        now = int(time.time())
        self.db.x("INSERT OR REPLACE INTO traffic VALUES(?,?,?,?,?,?)", ("fin", "awg3", c["pub"], now - now % 3600, 2 * 1024 ** 3, 0))
        limits.enforce(self.cfg, self.db)
        self.assertEqual(self.db.one("SELECT auto_off FROM clients WHERE id=?", (cid,))["auto_off"], "quota")
        _, _, page = self.req("GET", f"/client/{cid}", cookie=token)
        self.assertIn("исчерпан лимит", page)
        _, _, page = self.req("POST", f"/client/{cid}/limits", {"csrf": csrf, "expires": "", "quota_gb": "5", "quota_period": "month"}, cookie=token)
        self.assertIn("снова включён", page)
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        self.assertEqual((c["disabled"], c["auto_off"], c["expires"], c["quota_gb"]), (0, None, None, 5.0))
        _, _, page = self.req("POST", f"/client/{cid}/limits", {"csrf": csrf, "quota_gb": "-3"}, cookie=token)
        self.assertIn("Не сохранено", page)

    def test_99_lockout_by_ip(self):
        # earlier tests already left a few failures from 127.0.0.1, so the block may come before the 5th try
        codes = [self.req("POST", "/login", {"login": "admin", "password": "wrong"})[0] for _ in range(5)]
        self.assertEqual(set(codes) - {401, 429}, set())
        self.assertIn(429, codes + [self.req("POST", "/login", {"login": "admin", "password": "wrong"})[0]])
        self.assertEqual(self.req("POST", "/login", {"login": "admin", "password": OWNER_PW})[0], 429,
                         "correct password must be refused while the IP is blocked")


class ServerLogTest(unittest.TestCase):
    def test_tls_noise_is_quiet_real_errors_are_logged(self):
        srv = web.PanelServer.__new__(web.PanelServer)
        with self.assertLogs("vpnpanel.web", level="DEBUG") as cm:
            try:
                raise ssl.SSLError(1, "[SSL: SSLV3_ALERT_CERTIFICATE_UNKNOWN] alert")
            except ssl.SSLError:
                srv.handle_error(None, ("203.0.113.5", 1))
            try:
                raise ValueError("boom")
            except ValueError:
                srv.handle_error(None, ("203.0.113.6", 2))
        quiet, loud = cm.records
        self.assertEqual(quiet.levelname, "DEBUG")
        self.assertIsNone(quiet.exc_info)
        self.assertEqual(loud.levelname, "ERROR")
        self.assertIsNotNone(loud.exc_info)


class ProxyProtocolTest(unittest.TestCase):
    def test_real_address_behind_local_proxy_over_tls(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=t",
                        "-keyout", f"{tmp}/k", "-out", f"{tmp}/c"], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{tmp}/c", f"{tmp}/k")
        seen = []

        class Echo(web.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.client_address[0])
                self.send_response(204)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = web.PanelServer(("127.0.0.1", 0), Echo, ssl_ctx=ctx, proxy_from=["127.0.0.1"])
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            cctx = ssl._create_unverified_context()
            for header in (b"PROXY TCP4 198.51.100.7 127.0.0.1 40000 443\r\n", b""):
                raw = socket.create_connection(("127.0.0.1", port))
                raw.sendall(header)
                with cctx.wrap_socket(raw) as s:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    self.assertIn(b"204", s.recv(100))
            self.assertEqual(seen, ["198.51.100.7", "127.0.0.1"])
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
