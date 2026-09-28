"""Panel tests without VPN servers: awgctl is replaced by an in-memory fake per server, the web server runs
for real over HTTPS with a throw-away self-signed certificate.

    python3 -m unittest discover -s tests -p 'test_*.py'
"""
import http.client
import json
import os
import re
import shutil
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

from vpnpanel import auth, config, keys, poller, runner, service, web  # noqa: E402
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
        c = self.containers[rest[0]]
        opts = dict(zip(rest[1::2], rest[2::2]))
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
            c["peers"][pub] = {"name": opts.get("--name", ""), "ip": opts["--ip"], "disabled": False,
                               "rx": 0, "tx": 0, "hs": 0, "psk": stdin.strip()}
            return {"ok": True, "ip": opts["--ip"]}
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
    }),
}


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
                       "protected_pubkeys": [AGENT_PUB], "public_url": "https://panel.test:2053",
                       "servers": [{"id": "fin", "title": "Финляндия", "endpoint": "198.51.100.7", "transport": "local"},
                                   {"id": "usa", "title": "США", "endpoint": "198.51.100.8", "transport": "local"}]}, fh)
        cls.cfg = config.load(cfgfile)
        # an install from before accounts: one password in settings -> must become owner "admin"
        old = DB(cls.cfg["db"])
        old.set("admin_password", auth.hash_password(OWNER_PW))
        old.conn.close()
        cls.db = DB(cls.cfg["db"])
        runner.run = fake_run
        service.runner.run = fake_run
        web.runner.run = fake_run
        poller.runner.run = fake_run
        poller.poll_all(cls.cfg, cls.db)

        from http.server import ThreadingHTTPServer
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(web.App(cls.cfg, cls.db)))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f"{cls.tmp}/tls.crt", f"{cls.tmp}/tls.key")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        cls.httpd = httpd
        cls.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmp)

    # ---- http helpers ----
    def req(self, method, path, form=None, cookie=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ssl._create_unverified_context(), timeout=10)
        headers, body = {}, None
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

    def test_11_peer_removed_outside_panel_is_marked_deleted(self):
        c = FAKES["fin"].containers["amnezia-awg"]["peers"]
        gone = keys.pubkey(keys.genkey())
        c[gone] = {"name": "Temp app client", "ip": "10.8.1.9/32", "disabled": False, "rx": 0, "tx": 0, "hs": 0}
        poller.poll_all(self.cfg, self.db)
        del c[gone]
        poller.poll_all(self.cfg, self.db)
        self.assertIsNotNone(self.db.one("SELECT deleted FROM clients WHERE pub=?", (gone,))["deleted"])

    def test_20_admin_account_sees_only_its_servers(self):
        token, csrf = self.login()
        _, _, page = self.req("POST", "/users/new", {"csrf": csrf, "login": "Petrov", "name": "Пётр", "role": "admin",
                                                     "servers": ["usa"]}, cookie=token)
        invite = re.search(r'value="https://panel\.test:2053(/invite/[A-Za-z0-9_-]+)"', page).group(1)
        self.assertEqual(self.req("GET", invite)[0], 200)
        st, _, page = self.req("POST", invite, {"password": "short", "password2": "short"})
        self.assertEqual(st, 400)
        st, h, _ = self.req("POST", invite, {"password": "petrov-pass-123", "password2": "petrov-pass-123"})
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
        self.assertEqual(self.req("POST", "/login", {"login": "petrov", "password": "petrov-pass-123"})[0], 303,
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
        self.assertEqual(self.req("POST", "/login", {"login": "petrov", "password": "petrov-pass-123"})[0], 401,
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

    def test_99_lockout_by_ip(self):
        # earlier tests already left a few failures from 127.0.0.1, so the block may come before the 5th try
        codes = [self.req("POST", "/login", {"login": "admin", "password": "wrong"})[0] for _ in range(5)]
        self.assertEqual(set(codes) - {401, 429}, set())
        self.assertIn(429, codes + [self.req("POST", "/login", {"login": "admin", "password": "wrong"})[0]])
        self.assertEqual(self.req("POST", "/login", {"login": "admin", "password": OWNER_PW})[0], 429,
                         "correct password must be refused while the IP is blocked")


if __name__ == "__main__":
    unittest.main()
