"""Panel tests without VPN servers: awgctl is replaced by an in-memory fake, the web server runs for real
over HTTPS with a throw-away self-signed certificate.

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


class FakeCtl:
    """Behaves like awgctl for one server with two containers."""

    def __init__(self):
        self.containers = {
            "awg3": {"kind": "awg3", "port": 43000, "up": True, "subnet": "10.8.3.1/24", "peers": {}},
            "amnezia-awg": {"kind": "legacy", "port": 49000, "up": True, "subnet": "10.8.1.0/24", "peers": {
                AGENT_PUB: {"name": "agent", "ip": "10.8.1.6/32", "disabled": False, "rx": 0, "tx": 0, "hs": 0},
                keys.pubkey(keys.genkey()): {"name": "Old phone", "ip": "10.8.1.20/32", "disabled": False,
                                             "rx": 1000, "tx": 500, "hs": int(time.time())},
            }},
        }
        self.calls = []

    def run(self, cfg, server, *args, stdin="", timeout=40):
        self.calls.append(args)
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


def return_error(msg):
    raise runner.CtlError(f"fake: {msg}")


class PanelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=test",
                        "-keyout", f"{cls.tmp}/tls.key", "-out", f"{cls.tmp}/tls.crt"], check=True, capture_output=True)
        cfgfile = f"{cls.tmp}/config.json"
        with open(cfgfile, "w") as fh:
            json.dump({"listen": "127.0.0.1", "port": 0, "tls_cert": f"{cls.tmp}/tls.crt", "tls_key": f"{cls.tmp}/tls.key",
                           "db": f"{cls.tmp}/panel.db", "timezone": "Asia/Krasnoyarsk", "protected_pubkeys": [AGENT_PUB],
                           "servers": [{"id": "fin", "title": "Финляндия", "endpoint": "198.51.100.7", "transport": "local"}]},
                      fh)
        cls.cfg = config.load(cfgfile)
        cls.db = DB(cls.cfg["db"])
        cls.db.set("admin_password", auth.hash_password("correct horse battery"))
        cls.fake = FakeCtl()
        runner.run = cls.fake.run
        service.runner.run = cls.fake.run
        web.runner.run = cls.fake.run
        poller.runner.run = cls.fake.run
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
    def req(self, method, path, form=None, cookie=None, ip_hint=None):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=ssl._create_unverified_context(), timeout=10)
        headers = {}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = f"vpsess={cookie}"
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read().decode()
        conn.close()
        return r.status, dict(r.getheaders()), data

    def login(self):
        st, h, _ = self.req("POST", "/login", {"password": "correct horse battery"})
        self.assertEqual(st, 303)
        token = re.search(r"vpsess=([^;]+)", h["Set-Cookie"]).group(1)
        _, _, page = self.req("GET", "/", cookie=token)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        return token, csrf

    # ---- tests ----
    def test_01_requires_login(self):
        st, h, _ = self.req("GET", "/")
        self.assertEqual((st, h["Location"]), (303, "/login"))

    def test_02_security_headers(self):
        _, h, _ = self.req("GET", "/login")
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Cache-Control"], "no-store")

    def test_03_login_cookie_flags(self):
        _, h, _ = self.req("POST", "/login", {"password": "correct horse battery"})
        for flag in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(flag, h["Set-Cookie"])

    def test_04_dashboard_lists_imported_and_marks_protected(self):
        token, _ = self.login()
        _, _, page = self.req("GET", "/", cookie=token)
        self.assertIn("Old phone", page)
        self.assertIn("служебный", page)
        self.assertIn("AWG 3.1", page)

    def test_05_csrf_required(self):
        token, _ = self.login()
        st, _, _ = self.req("POST", "/new", {"name": "x", "target": "fin|awg3"}, cookie=token)
        self.assertEqual(st, 403)

    def test_06_create_client_config_share_and_revoke(self):
        token, csrf = self.login()
        st, h, _ = self.req("POST", "/new", {"csrf": csrf, "name": "Иван <script>", "target": "fin|awg3"}, cookie=token)
        self.assertEqual(st, 303)
        cid = int(h["Location"].rsplit("/", 1)[1])
        _, _, page = self.req("GET", f"/client/{cid}", cookie=token)
        self.assertIn("<svg", page)                      # QR rendered
        self.assertIn("HeaderProtectionKey = HPK", page)  # awg3 config
        self.assertIn("Endpoint = 198.51.100.7:43000", page)
        self.assertNotIn("Иван <script>", page)           # escaped
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        self.assertEqual(keys.pubkey(c["priv"]), c["pub"])
        self.assertEqual(self.fake.containers["awg3"]["peers"][c["pub"]]["psk"], c["psk"])

        st, _, page = self.req("POST", f"/client/{cid}/share", {"csrf": csrf, "hours": "24", "one_time": "1"}, cookie=token)
        link = re.search(r'value="https://[^"]+(/s/[A-Za-z0-9_-]+)"', page).group(1)
        st1, _, pub_page = self.req("GET", link)
        self.assertEqual(st1, 200)
        self.assertIn("PrivateKey", pub_page)
        st2, _, _ = self.req("GET", link)
        self.assertEqual(st2, 404, "one-time link must not open twice")
        self.assertIsNone(self.db.one("SELECT * FROM shares WHERE token_hash=?", (link.rsplit('/', 1)[1],)),
                          "raw token must not be stored")

        _, _, page = self.req("POST", f"/client/{cid}/share", {"csrf": csrf, "hours": "24"}, cookie=token)
        link2 = re.search(r'value="https://[^"]+(/s/[A-Za-z0-9_-]+)"', page).group(1)
        sid = self.db.one("SELECT id FROM shares WHERE client_id=? ORDER BY id DESC", (cid,))["id"]
        self.req("POST", f"/share/{sid}/revoke", {"csrf": csrf, "client": cid}, cookie=token)
        self.assertEqual(self.req("GET", link2)[0], 404, "revoked link must not open")

    def test_07_disable_enable_delete(self):
        token, csrf = self.login()
        _, h, _ = self.req("POST", "/new", {"csrf": csrf, "name": "Temp", "target": "fin|awg3"}, cookie=token)
        cid = int(h["Location"].rsplit("/", 1)[1])
        pub = self.db.one("SELECT pub FROM clients WHERE id=?", (cid,))["pub"]
        self.req("POST", f"/client/{cid}/disable", {"csrf": csrf}, cookie=token)
        self.assertTrue(self.fake.containers["awg3"]["peers"][pub]["disabled"])
        self.req("POST", f"/client/{cid}/enable", {"csrf": csrf}, cookie=token)
        self.assertFalse(self.fake.containers["awg3"]["peers"][pub]["disabled"])
        self.req("POST", f"/client/{cid}/delete", {"csrf": csrf}, cookie=token)
        self.assertNotIn(pub, self.fake.containers["awg3"]["peers"])
        self.assertIsNone(self.db.one("SELECT priv FROM clients WHERE id=?", (cid,))["priv"])

    def test_08_protected_peer_untouchable(self):
        token, csrf = self.login()
        cid = self.db.one("SELECT id FROM clients WHERE pub=?", (AGENT_PUB,))["id"]
        _, _, page = self.req("POST", f"/client/{cid}/delete", {"csrf": csrf}, cookie=token)
        self.assertIn("служебный", page)
        self.assertIn(AGENT_PUB, self.fake.containers["amnezia-awg"]["peers"])

    def test_09_migrate_keeps_name_and_octet(self):
        token, csrf = self.login()
        old = self.db.one("SELECT * FROM clients WHERE name='Old phone'")
        _, h, _ = self.req("POST", f"/client/{old['id']}/migrate", {"csrf": csrf, "target": "fin|awg3"}, cookie=token)
        new_id = int(h["Location"].rsplit("/", 1)[1])
        new = self.db.one("SELECT * FROM clients WHERE id=?", (new_id,))
        self.assertEqual((new["name"], new["ip"]), ("Old phone", "10.8.3.20/32"))
        self.assertEqual(self.db.one("SELECT migrated_to FROM clients WHERE id=?", (old["id"],))["migrated_to"], new_id)

    def test_10_poller_traffic_and_counter_reset(self):
        c = self.fake.containers["amnezia-awg"]["peers"]
        pub = next(k for k, v in c.items() if v["name"] == "Old phone")
        c[pub].update(rx=5000, tx=1500)
        poller.poll_all(self.cfg, self.db)
        c[pub].update(rx=200, tx=100)    # interface restarted: counters dropped
        poller.poll_all(self.cfg, self.db)
        tot = self.db.one("SELECT SUM(rx) rx, SUM(tx) tx FROM traffic WHERE pub=?", (pub,))
        self.assertEqual((tot["rx"], tot["tx"]), (4000 + 200, 1000 + 100))

    def test_11_peer_removed_outside_panel_is_marked_deleted(self):
        c = self.fake.containers["amnezia-awg"]["peers"]
        gone = keys.pubkey(keys.genkey())
        c[gone] = {"name": "Temp app client", "ip": "10.8.1.9/32", "disabled": False, "rx": 0, "tx": 0, "hs": 0}
        poller.poll_all(self.cfg, self.db)
        del c[gone]
        poller.poll_all(self.cfg, self.db)
        self.assertIsNotNone(self.db.one("SELECT deleted FROM clients WHERE pub=?", (gone,))["deleted"])

    def test_12_zz_lockout(self):
        for _ in range(5):
            st, _, _ = self.req("POST", "/login", {"password": "wrong"})
            self.assertEqual(st, 401)
        st, _, _ = self.req("POST", "/login", {"password": "correct horse battery"})
        self.assertEqual(st, 429, "correct password must be refused while the IP is blocked")


if __name__ == "__main__":
    unittest.main()
