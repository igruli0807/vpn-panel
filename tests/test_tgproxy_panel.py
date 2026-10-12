"""Telegram proxies in the panel (telemt: a link per client; mtg: one shared link), without servers.

    python3 -m unittest discover -s tests -p 'test_*.py'
"""
import os
import shutil
import sys
import tempfile
import unittest
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "panel"), os.path.join(ROOT, "panel", "vendor")]

from vpnpanel import clientconf, servers, service, views  # noqa: E402
from vpnpanel.db import DB  # noqa: E402

SECRET = bytes(range(16)).hex()                      # a made-up test value (32 hex characters)
SITE_HEX = "www.example.org".encode().hex()


class Cfg(dict):
    def server(self, sid):
        return next(s for s in self["servers"] if s["id"] == sid)


class TgProxyPanelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = DB(os.path.join(self.tmp, "panel.db"))
        self.cfg = Cfg(servers=[{"id": "s1", "title": "Тест", "endpoint": "203.0.113.5", "transport": "local"}],
                       protected_pubkeys=[])
        self.calls = []
        self._run = service.runner.run

        def fake_run(cfg, server, *args, stdin="", timeout=40):
            self.calls.append((args, stdin))
            if args[0] == "params" and args[1] == "telemt":
                return {"kind": "telemt", "port": 443, "domain": "www.example.org"}
            if args[0] == "params" and args[1] == "mtg-doppel":
                return {"kind": "mtg", "port": 9443, "domain": "www.example.org", "secret": "ee" + SECRET + SITE_HEX}
            return {"ok": True, "ip": ""}
        service.runner.run = fake_run
        for unit, kind, port in (("telemt", "telemt", 443), ("mtg-doppel", "mtg", 9443)):
            self.db.x("INSERT INTO health VALUES(?,?,?,?,?,?,?,?,?,NULL)", ("s1", unit, kind, port, 1, 0, 0, 0, 0))

    def tearDown(self):
        service.runner.run = self._run
        self.db.conn.close()
        shutil.rmtree(self.tmp)

    def link_parts(self, link):
        u = urllib.parse.urlsplit(link)
        return u.scheme, u.netloc + u.path, dict(urllib.parse.parse_qsl(u.query))

    def test_protocol_tables_agree(self):
        for proto in ("telemt", "mtg"):
            self.assertIn(proto, servers.PROTOCOLS)
            self.assertIn(proto, servers.SNI_PROTOCOLS)
            self.assertEqual(views.UNIT_PROTO[servers.UNIT_OF[proto]], proto)
            self.assertIn(proto, views.PROTO_TITLE)
            self.assertIn(proto, service.KIND_TITLE)
            self.assertIn(proto, views.BADGE)
            self.assertIn(proto, service.TCP_KINDS)
        self.assertIn("telemt", service.CAN_ADD)
        self.assertNotIn("mtg", service.CAN_ADD, "mtg has one shared link: nothing to add per client")

    def test_telemt_client_gets_own_link(self):
        cid = service.create_client(self.cfg, self.db, "s1", "telemt", "Иван, телефон")
        c = self.db.one("SELECT * FROM clients WHERE id=?", (cid,))
        add = next(a for a in self.calls if a[0][0] == "add")
        self.assertEqual(add[0][1], "telemt")
        self.assertRegex(c["secret"], r"^[0-9a-f]{32}$")
        self.assertEqual(add[1].strip(), c["secret"], "the secret goes to vpnctl on stdin")
        self.assertNotIn(c["secret"], " ".join(map(str, add[0])), "never on the command line")
        self.assertRegex(c["pub"], r"^[a-z0-9][a-z0-9._-]{1,31}$")
        b = service.client_config(self.cfg, self.db, c)
        scheme, where, q = self.link_parts(b["text"])
        self.assertEqual((scheme, where), ("https", "t.me/proxy"))
        self.assertEqual(q, {"server": "203.0.113.5", "port": "443", "secret": "ee" + c["secret"] + SITE_HEX})
        self.assertEqual(b["qr"], b["text"])
        self.assertTrue(b["tg_link"].startswith("tg://proxy?server=203.0.113.5&port=443&secret=ee"))
        self.assertIn("<svg", clientconf.qr_svg(b["qr"]))

    def test_telemt_login_from_form(self):
        cid = service.create_client(self.cfg, self.db, "s1", "telemt", "Мария", login="Maria.Phone")
        self.assertEqual(self.db.one("SELECT pub FROM clients WHERE id=?", (cid,))["pub"], "maria.phone")

    def test_telemt_user_made_elsewhere_has_no_link(self):
        self.db.x("INSERT INTO clients(server, container, pub, name, ip, source, created) VALUES('s1','telemt','old','Старый','','imported',1)")
        c = self.db.one("SELECT * FROM clients WHERE pub='old'")
        self.assertFalse(service.has_config(c))
        with self.assertRaises(service.OpError) as cm:
            service.client_config(self.cfg, self.db, c)
        self.assertIn("не в панели", str(cm.exception))

    def test_mtg_shared_link(self):
        self.db.x("INSERT INTO clients(server, container, pub, name, ip, source, created) "
                  "VALUES('s1','mtg-doppel','shared','Telegram — общая ссылка','','imported',1)")
        c = self.db.one("SELECT * FROM clients WHERE pub='shared'")
        self.assertTrue(service.has_config(c), "the shared link is on the server, the panel can hand it out")
        b = service.client_config(self.cfg, self.db, c)
        _, where, q = self.link_parts(b["text"])
        self.assertEqual(where, "t.me/proxy")
        self.assertEqual(q, {"server": "203.0.113.5", "port": "9443", "secret": "ee" + SECRET + SITE_HEX})
        for op in (service.disable, service.enable, service.delete):
            before = len(self.calls)
            with self.assertRaises(service.OpError) as cm:
                op(self.cfg, self.db, c["id"])
            self.assertIn("одна ссылка на всех", str(cm.exception))
            self.assertEqual(len(self.calls), before, "the server is not even asked")
        service.rename(self.cfg, self.db, c["id"], "Для отдела")
        self.assertEqual(self.calls[-1][0][:2], ("set-name", "mtg-doppel"))

    def test_pages_show_link_not_vpn_config(self):
        link = "https://t.me/proxy?server=203.0.113.5&port=443&secret=ee" + SECRET + SITE_HEX
        b = clientconf.build({"kind": "telemt", "port": 443, "domain": "www.example.org"},
                             {"name": "Иван <b>", "pub": "ivan", "secret": SECRET}, "203.0.113.5")
        self.assertEqual(b["text"], link)
        c = {"id": 1, "name": "Иван <b>"}
        block = views.config_block(b, "telemt", clientconf.qr_svg(b["qr"]), c)
        self.assertIn("Открыть в Telegram", block)
        self.assertIn("t.me/proxy?server=203.0.113.5&amp;port=443", block)
        self.assertNotIn(".conf", block)
        page = views.share_page(c, b, "telemt", clientconf.qr_svg(b["qr"]), "android")
        self.assertIn("Прокси для Telegram", page)
        self.assertIn("Подключить прокси", page)
        self.assertIn("org.telegram.messenger", page, "the app to install is Telegram itself")
        self.assertNotIn("Иван <b>", page)
        self.assertEqual(clientconf.app_links("mtg"), clientconf.app_links("telemt"))


if __name__ == "__main__":
    unittest.main()
