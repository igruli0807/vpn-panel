"""python3 -m vpnpanel <command>

  serve                          run the web panel and the poller
  set-password [LOGIN]           set a password (default: the first owner; creates owner "admin" if none)
  user list                      list accounts
  user add LOGIN [--name N] [--role owner|admin] [--servers id,id]   create an account, print an invite link
  user invite LOGIN              new one-time link to set the password (old password and sessions stop working)
  poll-once                      poll all servers once and print a summary (used by doctor.sh)
  import-client --server S --container C --conf FILE [--name N]
                                 attach an existing client config (with its private key) to the panel
"""
import argparse
import getpass
import json
import logging
import sys
import time

from . import accounts, auth, config, keys, poller
from .db import DB


def _read_password():
    if sys.stdin.isatty():
        p1, p2 = getpass.getpass("Пароль: "), getpass.getpass("Ещё раз: ")
        if p1 != p2:
            raise SystemExit("пароли не совпали")
        return p1
    return sys.stdin.readline().rstrip("\n")


def _invite_url(cfg, token):
    base = cfg.get("public_url") or f"https://<адрес панели>:{cfg['port']}"
    return f"{base.rstrip('/')}/invite/{token}"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vpnpanel")
    ap.add_argument("--config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    sp = sub.add_parser("set-password")
    sp.add_argument("login", nargs="?")
    sub.add_parser("poll-once")
    us = sub.add_parser("user").add_subparsers(dest="ucmd", required=True)
    us.add_parser("list")
    ua = us.add_parser("add")
    ua.add_argument("login")
    ua.add_argument("--name", default="")
    ua.add_argument("--role", default="admin", choices=["owner", "admin"])
    ua.add_argument("--servers", default="")
    ui = us.add_parser("invite")
    ui.add_argument("login")
    imp = sub.add_parser("import-client")
    imp.add_argument("--server", required=True)
    imp.add_argument("--container", required=True)
    imp.add_argument("--conf", required=True)
    imp.add_argument("--name", default="")
    a = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = config.load(a.config)
    db = DB(cfg["db"])

    if a.cmd == "serve":
        from . import web
        if not db.one("SELECT 1 FROM users WHERE pw_hash IS NOT NULL AND disabled=0"):
            print("no account with a password: run `python3 -m vpnpanel set-password`", file=sys.stderr)
            return 1
        poller.start(cfg, db)
        web.serve(cfg, db)
        return 0

    if a.cmd == "set-password":
        if a.login:
            u = db.one("SELECT * FROM users WHERE login=?", (a.login.lower(),))
            if not u:
                print(f"нет учётки {a.login}", file=sys.stderr)
                return 1
        else:
            u = db.one("SELECT * FROM users WHERE role='owner' ORDER BY id LIMIT 1")
            if not u:
                uid = db.x("INSERT INTO users(login, name, role, created) VALUES('admin', 'Владелец', 'owner', ?)",
                           (int(time.time()),))
                u = db.one("SELECT * FROM users WHERE id=?", (uid,))
        try:
            auth.set_password(db, u["id"], _read_password())
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 1
        db.x("UPDATE users SET disabled=0 WHERE id=?", (u["id"],))
        print(f"пароль для «{u['login']}» установлен, его сессии сброшены")
        return 0

    if a.cmd == "user":
        me = {"user_id": None}
        if a.ucmd == "list":
            for u in db.q("SELECT * FROM users ORDER BY role DESC, login"):
                state = "отключена" if u["disabled"] else ("ждёт пароль" if not u["pw_hash"] else "активна")
                print(f"{u['login']:<20} {u['role']:<6} {state:<12} servers={u['servers'] or 'все'}  {u['name']}")
            return 0
        if a.ucmd == "add":
            try:
                _, token = accounts.create(cfg, db, me, a.login, a.name, a.role,
                                           [s for s in a.servers.split(",") if s])
            except accounts.AccountError as e:
                print(str(e), file=sys.stderr)
                return 1
            print(_invite_url(cfg, token))
            return 0
        if a.ucmd == "invite":
            u = db.one("SELECT * FROM users WHERE login=?", (a.login.lower(),))
            if not u:
                print(f"нет учётки {a.login}", file=sys.stderr)
                return 1
            print(_invite_url(cfg, accounts.reset(db, u["id"])))
            return 0

    if a.cmd == "poll-once":
        summary = {}
        for s in cfg["servers"]:
            ok = poller.poll_server(cfg, db, s)
            rows = db.q("SELECT container, kind, up, peers, online FROM health WHERE server=?", (s["id"],))
            summary[s["id"]] = {"ok": ok, "containers": rows}
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if all(v["ok"] for v in summary.values()) else 2

    if a.cmd == "import-client":
        cfg.server(a.server)
        text = open(a.conf).read()
        fields = {}
        for line in text.splitlines():
            k, sep, v = line.partition("=")
            if sep:
                fields.setdefault(k.strip(), v.strip())
        priv = fields["PrivateKey"]
        pub = keys.pubkey(priv)
        db.x("INSERT INTO clients(server, container, pub, name, ip, priv, psk, source, created) "
             "VALUES(?,?,?,?,?,?,?,'panel',?) ON CONFLICT(server,container,pub) DO UPDATE SET "
             "priv=excluded.priv, psk=excluded.psk, source='panel', name=COALESCE(NULLIF(excluded.name,''), name)",
             (a.server, a.container, pub, a.name, fields.get("Address", ""), priv, fields.get("PresharedKey"),
              int(time.time())))
        print(f"imported {pub}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
