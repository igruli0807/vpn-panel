"""python3 -m vpnpanel <command>

  serve                          run the web panel and the poller
  set-password                   set the admin password (asks twice, or reads one line from stdin)
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

from . import auth, config, keys, poller
from .db import DB


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vpnpanel")
    ap.add_argument("--config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    sub.add_parser("set-password")
    sub.add_parser("poll-once")
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
        if not db.get("admin_password"):
            print("admin password is not set: run `python3 -m vpnpanel set-password`", file=sys.stderr)
            return 1
        poller.start(cfg, db)
        web.serve(cfg, db)
        return 0

    if a.cmd == "set-password":
        if sys.stdin.isatty():
            p1, p2 = getpass.getpass("Пароль: "), getpass.getpass("Ещё раз: ")
            if p1 != p2:
                print("пароли не совпали", file=sys.stderr)
                return 1
        else:
            p1 = sys.stdin.readline().rstrip("\n")
        if len(p1) < 10:
            print("пароль короче 10 символов", file=sys.stderr)
            return 1
        db.set("admin_password", auth.hash_password(p1))
        db.x("DELETE FROM sessions")
        print("пароль установлен, все сессии сброшены")
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
