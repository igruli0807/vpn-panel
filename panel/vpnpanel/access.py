"""Who may see what. Owners see every server; admins only the servers listed in their account."""
import json


def is_owner(me):
    return bool(me) and me["role"] == "owner"


def servers(cfg, me):
    """-> list of server ids this user may see and change, in config order."""
    ids = [s["id"] for s in cfg["servers"]]
    if is_owner(me):
        return ids
    try:
        mine = set(json.loads(me.get("servers") or "[]"))
    except (TypeError, ValueError):
        mine = set()
    return [i for i in ids if i in mine]


def can(cfg, me, sid):
    return sid in servers(cfg, me)


def sql(cfg, me, col="c.server"):
    """-> (where-clause, args) limiting a query to this user's servers."""
    if is_owner(me):
        return "1=1", ()
    ids = servers(cfg, me)
    if not ids:
        return "0", ()
    return f"{col} IN ({','.join('?' * len(ids))})", tuple(ids)
