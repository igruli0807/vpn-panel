"""Account management (owner only in the UI). Guards: nobody locks themselves out, the last owner stays."""
import json
import time

from . import auth

ROLES = {"owner": "владелец", "admin": "админ"}


class AccountError(Exception):
    pass


def _clean(cfg, login, name, role, servers):
    login = (login or "").strip().lower()
    if not auth.LOGIN_RE.match(login):
        raise AccountError("логин: 2–32 символа, латиница в нижнем регистре, цифры, точка, дефис, подчёркивание")
    if role not in ROLES:
        raise AccountError("нет такой роли")
    known = {s["id"] for s in cfg["servers"]}
    servers = [s for s in (servers or []) if s in known]
    if role == "admin" and not servers:
        raise AccountError("админу нужен хотя бы один сервер")
    return login, (name or "").strip()[:64], role, servers


def owners(db, exclude=None):
    rows = db.q("SELECT id FROM users WHERE role='owner' AND disabled=0")
    return [r["id"] for r in rows if r["id"] != exclude]


def create(cfg, db, me, login, name, role, servers):
    """-> (user_id, invite_token)."""
    login, name, role, servers = _clean(cfg, login, name, role, servers)
    if db.one("SELECT 1 FROM users WHERE login=?", (login,)):
        raise AccountError("такой логин уже есть")
    uid = db.x("INSERT INTO users(login, name, role, servers, created, created_by) VALUES(?,?,?,?,?,?)",
               (login, name, role, json.dumps(servers) if role == "admin" else None, int(time.time()), me["user_id"]))
    return uid, auth.create_invite(db, uid)


def get(db, uid):
    u = db.one("SELECT * FROM users WHERE id=?", (uid,))
    if not u:
        raise AccountError("нет такой учётки")
    return u


def update(cfg, db, me, uid, name, role, servers):
    u = get(db, uid)
    _, name, role, servers = _clean(cfg, u["login"], name, role, servers)
    if uid == me["user_id"] and role != "owner":
        raise AccountError("нельзя понизить самого себя")
    if u["role"] == "owner" and role != "owner" and not owners(db, exclude=uid):
        raise AccountError("это последний владелец")
    db.x("UPDATE users SET name=?, role=?, servers=? WHERE id=?",
         (name, role, json.dumps(servers) if role == "admin" else None, uid))


def set_disabled(db, me, uid, disabled):
    u = get(db, uid)
    if disabled and uid == me["user_id"]:
        raise AccountError("нельзя отключить самого себя")
    if disabled and u["role"] == "owner" and not owners(db, exclude=uid):
        raise AccountError("это последний владелец")
    db.x("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, uid))
    if disabled:
        auth.logout_others(db, uid)


def reset(db, uid):
    """New invite link; the old password and all sessions stop working at once."""
    get(db, uid)
    db.x("UPDATE users SET pw_hash=NULL WHERE id=?", (uid,))
    auth.logout_others(db, uid)
    return auth.create_invite(db, uid)


def delete(db, me, uid):
    u = get(db, uid)
    if uid == me["user_id"]:
        raise AccountError("нельзя удалить самого себя")
    if u["role"] == "owner" and not owners(db, exclude=uid):
        raise AccountError("это последний владелец")
    auth.logout_others(db, uid)
    db.x("DELETE FROM invites WHERE user_id=?", (uid,))
    db.x("DELETE FROM users WHERE id=?", (uid,))
    return u


def rename_self(db, me, login, name):
    login = (login or "").strip().lower()
    if not auth.LOGIN_RE.match(login):
        raise AccountError("логин: 2–32 символа, латиница в нижнем регистре, цифры, точка, дефис, подчёркивание")
    other = db.one("SELECT id FROM users WHERE login=?", (login,))
    if other and other["id"] != me["user_id"]:
        raise AccountError("такой логин уже есть")
    db.x("UPDATE users SET login=?, name=? WHERE id=?", (login, (name or "").strip()[:64], me["user_id"]))
