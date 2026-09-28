"""Accounts: scrypt passwords, DB-backed sessions, CSRF, lockout per IP and per login, invite links."""
import base64
import hashlib
import hmac
import re
import secrets
import time

_N, _R, _P = 2**14, 8, 1
LOGIN_RE = re.compile(r"^[a-z0-9._-]{2,32}$")
MIN_PASSWORD = 10
_DUMMY = None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def check_password(stored: str, password: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(base64.b64decode(dk)))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except (ValueError, TypeError, AttributeError):
        return False


def password_problem(password):
    if len(password or "") < MIN_PASSWORD:
        return f"пароль короче {MIN_PASSWORD} символов"
    return None


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _run_blocked(ts, cfg, now):
    window, block, k = cfg["login_window_minutes"] * 60, cfg["login_block_minutes"] * 60, cfg["login_max_failures"]
    for i in range(len(ts) - k + 1):
        if ts[i + k - 1] - ts[i] <= window and now - ts[i + k - 1] < block:
            return True
    return False


def blocked(cfg, db, ip, login=None):
    """True while the IP (or the login) has >= max failures inside the window and the block is on."""
    now = int(time.time())
    since = now - (cfg["login_window_minutes"] + cfg["login_block_minutes"]) * 60
    by_ip = [r["ts"] for r in db.q("SELECT ts FROM logins WHERE ip=? AND ok=0 AND ts>? ORDER BY ts", (ip, since))]
    if _run_blocked(by_ip, cfg, now):
        return True
    if login:
        by_login = [r["ts"] for r in db.q("SELECT ts FROM logins WHERE login=? AND ok=0 AND ts>? ORDER BY ts",
                                          (login.lower(), since))]
        return _run_blocked(by_login, cfg, now)
    return False


def _new_session(cfg, db, user_id, ip):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    db.x("INSERT INTO sessions(token_hash, csrf, expires, ip, user_id) VALUES(?,?,?,?,?)",
         (_h(token), csrf, int(time.time()) + cfg["session_hours"] * 3600, ip, user_id))
    db.x("UPDATE users SET last_login=? WHERE id=?", (int(time.time()), user_id))
    return token


def login(cfg, db, ip, login_name, password):
    """-> session token, "blocked" or None."""
    global _DUMMY
    login_name = (login_name or "").strip().lower()
    if blocked(cfg, db, ip, login_name):
        return "blocked"
    u = db.one("SELECT * FROM users WHERE login=? AND disabled=0", (login_name,)) if login_name else None
    if u and u["pw_hash"]:
        ok = check_password(u["pw_hash"], password or "")
    else:
        _DUMMY = _DUMMY or hash_password(secrets.token_hex(8))
        check_password(_DUMMY, password or "")  # same cost as a real check: no login enumeration by timing
        ok = False
    db.x("INSERT INTO logins(ts, ip, ok, login) VALUES(?,?,?,?)", (int(time.time()), ip, 1 if ok else 0, login_name))
    return _new_session(cfg, db, u["id"], ip) if ok else None


def session(db, token):
    """-> dict with session and user fields, or None."""
    if not token:
        return None
    s = db.one("""SELECT s.token_hash, s.csrf, s.expires, s.ip AS session_ip, u.id AS user_id, u.login, u.name, u.role,
                         u.servers
                  FROM sessions s JOIN users u ON u.id = s.user_id
                  WHERE s.token_hash=? AND u.disabled=0""", (_h(token),))
    if not s or s["expires"] < time.time():
        return None
    s["pending_requests"] = db.one("SELECT COUNT(*) n FROM tg_requests WHERE status='pending'")["n"]
    return s


def logout(db, token):
    if token:
        db.x("DELETE FROM sessions WHERE token_hash=?", (_h(token),))


def logout_others(db, user_id, keep_token=None):
    if keep_token:
        db.x("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (user_id, _h(keep_token)))
    else:
        db.x("DELETE FROM sessions WHERE user_id=?", (user_id,))


def set_password(db, user_id, password, keep_token=None):
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    db.x("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(password), user_id))
    logout_others(db, user_id, keep_token)


def csrf_ok(sess, value):
    return bool(sess) and bool(value) and hmac.compare_digest(sess["csrf"], value)


# ---------- invites: a colleague sets their own password; nobody sends passwords around ----------

def create_invite(db, user_id, hours=48):
    now = int(time.time())
    db.x("UPDATE invites SET used_at=? WHERE user_id=? AND used_at IS NULL", (now, user_id))  # older links die
    token = secrets.token_urlsafe(32)
    db.x("INSERT INTO invites(user_id, token_hash, created, expires) VALUES(?,?,?,?)",
         (user_id, _h(token), now, now + hours * 3600))
    return token


def invite_user(db, token):
    if not token or len(token) > 100:
        return None
    return db.one("""SELECT u.*, i.id AS invite_id FROM invites i JOIN users u ON u.id=i.user_id
                     WHERE i.token_hash=? AND i.used_at IS NULL AND i.expires>? AND u.disabled=0""",
                  (_h(token), int(time.time())))


def use_invite(cfg, db, token, password, ip):
    """Set the password from an invite; returns a fresh session token for that user."""
    u = invite_user(db, token)
    if not u:
        raise ValueError("ссылка недействительна: истекла, уже использована или отозвана")
    set_password(db, u["id"], password)
    db.x("UPDATE invites SET used_at=? WHERE id=?", (int(time.time()), u["invite_id"]))
    return u, _new_session(cfg, db, u["id"], ip)
