"""Admin authentication: single password (scrypt), DB-backed sessions, CSRF, per-IP lockout."""
import base64
import hashlib
import hmac
import secrets
import time

_N, _R, _P = 2**14, 8, 1


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
    except (ValueError, TypeError):
        return False


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def blocked(cfg, db, ip):
    """True while the IP has >= max failures inside the window and the block has not expired."""
    now = int(time.time())
    window = cfg["login_window_minutes"] * 60
    block = cfg["login_block_minutes"] * 60
    fails = db.q("SELECT ts FROM logins WHERE ip=? AND ok=0 AND ts>? ORDER BY ts", (ip, now - window - block))
    # sliding check: find a run of max failures within `window`, and see if its end is < block ago
    ts = [f["ts"] for f in fails]
    k = cfg["login_max_failures"]
    for i in range(len(ts) - k + 1):
        if ts[i + k - 1] - ts[i] <= window and now - ts[i + k - 1] < block:
            return True
    return False


def login(cfg, db, ip, password):
    """-> (session_token, csrf) or None."""
    if blocked(cfg, db, ip):
        return "blocked"
    stored = db.get("admin_password")
    ok = bool(stored) and check_password(stored, password or "")
    db.x("INSERT INTO logins(ts, ip, ok) VALUES(?,?,?)", (int(time.time()), ip, 1 if ok else 0))
    if not ok:
        return None
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    db.x("INSERT INTO sessions(token_hash, csrf, expires, ip) VALUES(?,?,?,?)",
         (_h(token), csrf, int(time.time()) + cfg["session_hours"] * 3600, ip))
    return token, csrf


def session(db, token):
    if not token:
        return None
    s = db.one("SELECT * FROM sessions WHERE token_hash=?", (_h(token),))
    if not s or s["expires"] < time.time():
        return None
    return s


def logout(db, token):
    if token:
        db.x("DELETE FROM sessions WHERE token_hash=?", (_h(token),))


def csrf_ok(sess, value):
    return bool(sess) and bool(value) and hmac.compare_digest(sess["csrf"], value)
