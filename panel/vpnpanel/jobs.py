"""Background jobs (server bootstrap, protocol install/remove): one thread each, log lines stored as they arrive."""
import json
import logging
import threading
import time

log = logging.getLogger("vpnpanel.jobs")
_lock = threading.Lock()


class Busy(Exception):
    pass


def running(db, server):
    return db.one("SELECT id FROM jobs WHERE server=? AND status='running'", (server,))


def start(db, server, action, fn, user_id=None):
    """fn(log_line) -> result dict. Raises Busy if this server already has a running job. Returns the job id."""
    with _lock:
        if server and running(db, server):
            raise Busy("на этом сервере уже идёт задача")
        jid = db.x("INSERT INTO jobs(server, action, status, started, user_id) VALUES(?,?, 'running', ?, ?)",
                   (server, action, int(time.time()), user_id))

    def line(text):
        stamp = time.strftime("%H:%M:%S")
        db.x("UPDATE jobs SET log = log || ? WHERE id=?", (f"{stamp}  {text}\n", jid))

    def work():
        try:
            result = fn(line) or {}
            db.x("UPDATE jobs SET status='ok', result=?, finished=? WHERE id=?",
                 (json.dumps(result, ensure_ascii=False), int(time.time()), jid))
            line("готово")
        except Exception as e:  # the job must end with a status whatever happens
            log.exception("job %s failed", jid)
            line(f"ошибка: {e}")
            db.x("UPDATE jobs SET status='failed', finished=? WHERE id=?", (int(time.time()), jid))

    threading.Thread(target=work, name=f"job-{jid}", daemon=True).start()
    return jid


def reap(db):
    """Jobs still 'running' after a restart of the panel can never finish: mark them failed."""
    db.x("UPDATE jobs SET status='failed', finished=?, log = log || 'панель перезапускалась во время задачи\n' "
         "WHERE status='running' AND started < ?", (int(time.time()), int(time.time()) - 5))
    db.x("DELETE FROM jobs WHERE finished IS NOT NULL AND finished < ?", (int(time.time()) - 30 * 86400,))
