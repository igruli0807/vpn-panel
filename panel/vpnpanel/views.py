"""HTML rendering. Plain f-strings; every dynamic value goes through e()."""
import base64
import html
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from .service import CAN_ADD, KIND_TITLE


def e(v):
    return html.escape("" if v is None else str(v), quote=True)


class Fmt:
    def __init__(self, tz):
        self.tz = ZoneInfo(tz)

    def dt(self, ts):
        if not ts:
            return "—"
        return datetime.fromtimestamp(ts, self.tz).strftime("%d.%m.%Y %H:%M")

    @staticmethod
    def ago(ts, now=None):
        if not ts:
            return "никогда"
        d = int((now or time.time()) - ts)
        if d < 60:
            return "только что"
        if d < 3600:
            return f"{d // 60} мин назад"
        if d < 86400:
            return f"{d // 3600} ч назад"
        return f"{d // 86400} дн назад"

    @staticmethod
    def size(n):
        n = float(n or 0)
        for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
            if n < 1024 or unit == "ТБ":
                return f"{n:.0f} {unit}" if unit in ("Б", "КБ") else f"{n:.1f} {unit}"
            n /= 1024


def layout(title, body, sess=None, active=""):
    nav = ""
    if sess:
        items = [("/", "Клиенты", "clients"), ("/new", "Добавить", "new"), ("/log", "Журнал", "log")]
        links = "".join(f'<a href="{h}" class="{"on" if a == active else ""}">{t}</a>' for h, t, a in items)
        nav = (f'<nav>{links}<form method="post" action="/logout" class="inline">'
               f'<input type="hidden" name="csrf" value="{e(sess["csrf"])}">'
               f'<button class="link">Выйти</button></form></nav>')
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} — VPN</title><link rel="stylesheet" href="/static/app.css"></head>
<body><header><a class="brand" href="/">VPN-панель</a>{nav}</header>
<main>{body}</main><script src="/static/app.js"></script></body></html>"""


def csrf_field(sess):
    return f'<input type="hidden" name="csrf" value="{e(sess["csrf"])}">'


def login_page(error=""):
    err = f'<p class="err">{e(error)}</p>' if error else ""
    return layout("Вход", f"""<section class="card narrow"><h1>Вход</h1>{err}
<form method="post" action="/login"><label>Пароль<input type="password" name="password" autofocus
autocomplete="current-password" required></label><button>Войти</button></form></section>""")


def banners(server_health, health, servers):
    out = []
    titles = {s["id"]: s.get("title", s["id"]) for s in servers}
    for sh in server_health:
        if not sh["ok"]:
            out.append(f'<div class="banner bad">Сервер {e(titles.get(sh["server"], sh["server"]))} не отвечает: '
                       f'{e(sh["error"])}</div>')
    for h in health:
        if not h["up"]:
            out.append(f'<div class="banner bad">{e(titles.get(h["server"], h["server"]))} / {e(h["container"])}: '
                       f'интерфейс VPN не поднят — клиенты не подключатся</div>')
    return "".join(out)


def dashboard(sess, fmt, servers, health, server_health, clients, filters, now):
    titles = {s["id"]: s.get("title", s["id"]) for s in servers}
    cards = []
    for h in health:
        state = "ok" if h["up"] else "bad"
        cards.append(f"""<a class="stat {state}" href="/?server={e(h['server'])}&amp;container={e(h['container'])}">
<b>{e(titles.get(h['server'], h['server']))}</b><span>{e(KIND_TITLE.get(h['kind'], h['kind']))} · UDP {e(h['port'])}</span>
<span class="big">{h['online']}<small> / {h['peers']} в сети</small></span></a>""")
    sopt = '<option value="">все серверы</option>' + "".join(
        f'<option value="{e(s["id"])}" {"selected" if filters["server"] == s["id"] else ""}>{e(s.get("title", s["id"]))}</option>'
        for s in servers)
    stopt = "".join(f'<option value="{v}" {"selected" if filters["status"] == v else ""}>{t}</option>'
                    for v, t in (("", "все"), ("online", "в сети"), ("offline", "не в сети"),
                                 ("disabled", "отключены"), ("migrated", "переехали"), ("deleted", "удалённые")))
    rows = []
    for c in clients:
        online = c["hs"] and now - c["hs"] < 180
        dot = "off" if c["disabled"] else ("on" if online else "idle")
        tags = []
        if c["disabled"]:
            tags.append('<span class="tag">отключён</span>')
        if c["migrated_to"]:
            tags.append('<span class="tag">переехал</span>')
        if c["deleted"]:
            tags.append('<span class="tag">удалён</span>')
        if c["protected"]:
            tags.append('<span class="tag svc">служебный</span>')
        rows.append(f"""<tr><td><i class="dot {dot}"></i></td>
<td><a href="/client/{c['id']}">{e(c['name'] or '(без имени)')}</a> {''.join(tags)}</td>
<td>{e(titles.get(c['server'], c['server']))}<br><small>{e(KIND_TITLE.get(c['kind'], c['container']))}</small></td>
<td><code>{e(c['ip'])}</code></td>
<td title="{e(fmt.dt(c['hs']))}">{e(fmt.ago(c['hs'], now))}<br><small>{e(c['endpoint'] or '')}</small></td>
<td class="num">{e(fmt.size(c['d1']))}</td><td class="num">{e(fmt.size(c['d30']))}</td></tr>""")
    table = ("".join(rows) if rows else '<tr><td colspan="7" class="muted">Нет клиентов под этот фильтр</td></tr>')
    body = f"""{banners(server_health, health, servers)}
<section class="stats">{''.join(cards)}</section>
<section class="card"><div class="row between"><h1>Клиенты <small>{len(clients)}</small></h1>
<a class="btn" href="/new">+ Добавить клиента</a></div>
<form class="filters" method="get" action="/">
<select name="server">{sopt}</select>
<input type="hidden" name="container" value="{e(filters['container'])}">
<select name="status">{stopt}</select>
<input type="search" name="q" value="{e(filters['q'])}" placeholder="имя или IP">
<button>Показать</button>{'<a href="/">сбросить</a>' if any(filters.values()) else ''}</form>
<div class="scroll"><table><thead><tr><th></th><th>Имя</th><th>Сервер</th><th>IP в VPN</th>
<th>Последнее подключение</th><th class="num">24 ч</th><th class="num">30 дн</th></tr></thead>
<tbody>{table}</tbody></table></div>
<p class="muted small">Трафик считается с момента запуска панели. «В сети» — рукопожатие за последние 3 минуты.</p>
</section>"""
    return layout("Клиенты", body, sess, "clients")


def new_page(sess, servers, health, error=""):
    titles = {s["id"]: s.get("title", s["id"]) for s in servers}
    opts = []
    for h in sorted(health, key=lambda h: (h["kind"] != "awg3", h["server"])):
        if h["kind"] in CAN_ADD:
            opts.append(f'<option value="{e(h["server"])}|{e(h["container"])}">'
                        f'{e(titles.get(h["server"], h["server"]))} — {e(KIND_TITLE[h["kind"]])} (UDP {e(h["port"])})</option>')
    err = f'<p class="err">{e(error)}</p>' if error else ""
    body = f"""<section class="card narrow"><h1>Новый клиент</h1>{err}
<form method="post" action="/new">{csrf_field(sess)}
<label>Имя<input name="name" maxlength="64" required placeholder="Например: Иван, телефон"></label>
<label>Сервер и протокол<select name="target">{''.join(opts)}</select></label>
<p class="muted small">AWG 3.1 — для приложений Amnezia VPN 5.0.1.5+ и AmneziaWG 3.1.
AWG 2.0 — для тех, у кого приложение старое.</p>
<button>Создать</button></form></section>"""
    return layout("Новый клиент", body, sess, "new")


def chart(points, fmt):
    """points: list of (hour_ts, rx, tx) for the last 7 days -> inline SVG bars (rx+tx per 6 h)."""
    if not points:
        return '<p class="muted">Трафика за неделю нет.</p>'
    buckets = {}
    for h, rx, tx in points:
        b = h - h % (6 * 3600)
        buckets[b] = buckets.get(b, 0) + rx + tx
    now = int(time.time())
    start = now - now % (6 * 3600) - 27 * 6 * 3600
    vals = [buckets.get(start + i * 6 * 3600, 0) for i in range(28)]
    top = max(vals) or 1
    w, hgt, bw = 560, 120, 20
    bars = "".join(
        f'<rect x="{i * bw}" y="{hgt - int(v / top * (hgt - 4))}" width="{bw - 3}" height="{int(v / top * (hgt - 4))}">'
        f'<title>{e(fmt.dt(start + i * 6 * 3600))}: {e(fmt.size(v))}</title></rect>'
        for i, v in enumerate(vals))
    return (f'<svg class="chart" viewBox="0 0 {w} {hgt}" role="img" aria-label="Трафик за 7 дней">{bars}</svg>'
            f'<p class="muted small">Трафик за 7 дней, столбец = 6 часов, максимум {e(fmt.size(top))}.</p>')


def client_page(sess, fmt, c, server, conf, kind, qr, shares, points, targets, protected, error="", new_link=""):
    title = c["name"] or "(без имени)"
    err = f'<p class="err">{e(error)}</p>' if error else ""
    link = ""
    if new_link:
        link = f"""<div class="banner ok">Ссылка создана — отправьте её клиенту. Показана один раз:
<div class="copyrow"><input readonly value="{e(new_link)}" id="newlink"><button type="button" data-copy="newlink">Копировать</button></div></div>"""
    now = int(time.time())
    status = ("отключён" if c["disabled"] else "в сети" if c["hs"] and now - c["hs"] < 180 else "не в сети")
    if c["deleted"]:
        status = "удалён"
    facts = f"""<dl class="facts"><dt>Сервер</dt><dd>{e(server.get('title', server['id']))} — {e(KIND_TITLE.get(kind or '', c['container']))}</dd>
<dt>IP в VPN</dt><dd><code>{e(c['ip'])}</code></dd><dt>Статус</dt><dd>{e(status)}</dd>
<dt>Последнее подключение</dt><dd>{e(fmt.dt(c['hs']))} ({e(fmt.ago(c['hs'], now))})</dd>
<dt>Откуда</dt><dd>{e(c['endpoint'] or '—')}</dd>
<dt>Трафик</dt><dd>24 ч: {e(fmt.size(c['d1']))} · 30 дн: {e(fmt.size(c['d30']))} · всего: {e(fmt.size(c['dall']))}</dd>
<dt>Создан</dt><dd>{e(fmt.dt(c['created']))} ({'в панели' if c['source'] == 'panel' else 'в приложении Amnezia'})</dd></dl>"""
    conf_block = ""
    if conf:
        b64 = base64.b64encode(conf.encode()).decode()
        fname = e(_fname(c["name"]))
        conf_block = f"""<section class="card"><h2>Конфиг</h2><div class="qrwrap">{qr}</div>
<p class="muted small">Отсканируйте QR в приложении ({e(_app(kind))}).</p>
<div class="row"><a class="btn" download="{fname}.conf" href="data:text/plain;base64,{b64}">Скачать .conf</a>
<button type="button" class="btn ghost" data-copy="conf">Копировать текст</button></div>
<textarea id="conf" readonly rows="6" class="hidden-ta">{e(conf)}</textarea></section>"""
    share_rows = "".join(
        f"""<tr><td>{e(fmt.dt(s['created']))}</td><td>{e(fmt.dt(s['expires']))}</td>
<td>{'одноразовая' if s['one_time'] else 'многоразовая'}</td>
<td>{'отозвана' if s['revoked'] else 'истекла' if s['expires'] < now else ('использована ' + fmt.dt(s['used_at'])) if s['used_at'] else 'не открывалась'}</td>
<td>{'' if s['revoked'] or s['expires'] < now else f'<form method="post" action="/share/{s["id"]}/revoke" class="inline">{csrf_field(sess)}<input type="hidden" name="client" value="{c["id"]}"><button class="link">отозвать</button></form>'}</td></tr>"""
        for s in shares)
    share_block = ""
    if conf and not c["deleted"]:
        share_block = f"""<section class="card"><h2>Ссылка для клиента</h2>
<form method="post" action="/client/{c['id']}/share" class="row">{csrf_field(sess)}
<select name="hours"><option value="24">на 24 часа</option><option value="72" selected>на 3 дня</option>
<option value="168">на неделю</option></select>
<label class="check"><input type="checkbox" name="one_time" value="1" checked> одноразовая</label>
<button>Создать ссылку</button></form>
<p class="muted small">Сертификат самоподписанный: при первом открытии браузер предупредит — нужно нажать «Дополнительно → Перейти».</p>
{'<div class="scroll"><table><thead><tr><th>Создана</th><th>До</th><th>Тип</th><th>Состояние</th><th></th></tr></thead><tbody>' + share_rows + '</tbody></table></div>' if shares else ''}
</section>"""
    actions = []
    if not c["deleted"] and not protected:
        actions.append(f"""<form method="post" action="/client/{c['id']}/rename" class="row">{csrf_field(sess)}
<input name="name" value="{e(c['name'])}" maxlength="64"><button class="ghost">Переименовать</button></form>""")
        tgl = "enable" if c["disabled"] else "disable"
        actions.append(f"""<form method="post" action="/client/{c['id']}/{tgl}" class="inline">{csrf_field(sess)}
<button class="ghost">{'Включить' if c['disabled'] else 'Отключить'}</button></form>""")
        if targets and kind != "awg3" and not c["migrated_to"]:
            topt = "".join(f'<option value="{e(t["server"])}|{e(t["container"])}">{e(t["title"])}</option>' for t in targets)
            actions.append(f"""<form method="post" action="/client/{c['id']}/migrate" class="row">{csrf_field(sess)}
<select name="target">{topt}</select><button>Перевести на AWG 3.1</button></form>""")
        actions.append(f"""<form method="post" action="/client/{c['id']}/delete" class="inline" data-confirm="Удалить клиента «{e(title)}»? Его VPN перестанет работать.">
{csrf_field(sess)}<button class="danger">Удалить</button></form>""")
    elif protected:
        actions.append('<p class="muted">Служебный пир (туннель администратора) — изменения из панели запрещены.</p>')
    migrated = f'<p>Переехал: <a href="/client/{c["migrated_to"]}">новый клиент</a></p>' if c["migrated_to"] else ""
    body = f"""<p><a href="/">← все клиенты</a></p>{err}{link}
<section class="card"><h1>{e(title)}</h1>{migrated}{facts}{chart(points, fmt)}
<div class="actions">{''.join(actions)}</div></section>{conf_block}{share_block}"""
    return layout(title, body, sess)


def share_page(c, conf, kind, qr):
    b64 = base64.b64encode(conf.encode()).decode()
    body = f"""<section class="card narrow"><h1>Ваш VPN</h1>
<p>Подключение для: <b>{e(c['name'])}</b></p>
<ol class="steps"><li>Установите приложение: {e(_app(kind))}.</li>
<li>В приложении нажмите «+» и выберите «QR-код» (с другого устройства) или «Файл».</li>
<li>Включите подключение.</li></ol>
<div class="qrwrap">{qr}</div>
<div class="row"><a class="btn" download="{e(_fname(c['name']))}.conf" href="data:text/plain;base64,{b64}">Скачать файл конфигурации</a>
<button type="button" class="btn ghost" data-copy="conf">Копировать текст</button></div>
<textarea id="conf" readonly rows="6" class="hidden-ta">{e(conf)}</textarea>
<p class="muted small">Это ваш личный ключ — не пересылайте его другим. Ссылка может быть одноразовой: сохраните файл сейчас.</p>
</section>"""
    return layout("Ваш VPN", body)


def not_found(msg="Ссылка недействительна: истекла, уже использована или отозвана."):
    return layout("Не найдено", f'<section class="card narrow"><h1>Не найдено</h1><p>{e(msg)}</p></section>')


def log_page(sess, fmt, events):
    rows = "".join(f"<tr><td>{e(fmt.dt(x['ts']))}</td><td>{e(x['ip'] or '')}</td><td>{e(x['text'])}</td></tr>"
                   for x in events)
    body = f"""<section class="card"><h1>Журнал</h1><div class="scroll"><table><thead><tr><th>Когда</th><th>IP</th>
<th>Что</th></tr></thead><tbody>{rows or '<tr><td colspan="3" class="muted">Пусто</td></tr>'}</tbody></table></div></section>"""
    return layout("Журнал", body, sess, "log")


def _app(kind):
    from .clientconf import APPS
    return APPS.get(kind or "", "Amnezia VPN или AmneziaWG")


def _fname(name):
    keep = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (name or "vpn"))
    return (keep.strip("_") or "vpn")[:40]
