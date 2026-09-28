"""HTML rendering (design canvas of 28.09.2026). Plain f-strings; every dynamic value goes through e()."""
import base64
import html
import json
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from .service import CAN_ADD, KIND_TITLE


def e(v):
    return html.escape("" if v is None else str(v), quote=True)


class Fmt:
    def __init__(self, tz):
        self.tz = ZoneInfo(tz)

    def dt(self, ts, short=False):
        if not ts:
            return "—"
        return datetime.fromtimestamp(ts, self.tz).strftime("%d.%m %H:%M" if short else "%d.%m.%Y %H:%M")

    def day(self, ts):
        return datetime.fromtimestamp(ts, self.tz).strftime("%d.%m")

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


# ---------- icons (inline stroke SVG, text-coloured) ----------

def _svg(size, sw, body, extra=""):
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="{sw}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"{extra}>{body}</svg>')


I_SHIELD = _svg(22, 2, '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"></path><path d="M9 12l2 2 4-4"></path>')
I_WARN = _svg(18, 2.2, '<path d="M12 3l10 18H2z"></path><path d="M12 10v5M12 18v.5"></path>')
I_OK = _svg(18, 2.4, '<path d="M5 12l5 5 9-10"></path>')
I_INFO = _svg(14, 2, '<circle cx="12" cy="12" r="9"></circle><path d="M12 8v5M12 16v.5"></path>')
I_LOCK = _svg(18, 2.2, '<rect x="5" y="11" width="14" height="10" rx="2"></rect><path d="M8 11V8a4 4 0 0 1 8 0v3"></path>')
I_MENU = _svg(20, 2, '<path d="M4 7h16M4 12h16M4 17h16"></path>')
I_USER = _svg(16, 2, '<circle cx="12" cy="8" r="4"></circle><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"></path>')
I_LINKOFF = _svg(40, 1.8, '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"></path>'
                          '<path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"></path><path d="M4 4l16 16"></path>')

BADGE = {"awg3": "b-awg3", "awg2": "b-awg2", "legacy": "b-legacy", "wireguard": "b-wg", "sstp": "b-sstp", "vless": "b-vless"}
KIND_TITLE_ALL = dict(KIND_TITLE, sstp="SSTP", vless="VLESS")


def badge(kind):
    return f'<span class="badge {BADGE.get(kind or "", "b-legacy")}">{e(KIND_TITLE_ALL.get(kind or "", kind or "?"))}</span>'


def alert(text, sub="", ok=False, solid=False, icon=None):
    cls = "alert ok" if ok else ("alert solid" if solid else "alert")
    icon = icon or (I_OK if ok else I_WARN)
    sub_html = f' <span class="sub">{e(sub)}</span>' if sub else ""
    role = "status" if ok else "alert"
    return f'<div class="{cls}" role="{role}">{icon}<div>{e(text)}{sub_html}</div></div>'


def csrf_field(me):
    return f'<input type="hidden" name="csrf" value="{e(me["csrf"])}">'


# ---------- page shells ----------

def layout(title, body, me=None, active="", page_cls="page"):
    nav = ""
    if me:
        items = [("/", "Клиенты", "clients"), ("/new", "Добавить", "new"), ("/log", "Журнал", "log")]
        if me["role"] == "owner":
            items.append(("/users", "Учётки", "users"))
        links = "".join(f'<a class="lnk{" on" if a == active else ""}" href="{h}">{t}</a>' for h, t, a in items)
        mlinks = "".join(f'<a class="{"on" if a == active else ""}" href="{h}">{t}</a>' for h, t, a in items)
        who = e(me["name"] or me["login"])
        logout = (f'<form method="post" action="/logout">{csrf_field(me)}'
                  f'<button class="btn txt out" type="submit">Выйти</button></form>')
        nav = f"""<nav class="nav" aria-label="Основное меню">
<a class="brand" href="/">{I_SHIELD}VPN-панель</a>{links}<span class="sp"></span>
<a class="who{' on' if active == 'me' else ''}" href="/me" title="Профиль и пароль">{I_USER}{who}</a>{logout}
<details class="mnav"><summary class="iconbtn" aria-label="Меню">{I_MENU}</summary>
<div class="menu">{mlinks}<a class="{'on' if active == 'me' else ''}" href="/me">Профиль · {who}</a>
<form method="post" action="/logout">{csrf_field(me)}<button type="submit">Выйти</button></form></div></details>
</nav>"""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)} — VPN-панель</title><link rel="stylesheet" href="/static/app.css"></head>
<body class="app">{nav}<main class="{page_cls}">{body}</main><script src="/static/app.js"></script></body></html>"""


def bare(title, body):
    """Pages without navigation: login, invite, public share."""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><link rel="stylesheet" href="/static/app.css"></head>
<body class="app">{body}<script src="/static/app.js"></script></body></html>"""


# ---------- login / invite ----------

def login_page(error="", locked=False, login=""):
    msg = ""
    if locked:
        msg = alert("Слишком много неудачных попыток. Попробуйте через час.", solid=True, icon=I_LOCK)
    elif error:
        msg = f'<p class="lb danger" role="alert">{e(error)}</p>'
    return bare("Вход — VPN-панель", f"""<div class="center-screen">
<form class="panel login" method="post" action="/login">
<div class="brand">{I_SHIELD}VPN-панель</div>{msg}
<div class="field"><label class="lb" for="lg">Логин</label>
<input id="lg" name="login" class="in lg" autocomplete="username" autocapitalize="none" value="{e(login)}" required></div>
<div class="field"><label class="lb" for="pw">Пароль</label>
<input id="pw" name="password" class="in lg" type="password" autocomplete="current-password" required></div>
<button class="btn pri lg" type="submit">Войти</button>
</form></div>""")


def invite_page(u, error=""):
    err = alert(error) if error else ""
    return bare("Пароль — VPN-панель", f"""<div class="center-screen">
<form class="panel login" method="post">
<div class="brand">{I_SHIELD}VPN-панель</div>
<div><h2>Задайте пароль</h2><p class="hint">Учётка <b>{e(u['login'])}</b>{(' · ' + e(u['name'])) if u['name'] else ''}.
Не короче 10 символов.</p></div>{err}
<input type="text" name="username" value="{e(u['login'])}" autocomplete="username" class="hidden-ta" tabindex="-1" aria-hidden="true">
<div class="field"><label class="lb" for="p1">Новый пароль</label>
<input id="p1" name="password" class="in lg" type="password" autocomplete="new-password" minlength="10" required></div>
<div class="field"><label class="lb" for="p2">Ещё раз</label>
<input id="p2" name="password2" class="in lg" type="password" autocomplete="new-password" minlength="10" required></div>
<button class="btn pri lg" type="submit">Сохранить и войти</button>
</form></div>""")


# ---------- dashboard ----------

def _row_state(c, now):
    if c["deleted"]:
        return "dot off", "удалён"
    if c["disabled"]:
        return "dot dis", "отключён"
    if c["hs"] and now - c["hs"] < 180:
        return "dot on", "в сети"
    return "dot off", "не в сети"


def _tags(c):
    t = []
    if c["disabled"] and not c["deleted"]:
        t.append('<span class="tag red">отключён</span>')
    if c["migrated_to"]:
        t.append('<span class="tag">переехал</span>')
    if c["deleted"]:
        t.append('<span class="tag">удалён</span>')
    if c["protected"]:
        t.append('<span class="tag svc">служебный</span>')
    return f'<span class="tags">{"".join(t)}</span>' if t else ""


def dashboard(me, fmt, servers, health, server_health, clients, filters, now):
    titles = {s["id"]: s.get("title", s["id"]) for s in servers}
    down = {sh["server"]: sh for sh in server_health if not sh["ok"]}
    alerts = []
    for sid, sh in down.items():
        alerts.append(alert(f"Сервер {titles.get(sid, sid)} не отвечает: {sh['error'] or 'нет ответа'}",
                            f"Последняя проверка — {fmt.dt(sh['checked'], short=True)}. Данные по нему могут быть устаревшими."))
    for h in health:
        if not h["up"] and h["server"] not in down:
            alerts.append(alert(f"{titles.get(h['server'], h['server'])} / {h['container']}: интерфейс VPN не поднят — клиенты не подключатся",
                                "Контейнер запущен, но VPN-интерфейса в нём нет. Сторож попробует поднять его сам в течение минуты."))
    cards = []
    for h in health:
        cls, state, on = "ct", "работает", str(h["online"])
        if h["server"] in down:
            cls, state, on = "ct na", "нет связи", "—"
        elif not h["up"]:
            cls, state, on = "ct bad", "интерфейс не поднят", "0"
        if filters["container"] == h["container"] and filters["server"] == h["server"]:
            cls += " sel"
        cards.append(f"""<a class="{cls}" href="/?server={e(h['server'])}&amp;container={e(h['container'])}">
<div class="top"><span class="small muted">{e(titles.get(h['server'], h['server']))}</span>{badge(h['kind'])}</div>
<div class="big">{on} <small>в сети из {h['peers']}</small></div>
<div class="top"><span class="mono muted">UDP {e(h['port'])}</span><span class="st">{state}</span></div></a>""")
    sopt = '<option value="">Все серверы</option>' + "".join(
        f'<option value="{e(s["id"])}"{" selected" if filters["server"] == s["id"] else ""}>{e(s.get("title", s["id"]))}</option>'
        for s in servers)
    stopt = "".join(f'<option value="{v}"{" selected" if filters["status"] == v else ""}>{t}</option>'
                    for v, t in (("", "Все статусы"), ("online", "В сети"), ("offline", "Не в сети"),
                                 ("disabled", "Отключены"), ("migrated", "Переехали"), ("deleted", "Удалённые")))
    rows, mrows = [], []
    for c in clients:
        dot, st = _row_state(c, now)
        dim = " class=\"dim\"" if (c["disabled"] or c["migrated_to"] or c["deleted"]) else ""
        name = e(c["name"] or "(без имени)")
        rows.append(f"""<tr{dim}><td class="st"><span class="{dot}" title="{st}"></span><span class="sr">{st}</span></td>
<td><a href="/client/{c['id']}">{name}</a>{_tags(c)}</td>
<td>{e(titles.get(c['server'], c['server']))}<span class="sub">{e(KIND_TITLE_ALL.get(c['kind'] or '', c['container']))}</span></td>
<td class="mono">{e(c['ip'])}</td>
<td><span title="{e(fmt.dt(c['hs']))}">{e(fmt.ago(c['hs'], now))}</span><span class="sub mono">{e(c['endpoint'] or '—')}</span></td>
<td class="r">{e(fmt.size(c['d1']))}</td><td class="r">{e(fmt.size(c['d30']))}</td></tr>""")
        mrows.append(f"""<a class="mrow" href="/client/{c['id']}"><span class="{dot}" title="{st}"></span>
<div class="grow"><div><span class="nm">{name}</span>{_tags(c)}</div>
<div class="meta"><span>{e(titles.get(c['server'], c['server']))} · {e(KIND_TITLE_ALL.get(c['kind'] or '', c['container']))}</span><span>{e(fmt.ago(c['hs'], now))}</span></div>
<div class="meta"><span class="mono">{e(c['ip'])}</span><span class="num">{e(fmt.size(c['d1']))} / 24 ч</span></div></div>
<span class="sr">{st}</span></a>""")
    empty = '<p class="empty">Нет клиентов под этот фильтр.</p>'
    table = (f"""<div class="scroll desk"><table class="t"><thead><tr><th><span class="sr">Статус</span></th><th>Имя</th><th>Сервер</th>
<th>IP в VPN</th><th>Последнее подключение</th><th class="r">24 ч</th><th class="r">30 дн</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div><div class="mlist">{''.join(mrows)}</div>""" if rows else empty)
    reset = '<a class="btn txt" href="/">сбросить</a>' if any(filters.values()) else ""
    body = f"""{('<div class="alerts">' + ''.join(alerts) + '</div>') if alerts else ''}
<section class="cards" aria-label="Контейнеры">{''.join(cards)}</section>
<section class="panel">
<div class="ph"><h2>Клиенты</h2><span class="count">{len(clients)}</span><span class="sp"></span>
<a class="btn pri" href="/new">+ Добавить клиента</a></div>
<form class="filters" method="get" action="/">
<select name="server" class="in" aria-label="Сервер">{sopt}</select>
<input type="hidden" name="container" value="{e(filters['container'])}">
<select name="status" class="in" aria-label="Статус">{stopt}</select>
<input type="search" name="q" class="in q" value="{e(filters['q'])}" placeholder="Имя или IP" aria-label="Поиск по имени или IP">
<button class="btn" type="submit">Найти</button>{reset}</form>
{table}
<p class="foot">Трафик считается с момента запуска панели. «В сети» — рукопожатие за последние 3 минуты.</p>
</section>"""
    return layout("Клиенты", body, me, "clients")


# ---------- new client ----------

def new_page(me, servers, health, error=""):
    titles = {s["id"]: s.get("title", s["id"]) for s in servers}
    opts = []
    for h in sorted(health, key=lambda h: (h["kind"] != "awg3", h["server"])):
        if h["kind"] in CAN_ADD and h["server"] in titles:
            opts.append(f'<option value="{e(h["server"])}|{e(h["container"])}">'
                        f'{e(titles[h["server"]])} — {e(KIND_TITLE[h["kind"]])} (UDP {e(h["port"])})</option>')
    err = alert("Не удалось создать клиента", error) if error else ""
    select = (f'<select name="target" class="in tall" aria-label="Сервер и протокол">{"".join(opts)}</select>' if opts else
              '<p class="hint">Нет доступных контейнеров для новых клиентов.</p>')
    body = f"""<form class="panel narrow" method="post" action="/new">{csrf_field(me)}
<div class="ph"><h2>Новый клиент</h2></div>
<div class="pb">{err}
<div class="field"><label class="lb" for="nm">Имя</label>
<input id="nm" name="name" class="in tall" maxlength="64" placeholder="Иван, телефон" required>
<span class="hint">До 64 символов. Видно только в панели.</span></div>
<fieldset class="field"><legend class="lb">Сервер и протокол</legend>{select}
<span class="hint">AWG 3.1 — для Amnezia VPN 5.0.1.5+ и AmneziaWG 3.1. AWG 2.0 — для тех, у кого приложение старое.</span></fieldset>
<button class="btn pri tall" type="submit"{'' if opts else ' disabled'}>Создать</button>
<span class="hint">После создания сразу откроется карточка с QR-кодом.</span>
</div></form>"""
    return layout("Новый клиент", body, me, "new", "page center")


# ---------- client card ----------

def chart(points, fmt):
    """7 days, 28 bars of 6 hours; SVG rects (no inline styles — CSP)."""
    now = int(time.time())
    step = 6 * 3600
    start = now - now % step - 27 * step
    buckets = [0] * 28
    for h, rx, tx in points:
        i = (h - start) // step
        if 0 <= i < 28:
            buckets[i] += rx + tx
    top = max(buckets) or 1
    bw, gap, hgt = 10, 3, 120
    bars = []
    for i, v in enumerate(buckets):
        bh = max(2, int(v / top * (hgt - 4))) if v else 2
        bars.append(f'<rect x="{i * (bw + gap)}" y="{hgt - bh}" width="{bw}" height="{bh}" rx="1">'
                    f'<title>{e(fmt.dt(start + i * step, short=True))}: {e(fmt.size(v))}</title></rect>')
    days = "".join(f"<span>{e(fmt.day(start + d * 4 * step))}</span>" for d in range(7))
    return (f'<svg class="chart" viewBox="0 0 {28 * (bw + gap) - gap} {hgt}" preserveAspectRatio="none" role="img" '
            f'aria-label="Трафик за 7 дней, 28 интервалов по 6 часов, максимум {e(fmt.size(top))}">{"".join(bars)}</svg>'
            f'<div class="axis">{days}</div>'), fmt.size(top) if any(buckets) else None


def client_page(me, fmt, c, server, conf, kind, qr, shares, points, targets, protected,
                error="", new_link="", notice=""):
    now = int(time.time())
    title = c["name"] or "(без имени)"
    dot, st = _row_state(c, now)
    top_alerts = ""
    if notice:
        top_alerts += alert(notice, ok=True)
    if error:
        top_alerts += alert(error)
    migrated = (f'<p>Переехал: <a href="/client/{c["migrated_to"]}">новый клиент</a></p>' if c["migrated_to"] else "")
    facts = f"""<section class="panel"><div class="ph"><h2>Сведения</h2></div><div class="pb"><dl class="dl">
<dt>Сервер и протокол</dt><dd>{e(server.get('title', server['id']))} · {e(KIND_TITLE_ALL.get(kind or '', c['container']))}</dd>
<dt>IP в VPN</dt><dd class="mono">{e(c['ip'])}</dd>
<dt>Статус</dt><dd class="row"><span class="{dot}"></span>{st}</dd>
<dt>Последнее подключение</dt><dd>{e(fmt.dt(c['hs']))} <span class="muted">· {e(fmt.ago(c['hs'], now))}</span></dd>
<dt>Откуда</dt><dd class="mono">{e(c['endpoint'] or '—')}</dd>
<dt>Трафик</dt><dd class="num">{e(fmt.size(c['d1']))} <span class="muted">24 ч</span> · {e(fmt.size(c['d30']))} <span class="muted">30 дн</span> · {e(fmt.size(c['dall']))} <span class="muted">всего</span></dd>
<dt>Создан</dt><dd>{e(fmt.dt(c['created']))} <span class="muted">· {'в панели' if c['source'] == 'panel' else 'в приложении Amnezia'}</span></dd>
</dl></div></section>"""
    svg, top = chart(points, fmt)
    traffic = f"""<section class="panel"><div class="ph"><h2>Трафик за 7 дней</h2><span class="sp"></span>
<span class="small muted">{('по 6 часов · максимум ' + e(top)) if top else 'трафика за неделю нет'}</span></div>
<div class="pb">{svg}</div></section>"""
    acts = []
    if protected:
        acts.append('<p class="muted">Служебный пир (туннель администратора) — изменения из панели запрещены.</p>')
    elif not c["deleted"]:
        acts.append(f"""<form class="field" method="post" action="/client/{c['id']}/rename">{csrf_field(me)}
<label class="lb" for="rn">Имя</label><div class="row"><input id="rn" name="name" class="in grow" value="{e(c['name'])}" maxlength="64">
<button class="btn" type="submit">Переименовать</button></div></form>""")
        tgl = "enable" if c["disabled"] else "disable"
        acts.append(f"""<div class="split"><div><div class="lb">Доступ</div><div class="hint">Отключённый клиент хранится, но не подключается.</div></div>
<form method="post" action="/client/{c['id']}/{tgl}">{csrf_field(me)}<button class="btn" type="submit">{'Включить' if c['disabled'] else 'Отключить'}</button></form></div>""")
        if targets and kind != "awg3" and not c["migrated_to"] and conf:
            acts.append(_migrate_form(me, c, targets))
        acts.append(f"""<div class="split top"><div><div class="lb danger">Удалить клиента</div><div class="hint">Его VPN перестанет работать сразу.</div></div>
<form method="post" action="/client/{c['id']}/delete" data-confirm="Удалить клиента «{e(title)}»? Его VPN перестанет работать.">
{csrf_field(me)}<button class="btn dng" type="submit">Удалить</button></form></div>""")
    actions = f'<section class="panel"><div class="ph"><h2>Действия</h2></div><div class="pb">{"".join(acts)}</div></section>' if acts else ""

    side = []
    if conf:
        b64 = base64.b64encode(conf.encode()).decode()
        fname = e(_fname(c["name"]))
        side.append(f"""<section class="panel"><div class="ph"><h2>Конфиг</h2></div><div class="pb qrwrap">
<div class="qr" role="img" aria-label="QR-код конфигурации">{qr}</div>
<p class="hint c">Сканируйте в {e(_app(kind))}: «+» → «QR-код».</p>
<div class="row wrap"><a class="btn pri" download="{fname}.conf" href="data:text/plain;base64,{b64}">Скачать .conf</a>
<button class="btn" type="button" data-copy="conf">Копировать текст</button></div>
<textarea id="conf" readonly class="hidden-ta" tabindex="-1" aria-hidden="true">{e(conf)}</textarea></div></section>""")
        side.append(_share_block(me, fmt, c, shares, new_link, now))
    elif not c["deleted"] and not protected:
        mig = _migrate_form(me, c, targets) if targets and not c["migrated_to"] else ""
        side.append(f"""<section class="panel"><div class="ph"><h2>Конфиг</h2></div><div class="pb">
<p class="muted">Клиент создан в приложении Amnezia — его ключа в панели нет. Выдайте ему новый конфиг через «Перевести на AWG 3.1».</p>{mig}</div></section>""")
    body = f"""<div class="head"><a class="btn txt back" href="/">← все клиенты</a>
<div class="row gap12 wrap"><h1>{e(title)}</h1>{badge(kind)}<span class="{dot}" title="{st}"></span><span class="muted">{st}</span></div>{migrated}</div>
{top_alerts}
<div class="grid2"><div class="col">{facts}{traffic}{actions}</div><div class="col side">{''.join(side)}</div></div>"""
    return layout(title, body, me, "clients")


def _migrate_form(me, c, targets):
    topt = "".join(f'<option value="{e(t["server"])}|{e(t["container"])}">{e(t["title"])}</option>' for t in targets)
    return f"""<form class="field" method="post" action="/client/{c['id']}/migrate">{csrf_field(me)}
<label class="lb" for="tg">Перевести на AWG 3.1</label>
<div class="row wrap"><select id="tg" name="target" class="in grow">{topt}</select><button class="btn pri" type="submit">Перевести</button></div>
<span class="hint">Создаст нового клиента с тем же именем и откроет его карточку. Старый получит метку «переехал».</span></form>"""


def _share_block(me, fmt, c, shares, new_link, now):
    if c["deleted"]:
        return ""
    box = ""
    if new_link:
        box = f"""<div class="linkbox"><div class="row between"><span class="lt">Ссылка создана</span><span class="small muted">показана один раз</span></div>
<div class="row"><input id="newlink" class="in mono grow" value="{e(new_link)}" readonly aria-label="Ссылка для клиента">
<button class="btn" type="button" data-copy="newlink">Копировать</button></div></div>"""
    rows = []
    for s in shares:
        if s["revoked"]:
            state = "отозвана"
        elif s["expires"] < now:
            state = "истекла"
        elif s["used_at"]:
            state = "использована " + fmt.dt(s["used_at"], short=True)
        else:
            state = "не открывалась"
        live = not s["revoked"] and s["expires"] >= now and not (s["one_time"] and s["used_at"])
        revoke = (f'<form method="post" action="/share/{s["id"]}/revoke">{csrf_field(me)}<input type="hidden" name="client" value="{c["id"]}">'
                  f'<button class="btn txt" type="submit">отозвать</button></form>' if live else "")
        rows.append(f"""<tr{'' if live else ' class="dim"'}><td class="num">{e(fmt.dt(s['created'], short=True))}</td>
<td class="num">{e(fmt.dt(s['expires'], short=True))}</td><td>{'1 раз' if s['one_time'] else 'много'}</td><td>{e(state)}</td><td class="r">{revoke}</td></tr>""")
    table = (f"""<div class="scroll"><table class="t dense small"><thead><tr><th>Создана</th><th>Действует до</th><th>Тип</th><th>Состояние</th><th></th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>""" if rows else "")
    return f"""<section class="panel"><div class="ph"><h2>Ссылка для клиента</h2></div><div class="pb">
<form class="row wrap gap12" method="post" action="/client/{c['id']}/share">{csrf_field(me)}
<div class="seg" role="radiogroup" aria-label="Срок">
<label><input type="radio" name="hours" value="24" checked>24 часа</label>
<label><input type="radio" name="hours" value="72">3 дня</label>
<label><input type="radio" name="hours" value="168">неделя</label></div>
<label class="chk"><input type="checkbox" name="one_time" value="1" checked>одноразовая</label>
<button class="btn pri" type="submit">Создать ссылку</button></form>
{box}
<p class="note">{I_INFO}Браузер клиента предупредит о сертификате — это ожидаемо: нужно нажать «Дополнительно» → «Перейти на сайт».</p>
{table}</div></section>"""


# ---------- public pages ----------

def share_page(c, conf, kind, qr):
    b64 = base64.b64encode(conf.encode()).decode()
    return bare("Ваш VPN", f"""<div class="pubwrap"><main class="pub">
<div class="head"><h1>Ваш VPN</h1><p class="muted">Подключение для: <strong>{e(c['name'])}</strong></p></div>
<ol class="steps">
<li><span class="n">1</span><div>Установите приложение <strong>{e(_app(kind))}</strong>.</div></li>
<li><span class="n">2</span><div>В приложении нажмите «+» и выберите «QR-код» или «Файл».</div></li>
<li><span class="n">3</span><div>Включите подключение.</div></li></ol>
<div class="soft"><div class="qr" role="img" aria-label="QR-код для подключения">{qr}</div>
<a class="btn pri xl full" download="{e(_fname(c['name']))}.conf" href="data:text/plain;base64,{b64}">Скачать файл конфигурации</a>
<button class="btn lg full" type="button" data-copy="conf">Копировать текст</button>
<textarea id="conf" readonly class="hidden-ta" tabindex="-1" aria-hidden="true">{e(conf)}</textarea></div>
<p class="small muted">Это ваш личный ключ — не пересылайте его. Ссылка может быть одноразовой: сохраните файл сейчас.</p>
</main></div>""")


def public_message(title, text):
    return bare(title, f"""<div class="pubwrap"><main class="pub"><div class="soft msg">
<span class="muted">{I_LINKOFF}</span><h1 class="sm">{e(title)}</h1><p class="muted">{e(text)}</p></div></main></div>""")


def link_invalid():
    return public_message("Ссылка недействительна",
                          "Она истекла, уже использована или отозвана. Попросите новую у того, кто её прислал.")


def server_down():
    return public_message("Сервер временно недоступен",
                          "Попробуйте открыть ссылку позже. Если не получится — напишите тому, кто её прислал.")


def not_found(msg="Нет такой страницы.", me=None):
    body = f'<section class="panel narrow"><div class="ph"><h2>Не найдено</h2></div><div class="pb"><p>{e(msg)}</p></div></section>'
    return layout("Не найдено", body, me, "", "page center") if me else public_message("Не найдено", msg)


# ---------- journal ----------

def log_page(me, fmt, events):
    rows = "".join(f"""<tr><td class="num">{e(fmt.dt(x['ts'], short=True))}</td><td>{e(x.get('who') or '—')}</td>
<td class="mono">{e(x['ip'] or '')}</td><td>{e(x['text'])}</td></tr>""" for x in events)
    mrows = "".join(f"""<div class="mrow"><div class="grow"><div>{e(x['text'])}</div>
<div class="meta"><span class="num">{e(fmt.dt(x['ts'], short=True))} · {e(x.get('who') or '—')}</span><span class="mono">{e(x['ip'] or '')}</span></div></div></div>"""
                    for x in events)
    content = (f"""<div class="scroll desk"><table class="t dense"><thead><tr><th>Когда</th><th>Кто</th><th>IP</th><th>Что</th></tr></thead>
<tbody>{rows}</tbody></table></div><div class="mlist">{mrows}</div>""" if events else '<p class="empty">Пусто.</p>')
    body = f'<section class="panel"><div class="ph"><h2>Журнал</h2><span class="count">{len(events)} последних</span></div>{content}</section>'
    return layout("Журнал", body, me, "log")


# ---------- profile ----------

def me_page(me, fmt, user, sessions, error="", ok=""):
    msgs = (alert(ok, ok=True) if ok else "") + (alert(error) if error else "")
    body = f"""<div class="head"><h1>Профиль</h1><p class="muted">{e(user['login'])} · {'владелец' if user['role'] == 'owner' else 'админ'}</p></div>{msgs}
<div class="grid2"><div class="col">
<form class="panel" method="post" action="/me/password">{csrf_field(me)}
<div class="ph"><h2>Пароль</h2></div><div class="pb">
<input type="text" name="username" value="{e(user['login'])}" autocomplete="username" class="hidden-ta" tabindex="-1" aria-hidden="true">
<div class="field"><label class="lb" for="cur">Текущий пароль</label><input id="cur" name="current" type="password" class="in tall" autocomplete="current-password" required></div>
<div class="field"><label class="lb" for="n1">Новый пароль</label><input id="n1" name="password" type="password" class="in tall" autocomplete="new-password" minlength="10" required>
<span class="hint">Не короче 10 символов. После смены все другие ваши сеансы закроются.</span></div>
<div class="field"><label class="lb" for="n2">Ещё раз</label><input id="n2" name="password2" type="password" class="in tall" autocomplete="new-password" minlength="10" required></div>
<button class="btn pri tall" type="submit">Сменить пароль</button></div></form>
</div><div class="col">
<form class="panel" method="post" action="/me/profile">{csrf_field(me)}
<div class="ph"><h2>Учётка</h2></div><div class="pb">
<div class="field"><label class="lb" for="ln">Логин</label><input id="ln" name="login" class="in tall" value="{e(user['login'])}" autocapitalize="none" required>
<span class="hint">Латиница в нижнем регистре, цифры, точка, дефис.</span></div>
<div class="field"><label class="lb" for="nm">Имя</label><input id="nm" name="name" class="in tall" value="{e(user['name'])}" maxlength="64"></div>
<button class="btn tall" type="submit">Сохранить</button></div></form>
<section class="panel"><div class="ph"><h2>Сеансы</h2><span class="count">{sessions}</span></div><div class="pb">
<p class="hint">Открытых входов с разных устройств: {sessions}. Последний вход — {e(fmt.dt(user['last_login']))}.</p>
<form method="post" action="/me/logout-others">{csrf_field(me)}<button class="btn" type="submit">Выйти на всех других устройствах</button></form></div></section>
</div></div>"""
    return layout("Профиль", body, me, "me")


# ---------- accounts (owner) ----------

def _server_names(u, titles):
    if u["role"] == "owner":
        return '<span class="muted">все</span>'
    try:
        ids = json.loads(u["servers"] or "[]")
    except ValueError:
        ids = []
    return ", ".join(e(titles.get(i, i)) for i in ids) or '<span class="muted">нет</span>'


def users_page(me, fmt, users, servers, error="", ok="", invite_link="", invite_for=""):
    titles = {s["id"]: s.get("title", s["id"]) for s in servers}
    msgs = (alert(ok, ok=True) if ok else "") + (alert(error) if error else "") + _invite_box(invite_link, invite_for)
    rows = []
    for u in users:
        if u["disabled"]:
            dot, st = "dot dis", "отключена"
        elif not u["pw_hash"]:
            dot, st = "dot off", "ждёт пароль"
        else:
            dot, st = "dot on", "активна"
        me_tag = ' <span class="tag acc">это вы</span>' if u["id"] == me["user_id"] else ""
        rows.append(f"""<tr{' class="dim"' if u['disabled'] else ''}><td class="st"><span class="{dot}" title="{st}"></span></td>
<td><a href="/users/{u['id']}">{e(u['login'])}</a>{me_tag}<span class="sub">{e(u['name'])}</span></td>
<td><span class="tag{' acc' if u['role'] == 'owner' else ''}">{'владелец' if u['role'] == 'owner' else 'админ'}</span></td>
<td>{_server_names(u, titles)}</td><td>{st}</td><td>{e(fmt.dt(u['last_login']))}</td></tr>""")
    body = f"""{msgs}<section class="panel"><div class="ph"><h2>Учётки</h2><span class="count">{len(users)}</span><span class="sp"></span>
<a class="btn pri" href="/users/new">+ Новая учётка</a></div>
<div class="scroll"><table class="t"><thead><tr><th><span class="sr">Статус</span></th><th>Логин</th><th>Роль</th><th>Серверы</th><th>Состояние</th><th>Последний вход</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<p class="foot">Владелец видит всё и управляет учётками. Админ видит и меняет клиентов только на отмеченных ему серверах.</p></section>"""
    return layout("Учётки", body, me, "users")


def _invite_box(link, who):
    if not link:
        return ""
    return f"""<div class="linkbox"><div class="row between"><span class="lt">Ссылка для «{e(who)}» — задать пароль</span>
<span class="small muted">действует 48 часов, один раз · показана один раз</span></div>
<div class="row"><input id="invlink" class="in mono grow" value="{e(link)}" readonly aria-label="Ссылка-приглашение">
<button class="btn" type="button" data-copy="invlink">Копировать</button></div>
<p class="note">{I_INFO}Перешлите ссылку коллеге. Пароль он задаст сам — его не знает никто, включая вас.</p></div>"""


def user_form_page(me, fmt, u, servers, error="", invite_link=""):
    new = u is None
    u = u or {"id": None, "login": "", "name": "", "role": "admin", "servers": "[]", "disabled": 0, "pw_hash": None,
              "last_login": None}
    try:
        mine = set(json.loads(u["servers"] or "[]"))
    except ValueError:
        mine = set()
    checks = "".join(
        f'<label class="chk"><input type="checkbox" name="servers" value="{e(s["id"])}"{" checked" if s["id"] in mine else ""}>'
        f'{e(s.get("title", s["id"]))}</label>' for s in servers)
    roles = "".join(f'<option value="{v}"{" selected" if u["role"] == v else ""}>{t}</option>'
                    for v, t in (("admin", "Админ — клиенты на отмеченных серверах"), ("owner", "Владелец — всё, включая учётки")))
    action = "/users/new" if new else f"/users/{u['id']}/update"
    login_field = (f"""<div class="field"><label class="lb" for="ln">Логин</label>
<input id="ln" name="login" class="in tall" autocapitalize="none" value="{e(u['login'])}" required placeholder="ivanov">
<span class="hint">Латиница в нижнем регистре, цифры, точка, дефис. Под ним коллега будет входить.</span></div>""" if new else
                   f'<div class="field"><span class="lb">Логин</span><span class="mono">{e(u["login"])}</span></div>')
    form = f"""<form class="panel" method="post" action="{action}">{csrf_field(me)}
<div class="ph"><h2>{'Новая учётка' if new else 'Учётка ' + e(u['login'])}</h2></div><div class="pb">
{alert(error) if error else ''}{_invite_box(invite_link, u['login'])}
{login_field}
<div class="field"><label class="lb" for="nm">Имя</label><input id="nm" name="name" class="in tall" maxlength="64" value="{e(u['name'])}" placeholder="Иван Иванов"></div>
<div class="field"><label class="lb" for="rl">Роль</label><select id="rl" name="role" class="in tall">{roles}</select></div>
<fieldset class="field"><legend class="lb">Серверы (для админа)</legend><div class="checks">{checks}</div>
<span class="hint">Админ увидит только клиентов этих серверов. Владельцу доступны все.</span></fieldset>
<button class="btn pri tall" type="submit">{'Создать и получить ссылку' if new else 'Сохранить'}</button>
{'<span class="hint">Пароль задаёт сам коллега по одноразовой ссылке — она появится после создания.</span>' if new else ''}
</div></form>"""
    manage = ""
    if not new:
        is_me = u["id"] == me["user_id"]
        tgl = "enable" if u["disabled"] else "disable"
        rows = [f"""<div class="split"><div><div class="lb">Сбросить пароль</div><div class="hint">Старый пароль и все сеансы перестанут работать; появится новая ссылка на 48 часов.</div></div>
<form method="post" action="/users/{u['id']}/reset">{csrf_field(me)}<button class="btn" type="submit">Сбросить</button></form></div>"""]
        if not is_me:
            rows.append(f"""<div class="split"><div><div class="lb">Доступ</div><div class="hint">Отключённая учётка не может войти; её сеансы закрываются сразу.</div></div>
<form method="post" action="/users/{u['id']}/{tgl}">{csrf_field(me)}<button class="btn" type="submit">{'Включить' if u['disabled'] else 'Отключить'}</button></form></div>""")
            rows.append(f"""<div class="split top"><div><div class="lb danger">Удалить учётку</div><div class="hint">Клиенты, которых она создала, остаются.</div></div>
<form method="post" action="/users/{u['id']}/delete" data-confirm="Удалить учётку «{e(u['login'])}»?">{csrf_field(me)}<button class="btn dng" type="submit">Удалить</button></form></div>""")
        else:
            rows.append('<p class="hint">Это ваша учётка: отключить или удалить её нельзя. Пароль меняется в «Профиле».</p>')
        manage = f'<section class="panel"><div class="ph"><h2>Управление</h2></div><div class="pb">{"".join(rows)}</div></section>'
    body = f"""<div class="head"><a class="btn txt back" href="/users">← все учётки</a></div>
<div class="grid2"><div class="col">{form}</div><div class="col">{manage}</div></div>"""
    return layout("Учётка", body, me, "users")


def _app(kind):
    from .clientconf import APPS
    return APPS.get(kind or "", "Amnezia VPN или AmneziaWG")


def _fname(name):
    keep = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (name or "vpn"))
    return (keep.strip("_") or "vpn")[:40]
