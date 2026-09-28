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
        n = me.get("pending_requests") or 0
        items = [("/", "Клиенты", "clients"), ("/new", "Добавить", "new"),
                 ("/requests", f"Заявки ({n})" if n else "Заявки", "requests"), ("/log", "Журнал", "log")]
        if me["role"] == "owner":
            items += [("/servers", "Серверы", "servers"), ("/users", "Учётки", "users"), ("/settings", "Настройки", "settings")]
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
<title>{e(title)} — VPN-панель</title><link rel="icon" type="image/svg+xml" href="/static/favicon.svg"><link rel="stylesheet" href="/static/app.css"></head>
<body class="app">{nav}<main class="{page_cls}">{body}</main><script src="/static/app.js"></script></body></html>"""


def bare(title, body):
    """Pages without navigation: login, invite, public share."""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><link rel="icon" type="image/svg+xml" href="/static/favicon.svg"><link rel="stylesheet" href="/static/app.css"></head>
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
<div class="top"><span class="mono muted">{"TCP" if h["kind"] in ("sstp", "vless") else "UDP"} {e(h['port'])}</span><span class="st">{state}</span></div></a>""")
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
    order = {"awg3": 0, "vless": 1, "awg2": 2, "sstp": 3}
    for h in sorted(health, key=lambda h: (order.get(h["kind"], 9), h["server"])):
        if h["kind"] in CAN_ADD and h["server"] in titles:
            proto = "TCP" if h["kind"] in ("sstp", "vless") else "UDP"
            label = " (системный)" if h["container"] == "sstp-host" else ""
            opts.append(f'<option value="{e(h["server"])}|{e(h["container"])}">'
                        f'{e(titles[h["server"]])} — {e(KIND_TITLE[h["kind"]])}{label} ({proto} {e(h["port"])})</option>')
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
<span class="hint">AWG 3.1 — для Amnezia VPN 5.0.1.5+ и AmneziaWG 3.1; AWG 2.0 — для старых приложений.
VLESS — клиенты Xray (v2rayNG, Hiddify, Streisand). SSTP — встроенный VPN Windows и MikroTik.</span></fieldset>
<div class="field"><label class="lb" for="lgn">Логин для SSTP <span class="muted">(необязательно)</span></label>
<input id="lgn" name="login" class="in tall" maxlength="32" autocapitalize="none" placeholder="придумается сам">
<span class="hint">Только для SSTP: латиница, цифры, точка, дефис. Пароль панель сгенерирует.</span></div>
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


def client_page(me, fmt, c, server, bundle, kind, qr, shares, points, targets, protected,
                error="", new_link="", notice="", selfsigned=True, send_html=""):
    conf = bundle["text"] if bundle else None
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
        if targets and kind in ("awg2", "legacy", "wireguard") and not c["migrated_to"] and conf:
            acts.append(_migrate_form(me, c, targets))
        acts.append(f"""<div class="split top"><div><div class="lb danger">Удалить клиента</div><div class="hint">Его VPN перестанет работать сразу.</div></div>
<form method="post" action="/client/{c['id']}/delete" data-confirm="Удалить клиента «{e(title)}»? Его VPN перестанет работать.">
{csrf_field(me)}<button class="btn dng" type="submit">Удалить</button></form></div>""")
    actions = f'<section class="panel"><div class="ph"><h2>Действия</h2></div><div class="pb">{"".join(acts)}</div></section>' if acts else ""

    side = []
    if bundle:
        side.append(f"""<section class="panel"><div class="ph"><h2>Конфиг</h2></div>{config_block(bundle, kind, qr, c)}
<div class="pb apps-pb"><div class="lb">Приложения для клиента</div>{apps_block(kind, "android", compact=True)}</div></section>""")
        if send_html:
            side.append(send_html)
        side.append(_share_block(me, fmt, c, shares, new_link, now, selfsigned))
    elif not c["deleted"] and not protected:
        mig = _migrate_form(me, c, targets) if targets and not c["migrated_to"] and kind in ("awg2", "legacy", "wireguard") else ""
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


def _share_block(me, fmt, c, shares, new_link, now, selfsigned=True):
    if c["deleted"]:
        return ""
    cert_note = (f'<p class="note">{I_INFO}Браузер клиента предупредит о сертификате — это ожидаемо: '
                 f'нужно нажать «Дополнительно» → «Перейти на сайт».</p>' if selfsigned else "")
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
{cert_note}
{table}</div></section>"""


# ---------- app download links ----------

def apps_block(kind, first="desktop", compact=False):
    from .clientconf import PLATFORMS, VERSION_NOTE, app_links
    links = app_links(kind)
    order = sorted(PLATFORMS, key=lambda p: p[0] != first)
    groups = []
    for pid, title in order:
        items = []
        for name, url, where, note in links[pid]:
            note_html = '<span class="anote">' + e(note) + '</span>' if note else ""
            items.append(f'<a class="applink" href="{e(url)}" target="_blank" rel="noopener noreferrer">'
                         f'<span class="an">{e(name)}</span><span class="aw">{e(where)}</span>{note_html}</a>')
        first_cls = " first" if pid == first else ""
        groups.append(f'<div class="apg{first_cls}"><div class="apt">{e(title)}</div>'
                      f'<div class="apl">{"".join(items)}</div></div>')
    note = VERSION_NOTE.get(kind or "")
    note_html = f'<p class="note">{I_INFO}{e(note)}</p>' if note else ""
    compact_cls = " compact" if compact else ""
    return f'<div class="apps{compact_cls}">{"".join(groups)}</div>{note_html}'


# ---------- public pages ----------

def _data_url(text, mime="text/plain"):
    return f"data:{mime};base64," + base64.b64encode(text.encode()).decode()


def config_block(b, kind, qr, c, public=False):
    """What the client receives, per protocol (admin card and public page share it)."""
    big = " xl full" if public else ""
    parts = []
    if qr:
        parts.append(f'<div class="qr" role="img" aria-label="QR-код для подключения">{qr}</div>')
    if b["kind"] == "sstp":
        rows = "".join(
            f'<div class="kv"><span class="k">{e(k)}</span><span class="v mono" id="f{i}">{e(v)}</span>'
            f'<button class="btn txt" type="button" data-copy-text="f{i}">копировать</button></div>'
            for i, (k, v) in enumerate(b["fields"]))
        parts.append(f'<div class="kvs">{rows}</div>')
        steps = ('<p class="hint">Windows: «Параметры → Сеть → VPN → Добавить»: тип «SSTP», сервер и логин/пароль отсюда. '
                 'Android — Open SSTP Client, MikroTik — /interface sstp-client.</p>')
        if b.get("cert_pem"):
            steps += ('<p class="hint">Сертификат сервера самоподписанный: на Windows его нужно один раз установить в '
                      '«Доверенные корневые центры сертификации» (двойной щелчок по файлу → «Установить сертификат»). '
                      'В Android-клиенте включите «не проверять сертификат» или импортируйте его.</p>')
        parts.append(steps)
        btns = [f'<button class="btn{" pri" if not b.get("cert_pem") else ""}{big}" type="button" data-copy="conf">Копировать всё</button>']
        if b.get("cert_pem"):
            btns.insert(0, f'<a class="btn pri{big}" download="{e(b["cert_name"])}" href="{_data_url(b["cert_pem"], "application/x-x509-ca-cert")}">Скачать сертификат</a>')
    elif b["kind"] == "vless":
        parts.append(f'<p class="hint c">Отсканируйте QR или скопируйте ссылку и вставьте в приложение («+» → «Импорт из буфера»).</p>')
        parts.append(f'<div class="uri mono">{e(b["text"])}</div>')
        btns = [f'<button class="btn pri{big}" type="button" data-copy="conf">Копировать ссылку</button>']
    else:
        parts.append(f'<p class="hint c">Сканируйте в {e(_app(kind))}: «+» → «QR-код».</p>')
        btns = [f'<a class="btn pri{big}" download="{e(b["filename"])}" href="{_data_url(b["text"])}">Скачать {"файл конфигурации" if public else ".conf"}</a>',
                f'<button class="btn{big if public else ""}" type="button" data-copy="conf">Копировать текст</button>']
    wrap = "soft" if public else "pb qrwrap"
    return (f'<div class="{wrap}">{"".join(parts)}<div class="row wrap{" col-btns" if public else ""}">{"".join(btns)}</div>'
            f'<textarea id="conf" readonly class="hidden-ta" tabindex="-1" aria-hidden="true">{e(b["text"])}</textarea></div>')


def share_page(c, b, kind, qr, platform="desktop"):
    step2 = {"sstp": "Создайте VPN-подключение типа SSTP с данными ниже.",
             "vless": "В приложении нажмите «+» и выберите «Сканировать QR» или «Импорт из буфера».",
             }.get(b["kind"], "В приложении нажмите «+» и выберите «QR-код» или «Файл».")
    return bare("Ваш VPN", f"""<div class="pubwrap"><main class="pub">
<div class="head"><h1>Ваш VPN</h1><p class="muted">Подключение для: <strong>{e(c['name'])}</strong></p></div>
<ol class="steps">
<li><span class="n">1</span><div class="grow">Установите приложение — ссылки для вашего устройства первыми:{apps_block(kind, platform)}</div></li>
<li><span class="n">2</span><div>{e(step2)}</div></li>
<li><span class="n">3</span><div>Включите подключение.</div></li></ol>
{config_block(b, kind, qr, c, public=True)}
<p class="small muted">Это ваши личные данные для входа — не пересылайте их. Ссылка может быть одноразовой: сохраните всё сейчас.</p>
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


# ---------- sending a config to the client ----------

def send_block(me, c, st, tg_link=""):
    parts = []
    if st["tg_ready"]:
        link = ""
        if tg_link:
            link = f"""<div class="linkbox"><div class="row between"><span class="lt">Ссылка на бота</span><span class="small muted">72 часа, один раз</span></div>
<div class="row"><input id="tglink" class="in mono grow" value="{e(tg_link)}" readonly aria-label="Ссылка на бота">
<button class="btn" type="button" data-copy="tglink">Копировать</button></div>
<p class="note">{I_INFO}Перешлите её человеку. Он нажмёт «Start» — и бот пришлёт ему всё для подключения.</p></div>"""
        now_btn = (f"""<form method="post" action="/client/{c['id']}/tg-send">{csrf_field(me)}<button class="btn" type="submit">Отправить снова в Telegram</button></form>"""
                   if st["tg_bound"] else "")
        parts.append(f"""<div class="field"><span class="lb">Telegram — бот @{e(st['tg_username'])}</span>
<div class="row wrap"><form method="post" action="/client/{c['id']}/tg-link">{csrf_field(me)}<button class="btn pri" type="submit">Ссылка на бота</button></form>{now_btn}</div>
{('<span class="hint">Человек уже подключил бота — можно отправлять сразу.</span>' if st['tg_bound'] else '')}{link}</div>""")
    else:
        parts.append('<p class="hint">Telegram не настроен' + (' — «Настройки» → Telegram.' if me["role"] == "owner" else '.') + '</p>')
    if st["smtp_ready"]:
        parts.append(f"""<form class="field" method="post" action="/client/{c['id']}/email">{csrf_field(me)}
<label class="lb" for="em">Почта</label><div class="row"><input id="em" name="email" type="email" class="in grow" value="{e(c.get('email') or '')}" placeholder="name@example.com" required>
<button class="btn" type="submit">Отправить</button></div></form>""")
    else:
        parts.append('<p class="hint">Почта не настроена' + (' — «Настройки» → Почта.' if me["role"] == "owner" else '.') + '</p>')
    return f'<section class="panel"><div class="ph"><h2>Отправить клиенту</h2></div><div class="pb">{"".join(parts)}</div></section>'


# ---------- settings (owner) ----------

def settings_page(me, st, smtp, error="", ok="", admin_link=""):
    msgs = (alert(ok, ok=True) if ok else "") + (alert(error) if error else "")
    sec = "".join(f'<option value="{v}"{" selected" if (smtp.get("smtp_security") or "starttls") == v else ""}>{t}</option>'
                  for v, t in (("starttls", "STARTTLS (587)"), ("ssl", "SSL/TLS (465)"), ("none", "без шифрования")))
    tg_state = (f'<p class="hint">Подключён бот <b>@{e(st["tg_username"])}</b> (токен {e(st["tg_masked"])}).</p>' if st["tg_ready"]
                else '<p class="hint">Создайте бота у @BotFather («/newbot») и вставьте его токен.</p>')
    body = f"""<div class="head"><h1>Настройки</h1></div>{msgs}
<div class="grid2"><div class="col">
<form class="panel" method="post" action="/settings/telegram">{csrf_field(me)}
<div class="ph"><h2>Telegram</h2></div><div class="pb">{tg_state}
<div class="field"><label class="lb" for="tgt">Токен бота</label><input id="tgt" name="tg_token" class="in tall mono" autocomplete="off" placeholder="123456:ABC…">
<span class="hint">Пустое поле + «Сохранить» — отключить бота. Токен хранится в базе панели и целиком больше не показывается.</span></div>
<button class="btn pri tall" type="submit">Проверить и сохранить</button></div></form>
{_tg_admin_block(me, st, admin_link) if st["tg_ready"] else ""}
</div><div class="col">
<form class="panel" method="post" action="/settings/smtp">{csrf_field(me)}
<div class="ph"><h2>Почта (SMTP)</h2></div><div class="pb">
<div class="row wrap"><div class="field grow"><label class="lb" for="sh">Сервер</label><input id="sh" name="smtp_host" class="in tall" value="{e(smtp.get('smtp_host'))}" placeholder="smtp.example.com"></div>
<div class="field"><label class="lb" for="sp">Порт</label><input id="sp" name="smtp_port" class="in tall" value="{e(smtp.get('smtp_port'))}" placeholder="587" inputmode="numeric"></div></div>
<div class="field"><label class="lb" for="ss">Шифрование</label><select id="ss" name="smtp_security" class="in tall">{sec}</select></div>
<div class="field"><label class="lb" for="su">Логин</label><input id="su" name="smtp_user" class="in tall" value="{e(smtp.get('smtp_user'))}" autocomplete="off"></div>
<div class="field"><label class="lb" for="spw">Пароль</label><input id="spw" name="smtp_pass" type="password" class="in tall" autocomplete="new-password" placeholder="{'сохранён — оставьте пустым, чтобы не менять' if smtp.get('smtp_pass') else ''}"></div>
<div class="field"><label class="lb" for="sf">Отправитель</label><input id="sf" name="smtp_from" class="in tall" value="{e(smtp.get('smtp_from'))}" placeholder="VPN &lt;vpn@example.com&gt;"></div>
<div class="field"><label class="lb" for="stt">Тестовое письмо на адрес <span class="muted">(необязательно)</span></label><input id="stt" name="test_to" type="email" class="in tall"></div>
<button class="btn pri tall" type="submit">Сохранить</button></div></form>
</div></div>"""
    return layout("Настройки", body, me, "settings")


def _tg_admin_block(me, st, link):
    state = ('<p class="hint">Ваш Telegram привязан: заявки приходят вам с кнопками «выдать» / «отклонить».</p>'
             if st.get("me_linked") else '<p class="hint">Привяжите свой Telegram — бот будет присылать вам заявки на VPN с кнопками одобрения.</p>')
    box = ""
    if link:
        box = f"""<div class="linkbox"><div class="row between"><span class="lt">Откройте ссылку в своём Telegram</span><span class="small muted">1 час, один раз</span></div>
<div class="row"><input id="adml" class="in mono grow" value="{e(link)}" readonly aria-label="Ссылка привязки">
<button class="btn" type="button" data-copy="adml">Копировать</button></div>
<p class="note">{I_INFO}Кто откроет её первым, тот и станет получать заявки — не пересылайте её.</p></div>"""
    return f"""<form class="panel" method="post" action="/settings/tg-admin">{csrf_field(me)}
<div class="ph"><h2>Заявки в мой Telegram</h2></div><div class="pb">{state}{box}
<button class="btn tall" type="submit">{'Привязать заново' if st.get('me_linked') else 'Получить ссылку привязки'}</button></div></form>"""


# ---------- servers (owner) ----------

PROTO_TITLE = {"awg3": "AWG 3.1", "sstp": "SSTP", "vless": "VLESS"}
UNIT_PROTO = {"awg3": "awg3", "sstp": "sstp", "xray": "vless"}


def servers_page(me, fmt, servers, health, server_health, jobs_running, protected_units, error="", ok=""):
    msgs = (alert(ok, ok=True) if ok else "") + (alert(error) if error else "")
    sh = {x["server"]: x for x in server_health}
    cards = []
    for s in servers:
        units = [h for h in health if h["server"] == s["id"]]
        info = s.get("info") or {}
        st = sh.get(s["id"])
        state = ('<span class="tag red">не отвечает</span>' if st and not st["ok"] else
                 '<span class="tag acc">на связи</span>' if st else '<span class="tag">ещё не опрошен</span>')
        rows = []
        for h in units:
            proto = UNIT_PROTO.get(h["container"])
            rm = ""
            if proto and h["container"] not in protected_units.get(s["id"], set()):
                rm = (f'<form method="post" action="/servers/{e(s["id"])}/uninstall" data-confirm="Удалить {e(PROTO_TITLE[proto])} с сервера «{e(s["title"])}»? '
                      f'Все его клиенты перестанут подключаться. Ключи сохранятся на сервере в стороне.">{csrf_field(me)}'
                      f'<input type="hidden" name="proto" value="{proto}"><button class="btn txt" type="submit">удалить</button></form>')
            elif proto:
                rm = '<span class="small muted">служебный туннель — удалять нельзя</span>'
            label = " (системный accel-ppp)" if h["container"] == "sstp-host" else ""
            rows.append(f"""<tr><td>{badge(h['kind'])}{e(label)}</td><td class="mono">{e(h['container'])}</td>
<td class="mono">{"TCP" if h["kind"] in ("sstp", "vless") else "UDP"} {e(h['port'])}</td>
<td>{'<span class="tag acc">работает</span>' if h['up'] else '<span class="tag red">не поднят</span>'}</td><td class="r">{h['peers']}</td><td class="r">{rm}</td></tr>""")
        installed = {UNIT_PROTO.get(h["container"]) for h in units}
        running = jobs_running.get(s["id"])
        installs = []
        if running:
            installs.append(f'<p class="hint">Идёт задача — <a href="/jobs/{running}">журнал</a>.</p>')
        else:
            for proto, title in PROTO_TITLE.items():
                if proto in installed:
                    continue
                sni = ('<input name="sni" class="in" placeholder="SNI (авто)" aria-label="SNI для REALITY">' if proto == "vless" else "")
                installs.append(f"""<form class="row wrap" method="post" action="/servers/{e(s['id'])}/install">{csrf_field(me)}
<input type="hidden" name="proto" value="{proto}"><input name="port" class="in port" placeholder="порт (авто)" inputmode="numeric" aria-label="Порт">{sni}
<button class="btn" type="submit">Установить {e(title)}</button></form>""")
        facts = []
        if info:
            facts.append(f"vpnctl {e(info.get('version', '?'))} · {e(info.get('os', ''))} · свободно {e(info.get('free_mb'))} МБ · памяти {e(info.get('mem_avail_mb'))} МБ"
                         + ("" if info.get("docker") else " · docker будет установлен"))
        manage = []
        if s.get("transport") == "ssh":
            manage.append(f'<form method="post" action="/servers/{e(s["id"])}/check">{csrf_field(me)}<button class="btn" type="submit">Проверить</button></form>')
            manage.append(f'<a class="btn" href="/servers/{e(s["id"])}/update">Обновить агент</a>')
            if s.get("source") != "config":
                manage.append(f'<form method="post" action="/servers/{e(s["id"])}/remove" data-confirm="Убрать «{e(s["title"])}» из панели? VPN на сервере продолжит работать, '
                              f'но панель перестанет его видеть и снимет с него свой ключ.">{csrf_field(me)}<button class="btn dng" type="submit">Убрать из панели</button></form>')
        else:
            manage.append('<span class="hint">Этот сервер — хост самой панели (управляется локально).</span>')
        table = (f'<div class="scroll"><table class="t dense"><thead><tr><th>Протокол</th><th>Юнит</th><th>Порт</th><th>Состояние</th>'
                 f'<th class="r">Клиентов</th><th></th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>' if rows else
                 '<p class="empty">Протоколов пока нет.</p>')
        cards.append(f"""<section class="panel"><div class="ph"><h2>{e(s['title'])}</h2>{state}<span class="sp"></span>
<span class="mono muted small">{e(s['endpoint'])}{(' · ssh ' + e(s.get('ssh_host')) + ':' + e(s.get('ssh_port'))) if s.get('transport') == 'ssh' else ' · локально'}</span></div>
{table}<div class="pb">{('<p class="hint">' + ''.join(facts) + '</p>') if facts else ''}
<div class="lb">Установить протокол</div>{''.join(installs) or '<p class="hint">Все протоколы уже стоят.</p>'}
<div class="row wrap">{''.join(manage)}</div></div></section>""")
    body = f"""{msgs}<div class="row between"><h1>Серверы</h1><a class="btn pri" href="/servers/new">+ Добавить сервер</a></div>
{''.join(cards)}"""
    return layout("Серверы", body, me, "servers")


def server_form_page(me, s=None, error=""):
    new = s is None
    s = s or {}
    title = "Новый сервер" if new else f"Обновить агент: {s.get('title')}"
    ident = ("" if not new else f"""<div class="field"><label class="lb" for="tt">Название</label><input id="tt" name="title" class="in tall" required maxlength="40" placeholder="Нидерланды"></div>
<div class="field"><label class="lb" for="ep">Адрес для клиентов <span class="muted">(IP или домен)</span></label><input id="ep" name="endpoint" class="in tall" placeholder="как SSH-адрес">
<span class="hint">Этот адрес попадёт в конфиги клиентов.</span></div>""")
    body = f"""<div class="head"><a class="btn txt back" href="/servers">← все серверы</a></div>
<form class="panel narrow" method="post" action="{'/servers/new' if new else '/servers/' + e(s['id']) + '/update'}">{csrf_field(me)}
<div class="ph"><h2>{e(title)}</h2></div><div class="pb">{alert(error) if error else ''}
{ident}
<div class="row wrap"><div class="field grow"><label class="lb" for="hs">SSH-адрес</label><input id="hs" name="host" class="in tall" required value="{e(s.get('ssh_host', ''))}" placeholder="203.0.113.10"></div>
<div class="field"><label class="lb" for="pt">Порт</label><input id="pt" name="port" class="in tall port" value="{e(s.get('ssh_port', 22))}" inputmode="numeric"></div></div>
<div class="field"><label class="lb" for="us">Пользователь</label><input id="us" name="user" class="in tall" value="root"></div>
<div class="field"><label class="lb" for="pw">Пароль root</label><input id="pw" name="password" type="password" class="in tall" autocomplete="off"></div>
<div class="field"><label class="lb" for="pk">…или приватный ключ</label><textarea id="pk" name="key" class="in ta mono" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></div>
<p class="note">{I_INFO}Пароль или ключ нужен один раз: панель положит на сервер vpnctl и свой ключ, который умеет только управлять VPN. Сами пароль и ключ нигде не сохраняются.</p>
<button class="btn pri tall" type="submit">{'Подключить' if new else 'Обновить'}</button></div></form>"""
    return layout(title, body, me, "servers", "page center")


def job_page(me, fmt, job, server_title):
    running = job["status"] == "running"
    state = {"running": '<span class="tag acc">идёт</span>', "ok": '<span class="tag acc">готово</span>',
             "failed": '<span class="tag red">ошибка</span>'}[job["status"]]
    refresh = '<meta http-equiv="refresh" content="3">' if running else ""
    body = f"""{refresh}<div class="head"><a class="btn txt back" href="/servers">← все серверы</a>
<div class="row gap12"><h1>{e(job['action'])}</h1>{state}</div><p class="muted">{e(server_title)} · начато {e(fmt.dt(job['started']))}</p></div>
<section class="panel"><div class="ph"><h2>Журнал</h2>{'<span class="small muted">страница обновляется сама</span>' if running else ''}</div>
<pre class="log">{e(job['log'])}</pre></section>"""
    return layout("Задача", body, me, "servers")


# ---------- Telegram requests ----------

def requests_page(me, fmt, pending, history, targets, bot_ready, approver_linked, error="", ok=""):
    msgs = (alert(ok, ok=True) if ok else "") + (alert(error) if error else "")
    tips = []
    if not bot_ready:
        tips.append("Бот не настроен — «Настройки» → Telegram.")
    elif me["role"] == "owner" and not approver_linked:
        tips.append("Привяжите свой Telegram в «Настройках» — заявки будут приходить вам с кнопками одобрения.")
    topt = "".join(f'<option value="{e(t[0])}|{e(t[1])}">{e(t[2])}</option>' for t in targets)
    rows = []
    for r in pending:
        approve = (f"""<form class="row wrap" method="post" action="/requests/{r['id']}/approve">{csrf_field(me)}
<select name="target" class="in">{topt}</select><button class="btn pri" type="submit">Одобрить</button></form>""" if targets else
                   '<span class="hint">нет доступных протоколов</span>')
        rows.append(f"""<tr><td class="num">{e(fmt.dt(r['created'], short=True))}</td>
<td><b>{e(r['full_name'] or '—')}</b><span class="sub">{('@' + e(r['username'])) if r['username'] else 'без username'} · id {e(r['chat_id'])}</span></td>
<td>{approve}</td><td class="r"><form method="post" action="/requests/{r['id']}/reject" data-confirm="Отклонить заявку?">{csrf_field(me)}
<button class="btn dng" type="submit">Отклонить</button></form></td></tr>""")
    hist = "".join(f"""<tr class="dim"><td class="num">{e(fmt.dt(r['decided'], short=True))}</td><td>{e(r['full_name'] or r['username'] or r['chat_id'])}</td>
<td>{'одобрена' if r['status'] == 'approved' else 'отклонена'}{(' · ' + e(r['decider'])) if r.get('decider') else ''}</td>
<td class="r">{f'<a href="/client/{r["client_id"]}">клиент</a>' if r['client_id'] else ''}</td></tr>""" for r in history)
    body = f"""<div class="head"><h1>Заявки из Telegram</h1><p class="muted">Человек пишет боту и жмёт «Запросить доступ». Конфиг он получит только после одобрения.</p></div>
{msgs}{''.join('<div class="alert">' + I_INFO + '<div>' + e(t) + '</div></div>' for t in tips)}
<section class="panel"><div class="ph"><h2>Ждут решения</h2><span class="count">{len(pending)}</span></div>
{('<div class="scroll"><table class="t"><thead><tr><th>Когда</th><th>Кто</th><th>Что выдать</th><th></th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>') if rows else '<p class="empty">Новых заявок нет.</p>'}</section>
<section class="panel"><div class="ph"><h2>Решённые</h2></div>
{('<div class="scroll"><table class="t dense"><thead><tr><th>Когда</th><th>Кто</th><th>Решение</th><th></th></tr></thead><tbody>' + hist + '</tbody></table></div>') if hist else '<p class="empty">Пока пусто.</p>'}</section>"""
    return layout("Заявки", body, me, "requests")
