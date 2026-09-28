"""Client configuration (.conf) for AmneziaWG 3.1 / 2.0 / Legacy and plain WireGuard.

`params` is what `awgctl params <container>` returns; the client's own keys come from the panel.
"""

# Order matters only for readability; AmneziaWG apps accept any order inside [Interface].
_SHARED_ORDER = ("S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
_CLIENT_ORDER = ("Jc", "Jmin", "Jmax", "I1", "I2", "I3", "I4", "I5")


def render(params, *, private_key, address, preshared_key, endpoint_host,
           allowed_ips="0.0.0.0/0, ::/0"):
    lines = ["[Interface]", f"PrivateKey = {private_key}", f"Address = {address}"]
    if params.get("dns"):
        lines.append(f"DNS = {params['dns']}")
    if params.get("mtu"):
        lines.append(f"MTU = {params['mtu']}")
    client_side = params.get("client_side") or {}
    shared = params.get("shared") or {}
    lines += [f"{k} = {client_side[k]}" for k in _CLIENT_ORDER if client_side.get(k) not in (None, "")]
    lines += [f"{k} = {shared[k]}" for k in _SHARED_ORDER if shared.get(k) not in (None, "")]
    if params.get("header_protection_key"):
        lines.append(f"HeaderProtectionKey = {params['header_protection_key']}")
    lines += ["", "[Peer]", f"PublicKey = {params['server_public_key']}"]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines += [f"AllowedIPs = {allowed_ips}", f"Endpoint = {endpoint_host}:{params['port']}",
              f"PersistentKeepalive = {params.get('keepalive') or 25}", ""]
    return "\n".join(lines)


def build(params, c, endpoint_host):
    """-> dict describing what the client gets, per protocol:
    text (to copy), qr (text for the QR or None), filename + mime (download), fields [(label, value)], cert_pem."""
    kind = params.get("kind")
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (c.get("name") or "vpn")).strip("_")[:40] or "vpn"
    if kind == "sstp":
        # a real certificate validates only by its name — use it instead of the server IP
        host = params.get("cert_name") if (not params.get("self_signed") and params.get("cert_name")) else endpoint_host
        server = f"{host}:{params['port']}"
        fields = [("Сервер", server), ("Логин", c["pub"]), ("Пароль", c.get("secret") or "")]
        text = "\n".join(f"{k}: {v}" for k, v in fields)
        cert = params.get("cert_pem") if params.get("self_signed") else None
        return {"kind": "sstp", "text": text, "qr": None, "filename": f"{safe}-sstp.txt", "mime": "text/plain",
                "fields": fields, "cert_pem": cert, "cert_name": f"vpn-{endpoint_host}.crt"}
    if kind == "vless":
        import urllib.parse as up
        q = {"encryption": "none", "flow": params.get("flow") or "xtls-rprx-vision", "security": "reality",
             "sni": params["sni"], "fp": params.get("fp") or "chrome", "pbk": params["public_key"],
             "sid": params["short_id"], "type": "tcp"}
        uri = (f"vless://{c['pub']}@{endpoint_host}:{params['port']}?{up.urlencode(q)}"
               f"#{up.quote(c.get('name') or 'VPN')}")
        return {"kind": "vless", "text": uri, "qr": uri, "filename": f"{safe}-vless.txt", "mime": "text/plain",
                "fields": [], "cert_pem": None}
    conf = render(params, private_key=c["priv"], address=c["ip"], preshared_key=c.get("psk"),
                  endpoint_host=endpoint_host)
    return {"kind": kind, "text": conf, "qr": conf, "filename": f"{safe}.conf", "mime": "text/plain",
            "fields": [], "cert_pem": None}


APPS = {
    "awg3": "Amnezia VPN 5.0.1.5+ или AmneziaWG 3.1 (Android, Windows)",
    "awg2": "Amnezia VPN 4.8+ или AmneziaWG",
    "legacy": "Amnezia VPN или AmneziaWG",
    "wireguard": "WireGuard, Amnezia VPN или AmneziaWG",
    "sstp": "встроенный VPN Windows, Open SSTP Client (Android), MikroTik",
    "vless": "v2rayNG, Hiddify, Streisand, v2RayTun и другие клиенты Xray",
}

# Official download links (checked 28.09.2026 on amnezia.org, docs.amnezia.org, the stores).
# (name, url, where, note)
_AMNEZIA = {
    "android": [
        ("Amnezia VPN", "https://play.google.com/store/apps/details?id=org.amnezia.vpn", "Google Play", ""),
        ("AmneziaWG", "https://play.google.com/store/apps/details?id=org.amnezia.awg", "Google Play", ""),
        ("Amnezia VPN — APK", "https://github.com/amnezia-vpn/amnezia-client/releases/latest", "GitHub",
         "если нет Google Play"),
    ],
    "ios": [
        ("AmneziaVPN", "https://apps.apple.com/app/amneziavpn/id1600529900", "App Store",
         "нет в российском App Store — нужен Apple ID другой страны"),
        ("DefaultVPN", "https://apps.apple.com/app/defaultvpn/id6744725017", "App Store",
         "от Amnezia, есть в российском App Store; импорт — файлом .conf"),
        ("AmneziaWG", "https://apps.apple.com/app/amneziawg/id6478942365", "App Store", ""),
    ],
    "desktop": [
        ("Amnezia VPN — Windows, macOS, Linux", "https://amnezia.org/downloads", "amnezia.org", ""),
    ],
}
_WIREGUARD = {
    "android": [("WireGuard", "https://play.google.com/store/apps/details?id=com.wireguard.android", "Google Play", "")]
               + _AMNEZIA["android"][:1],
    "ios": [("WireGuard", "https://apps.apple.com/app/wireguard/id1441195209", "App Store", "")] + _AMNEZIA["ios"][1:2],
    "desktop": [("WireGuard — Windows, macOS, Linux", "https://www.wireguard.com/install/", "wireguard.com", "")],
}
# VLESS / SSTP links checked 28.09.2026 (iTunes lookup API for ru/us storefronts, Google Play pages, project READMEs).
_VLESS = {
    "android": [
        ("Hiddify", "https://play.google.com/store/apps/details?id=app.hiddify.com", "Google Play", "бесплатно"),
        ("Happ", "https://play.google.com/store/apps/details?id=com.happproxy", "Google Play", "бесплатно"),
        ("v2rayNG", "https://github.com/2dust/v2rayNG/releases", "GitHub", "APK; из Google Play убран"),
    ],
    "ios": [
        ("Shadowrocket", "https://apps.apple.com/app/shadowrocket/id932747118", "App Store",
         "есть в российском App Store, платно (249 ₽)"),
        ("Streisand", "https://apps.apple.com/us/app/streisand/id6450534064", "App Store",
         "бесплатно; нет в российском App Store"),
        ("Hiddify", "https://apps.apple.com/us/app/hiddify-proxy-vpn/id6596777532", "App Store",
         "бесплатно; нет в российском App Store"),
    ],
    "desktop": [
        ("Hiddify — Windows, macOS, Linux", "https://github.com/hiddify/hiddify-app/releases/latest", "GitHub", ""),
        ("v2rayN — Windows", "https://github.com/2dust/v2rayN/releases", "GitHub", ""),
        ("Happ — Windows, macOS, Linux", "https://github.com/Happ-proxy/happ-desktop/releases/latest", "GitHub", ""),
    ],
}
_SSTP = {
    "android": [
        ("Open SSTP Client", "https://play.google.com/store/apps/details?id=kittoku.osc", "Google Play",
         "бесплатно; для самоподписанного сертификата выключите «Verify Hostname»"),
        ("Open SSTP Client — APK", "https://github.com/kittoku/Open-SSTP-Client/releases", "GitHub", ""),
    ],
    "ios": [
        ("SSTP Connect", "https://apps.apple.com/app/sstp-connect/id1543667909", "App Store",
         "есть в российском App Store, платно (249 ₽); встроенного SSTP в iOS нет"),
    ],
    "desktop": [
        ("Windows — встроенный VPN", "https://support.microsoft.com/ru-ru/windows/connect-to-a-vpn-in-windows-3d29aeb1-f497-f6b7-7633-115722c1009c",
         "microsoft.com", "тип подключения «SSTP»"),
        ("macOS — SSTP Connect", "https://apps.apple.com/app/sstp-connect/id1543667909", "App Store", "Apple Silicon"),
        ("MikroTik — SSTP client", "https://help.mikrotik.com/docs/spaces/ROS/pages/2031645/SSTP", "mikrotik.com", ""),
    ],
}
PLATFORMS = (("android", "Android"), ("ios", "iPhone и iPad"), ("desktop", "Компьютер"))
VERSION_NOTE = {
    "awg3": "Протокол AWG 3.1 — нужна свежая версия приложения: Amnezia VPN 5.0.1.5+ или AmneziaWG 3.1. "
            "Если после импорта нет подключения — обновите приложение.",
    "vless": "VLESS REALITY: импорт — сканом QR или ссылкой vless:// из буфера обмена.",
}


def app_links(kind):
    """-> {platform: [(name, url, where, note), ...]} for a container kind."""
    return {"wireguard": _WIREGUARD, "vless": _VLESS, "sstp": _SSTP}.get(kind, _AMNEZIA)


def platform_of(user_agent):
    ua = (user_agent or "").lower()
    if "iphone" in ua or "ipad" in ua or "ipod" in ua:
        return "ios"
    if "android" in ua:
        return "android"
    return "desktop"


def qr_svg(text, scale=4):
    """QR code as inline SVG (vendored segno, no network)."""
    import io
    import segno
    buf = io.BytesIO()
    # omitsize: no width/height, a viewBox instead — so CSS can scale any QR version to the same size
    segno.make(text, error="l", micro=False).save(buf, kind="svg", scale=scale, border=2,
                                                   dark="#111", light="#fff", xmldecl=False,
                                                   svgns=True, nl=False, omitsize=True)
    return buf.getvalue().decode()


def qr_png(text, scale=6):
    import io
    import segno
    buf = io.BytesIO()
    segno.make(text, error="l", micro=False).save(buf, kind="png", scale=scale, border=2)
    return buf.getvalue()
