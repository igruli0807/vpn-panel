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


APPS = {
    "awg3": "Amnezia VPN 5.0.1.5+ или AmneziaWG 3.1 (Android, Windows)",
    "awg2": "Amnezia VPN 4.8+ или AmneziaWG",
    "legacy": "Amnezia VPN или AmneziaWG",
    "wireguard": "WireGuard, Amnezia VPN или AmneziaWG",
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
PLATFORMS = (("android", "Android"), ("ios", "iPhone и iPad"), ("desktop", "Компьютер"))
VERSION_NOTE = {
    "awg3": "Протокол AWG 3.1 — нужна свежая версия приложения: Amnezia VPN 5.0.1.5+ или AmneziaWG 3.1. "
            "Если после импорта нет подключения — обновите приложение.",
}


def app_links(kind):
    """-> {platform: [(name, url, where, note), ...]} for a container kind."""
    return _WIREGUARD if kind == "wireguard" else _AMNEZIA


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
    segno.make(text, error="l", micro=False).save(buf, kind="svg", scale=scale, border=2,
                                                   dark="#111", light="#fff", xmldecl=False,
                                                   svgns=True, nl=False)
    return buf.getvalue().decode()


def qr_png(text, scale=6):
    import io
    import segno
    buf = io.BytesIO()
    segno.make(text, error="l", micro=False).save(buf, kind="png", scale=scale, border=2)
    return buf.getvalue()
