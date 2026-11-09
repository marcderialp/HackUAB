"""RB-03 Identity: sign-ins and accounts (UC-IDP-001..008, UC-VPN-001)."""
from __future__ import annotations

from collections import Counter

from triage import data
from triage.collectors.base import Pack, is_internal, local_str
from triage.collectors.email import SUSPICIOUS_UA, unusual_signins
from triage.normalize import normalize_user

PERSISTENCE_OPS = ("inbox rule", "mailbox rule", "set-inboxrule", "new-inboxrule", "consent", "add-mfamethod",
                   "add mfa", "register security info", "add member", "add user")
ANON = ("is_tor", "is_vpn_provider", "is_hosting", "is_residential_proxy")


SHARED_EXIT_ACCOUNTS = 5  # distinct accounts with a correct sign-in from one IP in ±7 days
SHARED_EXIT_DAYS = 2  # ...on at least this many different days


def _success(e: dict) -> bool:
    return e.get("result") == "success" or e.get("action") == "connect"


def shared_exit(pack: Pack, ip: str) -> bool:
    """Fact (not a verdict): is this external IP used by many of our own accounts over days?

    An office, store or carrier NAT exit is shared by many employees that all sign in correctly; an
    attacker's IP is not. Not stated if the IP is anonymous infrastructure (Tor, VPN provider, hosting)."""
    geo = (pack.query("RB-03.1 GeoIP de la IP de origen", "get_intel", {"indicator": ip},
                      lambda: data.get_intel(ip)) or {}).get("geo") or {}
    if any(str(geo.get(k)) == "True" for k in ANON):
        return False
    week = [i["event"] | {"event_id": i["event_id"]} for i in
            pack.timeline("RB-03.1 uso de la IP de origen (±7 días)", ip, sources=["idp_signins", "vpn"],
                          before_h=168, after_h=168)]
    good = [e for e in week if _success(e)]
    accounts = {normalize_user(str(e.get("user_upn") or e.get("user"))) for e in good}
    days = {str(e.get("timestamp", ""))[:10] for e in good}
    if len(accounts) < SHARED_EXIT_ACCOUNTS or len(days) < SHARED_EXIT_DAYS:
        return False
    isp = ", ".join(str(x) for x in (geo.get("as_org"), geo.get("city"), geo.get("country")) if x)
    pack.find("RB-03.1 salida compartida", f"{ip}{f' ({isp})' if isp else ''}: {len(accounts)} cuentas propias con "
              f"inicio de sesión correcto en {len(days)} días distintos (±7 días): IP de salida compartida conocida, "
              "no infraestructura de un atacante", "idp_signins/vpn/geoip", [e["event_id"] for e in good[:5]])
    return True


def collect(pack: Pack) -> None:
    users = list(dict.fromkeys(normalize_user(u) for u in pack.ents.get("users", []) if not u.startswith("(")))
    ext_ips = [ip for ip in pack.ents.get("ips", []) if not is_internal(ip)]

    # Spraying / many accounts from one origin: who actually got in? Many accounts that ALL sign in
    # correctly, with no failure, is the pattern of a shared exit (office, store, carrier NAT), not spraying.
    account = lambda e: normalize_user(str(e.get("user_upn") or e.get("user")))  # noqa: E731
    for ip in ext_ips[:6]:
        tried = [i["event"] | {"event_id": i["event_id"]} for i in
                 pack.timeline("RB-03.1 intentos desde el origen (±2 h)", ip, sources=["idp_signins", "vpn"],
                               before_h=2, after_h=2)]
        accounts = Counter(account(e) for e in tried)
        ok = [e for e in tried if _success(e)]
        failed = [e for e in tried if not _success(e)]
        if len(accounts) > 3 and not failed:
            pack.find("RB-03.1 origen", f"{ip}: {len(accounts)} cuentas distintas iniciaron sesión correctamente desde "
                      "esta IP en ±2 h sin ningún fallo: patrón de salida compartida (oficina, tienda, operador o NAT), "
                      "no de rociado de contraseñas", "idp_signins/vpn", [e["event_id"] for e in ok[:5]])
        elif len(accounts) > 3:
            winners = sorted({account(e) for e in ok})
            pack.find("RB-03.1 origen", f"{ip}: {len(tried)} intentos contra {len(accounts)} cuentas, {len(failed)} "
                      f"fallidos; {len(winners)} cuentas con acceso correcto" +
                      (f" ({', '.join(winners)})" if winners else ""),
                      "idp_signins/vpn", [e["event_id"] for e in ok] or [e["event_id"] for e in failed[:5]],
                      notable=bool(ok))
            for acct in winners[:3]:
                if acct not in {normalize_user(u) for u in users}:
                    users.append(acct)
        shared_exit(pack, ip)

    for user in users[:4]:
        signins = [i["event"] | {"event_id": i["event_id"]} for i in
                   pack.timeline("RB-03.1 inicios de sesión ±24 h", user, sources=["idp_signins", "vpn"],
                                 before_h=24, after_h=24)]
        # 1. Origin
        origins = Counter((str(s.get("src_ip")), str(s.get("country"))) for s in signins if s.get("src_ip"))
        flagged, suspicious_ips = [], set()
        for (ip, country), n in origins.most_common(8):
            if is_internal(ip):
                continue
            geo = (pack.query("RB-03.1 GeoIP del origen", "get_intel", {"indicator": ip},
                              lambda i=ip: data.get_intel(i)) or {}).get("geo") or {}
            kinds = [k[3:] for k in ANON if str(geo.get(k)) == "True"]
            if kinds:
                flagged.append(f"{ip} ({', '.join(kinds)}, {geo.get('as_org')}, {country})")
                suspicious_ips.add(ip)
        if flagged:
            pack.find("RB-03.1 origen", f"{user}: accesos desde infraestructura anónima o de hosting: {'; '.join(flagged)}",
                      "idp_signins/geoip", notable=True)
        countries = sorted({c for (_, c) in origins if c not in ("None", "")})
        if len(countries) > 1:
            pack.find("RB-03.1 origen", f"{user}: países distintos en ±24 h: {', '.join(countries)}", "idp_signins")

        # 2. Device and client
        odd_ua = [s for s in signins if any(k in str(s.get("user_agent", "")).casefold() for k in SUSPICIOUS_UA)]
        if odd_ua:
            pack.find("RB-03.2 cliente", f"{user}: clientes no navegador ({', '.join(sorted({str(s.get('user_agent'))[:25] for s in odd_ua}))})",
                      "idp_signins", [s["event_id"] for s in odd_ua], notable=True)
        new = unusual_signins(pack, user, "RB-03.2 sesión desde IP nueva", before_h=24, after_h=24)
        suspicious_ips |= {str(s.get("src_ip")) for s in new}
        if new:
            s = new[0]
            pack.find("RB-03.2 dispositivo", f"{user}: sesión correcta desde IP nueva {s.get('src_ip')} con "
                      f"{'dispositivo no conforme' if not s.get('device_compliant', True) else 'cliente no navegador'} "
                      f"a las {local_str(s['timestamp'])}", "idp_signins", [x["event_id"] for x in new], notable=True)
        for sid in sorted({s["session_id"] for s in signins if s.get("session_id")}):
            ips = sorted({str(s.get("src_ip")) for s in signins if s.get("session_id") == sid})
            if len(ips) > 1:
                pack.find("RB-03.2 sesión reutilizada", f"{user}: la sesión {sid} aparece desde {', '.join(ips)}",
                          "idp_signins", [s["event_id"] for s in signins if s.get("session_id") == sid], notable=True)

        # 3. MFA pattern: many timeouts/denials then an approval = fatigue
        mfa = Counter(str(s.get("mfa_result")) for s in signins if s.get("mfa_result"))
        rejected = mfa.get("denied", 0) + mfa.get("timeout", 0)
        if rejected >= 3:
            pack.find("RB-03.3 MFA", f"{user}: {rejected} notificaciones MFA rechazadas o sin respuesta y "
                      f"{mfa.get('approved', 0)} aprobadas en ±24 h", "idp_signins",
                      [s["event_id"] for s in signins if s.get("mfa_result") in ("denied", "timeout", "approved")][:15],
                      notable=mfa.get("approved", 0) > 0)

        # 5. What the session did after (mailbox rules, OAuth consent, new MFA, downloads, group changes)
        audit = [i["event"] | {"event_id": i["event_id"]} for i in
                 pack.timeline("RB-03.5 actividad de la cuenta después (24 h)", user, sources=["idp_audit", "ad_events"],
                               before_h=0, after_h=24)]
        risky = [a for a in audit if any(k in (str(a.get("operation", "")) + " " + str(a.get("event", ""))).casefold()
                                         for k in PERSISTENCE_OPS + ("download", "agreg", "added"))]
        if risky:
            ops = Counter(str(a.get("operation") or a.get("event")) for a in risky)
            # Rules and downloads are common; they matter when done from a suspicious origin. A new MFA
            # method or consent to an unverified app always matters.
            hot = [a for a in risky if str(a.get("src_ip")) in suspicious_ips
                   or "mfa" in str(a.get("operation", "")).casefold()
                   or ("consent" in str(a.get("operation", "")).casefold()
                       and str((a.get("details") or {}).get("publisher", "")).casefold() != "verificado")]
            pack.find("RB-03.5 acciones posteriores", f"{user}: {', '.join(f'{k} ×{v}' for k, v in ops.most_common(5))}"
                      + (f"; {len(hot)} desde un origen sospechoso o de persistencia" if hot else ""),
                      "idp_audit/ad_events", [a["event_id"] for a in (hot or risky)], notable=bool(hot))
