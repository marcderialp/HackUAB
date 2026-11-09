"""RB-05 Online store: web attacks, credential stuffing, account takeover, web shells
(UC-WEB-001..003, UC-EDR-009)."""
from __future__ import annotations

from collections import Counter

from triage import data
from triage.collectors.base import Pack, is_internal, local_str

FRONTENDS = ("WEB-ECOM01", "WEB-ECOM02", "WEB-ECOM03", "WEB-ECOM04")
WEB_PARENTS = ("nginx", "php-fpm", "java", "httpd", "w3wp")
FRAUD_EVENTS = ("email_change", "address_change", "giftcard_purchase", "password_change", "payment_method_added")


def collect(pack: Pack) -> None:
    ext_ips = [ip for ip in pack.ents.get("ips", []) if not is_internal(ip)]
    customers = list(pack.ents.get("customers", []))

    # 1. WAF: blocked or not, which paths, known vulnerabilities on the frontends
    for ip in ext_ips[:3]:
        waf = [e for e in pack.events("RB-05.1 peticiones WAF del origen (±2 h)", "waf", q=ip, before_h=2, after_h=2)
               if e.get("src_ip") == ip]
        if waf:
            actions = Counter(str(e.get("action")) for e in waf)
            ok_attacks = [e for e in waf if e.get("rule_id") and str(e.get("status")) == "200"]
            pack.find("RB-05.1 WAF", f"{ip}: {len(waf)} peticiones ({', '.join(f'{k} {v}' for k, v in actions.items())}); "
                      f"rutas: {', '.join(sorted({str(e.get('uri', ''))[:40] for e in waf})[:4])}", "waf",
                      [e["event_id"] for e in waf[:10]], notable=bool(ok_attacks))
            if ok_attacks:
                pack.find("RB-05.1 WAF", f"{len(ok_attacks)} peticiones con firma de ataque respondidas con 200",
                          "waf", [e["event_id"] for e in ok_attacks], notable=True)
    vulns = []
    for host in FRONTENDS:
        asset = pack.query("RB-05.1 vulnerabilidades del frontal", "get_asset", {"key": host},
                           lambda h=host: data.get_asset(h)) or {}
        vulns += [f"{host}: {v.get('id')} ({v.get('producto')}, {v.get('estado')})" for v in asset.get("vulnerabilities", [])
                  if v.get("estado") != "corregida"]
    if vulns:
        pack.find("RB-05.1 vulnerabilidades", "abiertas en los frontales: " + "; ".join(vulns), "vulnerabilidades.csv")

    # 2-3. Credential stuffing: how many logins SUCCEEDED, and what those accounts did next
    if pack.alert.get("rule_id") in ("UC-WEB-002", "UC-WEB-003") or customers:
        ips = set(ext_ips)
        auth = []
        for ip in sorted(ips)[:60]:
            auth += [e for e in pack.events("RB-05.2 accesos de clientes desde el origen (±1 h)", "ecom_auth", q=ip,
                                            before_h=1, after_h=1) if e.get("src_ip") == ip]
        for c in customers[:5]:
            auth += [e for e in pack.events("RB-05.3 accesos del cliente (±2 h)", "ecom_auth", q=c, before_h=2, after_h=2)
                     if e.get("customer_id") == c and e not in auth]
        ok = [e for e in auth if e.get("result") == "success"]
        if auth:
            fps = Counter(str(e.get("device_fp")) for e in auth)
            pack.find("RB-05.2 credential stuffing", f"{len(auth)} intentos, {len(ok)} correctos "
                      f"({len({e.get('customer_id') for e in ok})} cuentas); huellas {', '.join(list(fps)[:3])}",
                      "ecom_auth", [e["event_id"] for e in ok] or [e["event_id"] for e in auth[:5]], notable=bool(ok))
        for c in sorted({e.get("customer_id") for e in ok} | set(customers))[:12]:
            acct = [e for e in pack.events("RB-05.3 cambios en la cuenta tras el acceso (2 h)", "ecom_account", q=c,
                                           before_h=0.5, after_h=2) if e.get("customer_id") == c]
            fraud = [e for e in acct if e.get("event") in FRAUD_EVENTS]
            if fraud:
                seq = " > ".join(f"{e['event']} {local_str(e['timestamp'])}" for e in sorted(fraud, key=lambda x: x["timestamp"]))
                pack.find("RB-05.3 toma de cuenta", f"cliente {c}: {seq}", "ecom_account",
                          [e["event_id"] for e in fraud], notable=True)

    # 4. Web shell: did a frontend spawn a shell?
    shells = []
    for host in FRONTENDS:
        shells += [i for i in pack.timeline("RB-05.4 procesos lanzados por el servidor web (±2 h)", host,
                                            sources=["edr_events"], before_h=2, after_h=2)
                   if any(p in str(i["event"].get("parent_name", "")).casefold() for p in WEB_PARENTS)]
    if shells:
        pack.find("RB-05.4 web shell", f"{len(shells)} procesos lanzados por el servidor web en los frontales",
                  "edr_events", [i["event_id"] for i in shells], notable=True)
