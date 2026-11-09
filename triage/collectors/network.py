"""RB-09 Network: C2, scans and lateral movement (UC-NET-001..006) and RB-08 OT (UC-OT-001)."""
from __future__ import annotations

from collections import Counter

from triage import data
from triage.collectors.base import Pack, is_internal, local_str

OT_PORTS = {"502", "44818"}



YOUNG_DOMAIN_DAYS = 30


def _young_domain(age) -> bool:
    """A domain registered less than 30 days ago (0 days counts: `age or 9999` treated it as old)."""
    try:
        return age is not None and float(age) < YOUNG_DOMAIN_DAYS
    except (TypeError, ValueError):
        return False

def collect(pack: Pack) -> None:
    ev = pack.alert.get("evidence") or {}
    rule = pack.alert.get("rule_id", "")
    hosts = pack.ents.get("hosts", [])

    # 1. Domains: how many internal hosts talk to it, since when, through which process
    domains = [d for d in pack.ents.get("domains", []) if not d.endswith("tarvia.example")]
    for dom in domains[:3]:
        target = ev.get("parent_domain") or dom
        dns = pack.events("RB-09.1 consultas DNS al dominio (±7 días)", "dns", q=target, before_h=24 * 7, after_h=24)
        dns = [e for e in dns if str(e.get("query", "")).casefold().endswith(target.casefold())]
        clients = Counter(str(e.get("hostname") or e.get("src_ip")) for e in dns)
        first = min((e["timestamp"] for e in dns), default=None)
        if dns:
            pack.find("RB-09.1 difusión", f"{target}: {len(dns)} consultas desde {len(clients)} equipos "
                      f"({', '.join(list(clients)[:5])}); primera {local_str(first)}", "dns",
                      [e["event_id"] for e in dns[:10]])
        long_labels = [e for e in dns if len(str(e.get("query", "")).split(".")[0]) > 40]
        if long_labels:
            txt = sum(1 for e in long_labels if e.get("qtype") == "TXT")
            per_host = Counter(str(e.get("hostname")) for e in long_labels)
            # Anti-spam lookups also use long labels; a tunnel shows TXT queries or high volume per host
            # (UC-NET-006: >200 in 1 h).
            tunnel = txt > 0 or per_host.most_common(1)[0][1] >= 100
            pack.find("RB-09.1 túnel DNS", f"{len(long_labels)} consultas con subdominios >40 caracteres "
                      f"({txt} TXT) desde {', '.join(f'{h} ×{n}' for h, n in per_host.most_common(3))}",
                      "dns", [e["event_id"] for e in long_labels[:10]], notable=tunnel)
        procs = pack.query("RB-09.1 proceso detrás", "mentions", {"text": dom, "sources": ["edr_events"]},
                           lambda d=dom: data.mentions(d, *pack.window(24 * 7, 24), sources=["edr_events"], limit=50)) or {}
        names = Counter(str(i["event"].get("process_name")) for i in procs.get("items", []))
        if names:
            pack.find("RB-09.1 proceso", f"procesos que mencionan {dom}: {', '.join(f'{k} ×{v}' for k, v in names.most_common(4))}",
                      "edr_events", [i["event_id"] for i in procs.get("items", [])][:10])
    if ev.get("mean_interval_s"):
        pack.find("RB-09.1 beaconing", f"intervalo medio {ev.get('mean_interval_s')} s"
                  + (f", desviación {ev.get('stddev_interval_s')} s" if ev.get("stddev_interval_s") else "")
                  + (f", dominio de {ev.get('domain_age_days')} días" if ev.get("domain_age_days") is not None else ""),
                  "alerta", notable=_young_domain(ev.get("domain_age_days")))

    # 2. External IPs: firewall flows (TI already in common)
    for ip in [i for i in pack.ents.get("ips", []) if not is_internal(i)][:3]:
        flows = pack.events("RB-09.2 flujos hacia la IP", "firewall", q=ip, before_h=24, after_h=24)
        flows = [e for e in flows if e.get("dst_ip") == ip or e.get("src_ip") == ip]
        if flows:
            allowed = sum(1 for e in flows if e.get("action") == "allow")
            pack.find("RB-09.2 flujos", f"{ip}: {len(flows)} conexiones ({allowed} permitidas), "
                      f"{sum(int(e.get('bytes') or 0) for e in flows)} bytes", "firewall",
                      [e["event_id"] for e in flows[:10]], notable=allowed > 0)

    # 3. Scans: fan-out from the source in a short window
    if rule == "UC-NET-003" and hosts:
        src = data.get_asset(hosts[0])
        if src:
            fw = pack.events("RB-09.3 abanico del escaneo (±15 min)", "firewall", q=src["ip"], before_h=0.25, after_h=0.25)
            fw = [e for e in fw if e.get("src_ip") == src["ip"]]
            authorized = bool((pack.context.get("flags") or [{}])[0].get("applies"))
            pack.find("RB-09.3 escaneo", f"{hosts[0]} ({src.get('type')}): {len({e.get('dst_ip') for e in fw})} destinos y "
                      f"{len({e.get('dst_port') for e in fw})} puertos en ±15 min; zonas "
                      f"{', '.join(sorted({str(e.get('zone_dst')) for e in fw}))}"
                      + ("" if authorized else "; no es el escáner autorizado en su ventana"), "firewall",
                      [e["event_id"] for e in fw[:10]], notable=not authorized)

    # 4. Lateral movement: what happened on the destination
    if rule == "UC-NET-004" or ev.get("method"):
        dst = ev.get("dst") or (hosts[1] if len(hosts) > 1 else None)
        if dst:
            on_dst = [i["event"] | {"event_id": i["event_id"]} for i in
                      pack.timeline("RB-09.4 actividad en el destino (2 h)", dst, sources=["edr_events"], before_h=0.25,
                                    after_h=2)]
            svc = [e for e in on_dst if e.get("event_type") == "service_install"]
            unsigned = [e for e in on_dst if e.get("event_type") == "process_start" and not e.get("signer")]
            pack.find("RB-09.4 destino", f"{dst}: {len(svc)} servicios instalados, {len(unsigned)} procesos sin firma "
                      f"en 2 h", "edr_events", [e["event_id"] for e in svc + unsigned], notable=bool(unsigned))

    # RB-08 OT: flows into the OT zone from the source
    if rule.startswith("UC-OT") or ev.get("dst_zone") == "LOGISTICS-OT":
        src_name = ev.get("src") or (hosts[0] if hosts else None)
        src = data.get_asset(src_name) if src_name else None
        if src:
            fw = pack.events("RB-08.2 flujos hacia OT (±1 h)", "firewall", q=src["ip"], before_h=1, after_h=1)
            ot = [e for e in fw if e.get("zone_dst") == "LOGISTICS-OT"]
            ports = Counter(str(e.get("dst_port")) for e in ot)
            pack.find("RB-08.2 protocolos", f"{src_name} → OT: {len(ot)} conexiones, puertos "
                      f"{', '.join(f'{p} ×{n}' for p, n in ports.most_common())}; reglas "
                      f"{', '.join(sorted({str(e.get('rule')) for e in ot}))}", "firewall",
                      [e["event_id"] for e in ot[:10]], notable=bool(set(ports) - OT_PORTS))
            prior = [i for i in pack.timeline("RB-08.3 actividad previa en el origen (24 h)", src_name,
                                              sources=["edr_events"], before_h=24, after_h=0)
                     if not i["event"].get("signer") and i["event"].get("event_type") == "process_start"]
            if prior:
                pack.find("RB-08.3 origen", f"{src_name}: {len(prior)} procesos sin firma en las 24 h previas",
                          "edr_events", [i["event_id"] for i in prior], notable=True)
        pack.find("RB-08", "OT: nunca aislar ni bloquear desde el SOC; solo escalar a N2 y Operaciones", "RB-08.md")
