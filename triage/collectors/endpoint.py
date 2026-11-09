"""RB-02 Malware and execution on the endpoint (UC-EDR-001..008, 010-012)."""
from __future__ import annotations

from collections import Counter

from triage import data
from triage.collectors.base import Pack, is_internal, local_str

ADMIN_PORTS = {"445", "3389", "5985", "135", "22", "1433"}
ODD_PATHS = ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\programdata\\", "/tmp/", "\\users\\public\\")
PERSISTENCE = ("registry_set", "service_install", "scheduled_task", "cron")
SENSITIVE = ("lsass", "login data", "cookies", "tarviapos")


def collect(pack: Pack) -> None:
    ev = pack.alert.get("evidence") or {}
    hosts = pack.ents.get("hosts", [])
    host = hosts[-1] if hosts else None
    if not host:
        pack.find("RB-02", "la alerta no indica equipo: no se puede revisar el árbol de procesos", "alerta")
        return

    # 1. Process tree around the event: parent, children, signer, path
    around = [i["event"] | {"event_id": i["event_id"]} for i in
              pack.timeline("RB-02.1 árbol de procesos (±30 min)", host, sources=["edr_events"], before_h=0.5,
                            after_h=0.5)]
    procs = [e for e in around if e.get("event_type") == "process_start"]
    unsigned = [e for e in procs if not e.get("signer")]
    odd_path = [e for e in procs if any(p in str(e.get("process_path", "")).casefold() for p in ODD_PATHS)]
    if procs:
        chain = [f"{e.get('parent_name') or '?'} → {e.get('process_name')}" for e in procs[:8]]
        pack.find("RB-02.1 árbol de procesos", f"{len(procs)} procesos en {host} ±30 min: {'; '.join(chain)}",
                  "edr_events", [e["event_id"] for e in procs])
    if unsigned:
        pack.find("RB-02.1 firma", f"procesos sin firma: {', '.join(sorted({str(e.get('process_name')) for e in unsigned}))}",
                  "edr_events", [e["event_id"] for e in unsigned], notable=True)
    if odd_path:
        pack.find("RB-02.1 ruta", f"ejecutables en rutas de usuario o temporales: "
                  f"{', '.join(sorted({str(e.get('process_path')) for e in odd_path}))[:200]}", "edr_events",
                  [e["event_id"] for e in odd_path], notable=True)
    change = (pack.context.get("flags") or [{}])[0]
    if change.get("applies"):
        pack.find("RB-02.1 software aprobado", f"cubierto por un cambio aprobado: {change.get('detail')}",
                  "calendario_cambios.csv")

    # 3. EDR action
    action = ev.get("edr_action") or ev.get("action")
    if action:
        # "detected_only" means nothing stopped it: it matters when the process itself looks bad.
        pack.find("RB-02.3 acción del EDR", f"acción: {action}" + (f"; ejecutado: {ev['executed']}" if "executed" in ev else ""),
                  "alerta", notable=str(action) == "detected_only" and bool(unsigned or odd_path))

    # 4. Activity after (24 h): persistence, credential access, network
    after = [i["event"] | {"event_id": i["event_id"], "source": i["source"]} for i in
             pack.timeline("RB-02.4 actividad posterior en el equipo (24 h)", host,
                           sources=["edr_events", "firewall", "proxy", "dns"], before_h=0, after_h=24)]
    persist = [e for e in after if e.get("event_type") in PERSISTENCE]
    if persist:
        pack.find("RB-02.4 persistencia", f"{len(persist)} eventos de persistencia "
                  f"({', '.join(sorted({str(e.get('event_type')) for e in persist}))})", "edr_events",
                  [e["event_id"] for e in persist], notable=True)
    window = around + [e for e in after if e not in around]
    creds = [e for e in window if e.get("source", "edr_events") == "edr_events"
             and any(s in (str(e.get("details", "")) + " " + str(e.get("command_line", ""))).casefold()
                     for s in SENSITIVE + ("comsvcs", "minidump", "procdump"))]
    if creds:
        pack.find("RB-02.4 credenciales", f"{len(creds)} accesos a memoria o almacenes sensibles (LSASS, navegador, TPV)",
                  "edr_events", [e["event_id"] for e in creds], notable=True)
    agent = [e for e in after if e.get("event_type") == "agent_status"]
    if agent:
        pack.find("RB-02.4 agente EDR", f"{len(agent)} cambios de estado del agente EDR"
                  + (" (dentro de un cambio aprobado)" if change.get("applies") else ""), "edr_events",
                  [e["event_id"] for e in agent], notable=not change.get("applies"))
    fw = [e for e in after if e.get("source") == "firewall"]
    lateral = [e for e in fw if is_internal(str(e.get("dst_ip", ""))) and str(e.get("dst_port")) in ADMIN_PORTS]
    if lateral:
        dsts = Counter(str(e.get("dst_ip")) for e in lateral)
        pack.find("RB-02.4 movimiento lateral", f"{len(lateral)} conexiones a puertos de administración "
                  f"({', '.join(sorted({str(e.get('dst_port')) for e in lateral}))}) hacia {len(dsts)} equipos internos",
                  "firewall", [e["event_id"] for e in lateral], notable=len(dsts) > 3)
    outbound = sorted({str(e.get("dst_ip")) for e in fw if e.get("dst_ip") and not is_internal(str(e["dst_ip"]))})
    bad = []
    for ip in outbound[:30]:
        tip = (pack.query("RB-02.4 reputación de destinos", "get_intel", {"indicator": ip},
                          lambda i=ip: data.get_intel(i)) or {}).get("tip")
        if tip and tip.get("reputation") == "malicious":
            bad.append(f"{ip} ({tip.get('malware_family')})")
    if bad:
        pack.find("RB-02.4 C2", f"conexiones a IPs maliciosas del TIP: {', '.join(bad)}", "firewall/ti_feed", notable=True)

    # 5. Users on the host
    users = pack.query("RB-02.5 usuarios en el equipo", "users_for_host", {"host": host},
                       lambda: data.users_for_host(host, *pack.window(24, 24))) or []
    if users:
        names = [str(u.get("user") or u.get("entity_value") or u.get("value")) for u in users[:6]]
        pack.find("RB-02.5 usuarios", f"usuarios vistos en {host} (±24 h): {', '.join(names)}", "logs",
                  notable=any(n.startswith("adm.") for n in names))
    first = (procs or around or [{}])[0]
    if first.get("timestamp"):
        pack.find("RB-02 hora", f"actividad desde las {local_str(first['timestamp'])} (hora local)", "edr_events")
