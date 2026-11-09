"""Light collectors for the low-volume runbooks, where the deep-dive agent takes over for anything else:
RB-04 DLP, RB-06 cloud, RB-07 AI assistant (Vela), RB-10 CI/CD."""
from __future__ import annotations

from collections import Counter

from triage import data
from triage.collectors.base import Pack, is_internal, local_str

ARCHIVERS = ("7z", "winrar", "rar.exe", "zip", "tar ", "compress-archive")
IAM_WRITES = ("CreateUser", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy", "CreateLoginProfile",
              "AttachRolePolicy", "UpdateAssumeRolePolicy")
SECRET_VARS = ("AWS_", "NPM_TOKEN", "TOKEN", "SECRET", "PASSWORD")


def rb04_dlp(pack: Pack) -> None:
    ev = pack.alert.get("evidence") or {}
    for user in pack.ents.get("users", [])[:2]:
        dlp = [e for e in pack.events("RB-04.1 otros envíos DLP del usuario (±7 días)", "dlp", q=user,
                                      before_h=24 * 7, after_h=24 * 2) if e.get("user") == user]
        dests = Counter(str(e.get("destination")) for e in dlp)
        if dlp:
            pack.find("RB-04.1 volumen", f"{user}: {len(dlp)} eventos DLP en ±7 días; destinos "
                      f"{', '.join(f'{d} ×{n}' for d, n in dests.most_common(4))}; "
                      f"{sum(int(e.get('file_size') or 0) for e in dlp) // 1_000_000} MB", "dlp",
                      [e["event_id"] for e in dlp[:10]])
        host = (pack.ents.get("hosts") or [None])[0]
        sql = [e for e in pack.events("RB-04.4 consultas masivas previas (24 h)", "sql_audit", q=host or user,
                                      before_h=24, after_h=1)
               if int(e.get("rows_returned") or 0) > 10_000]
        if sql:
            top = f"{max(int(e['rows_returned']) for e in sql):,}".replace(",", ".")
            pack.find("RB-04.4 consultas masivas", f"{len(sql)} consultas con más de 10.000 filas (máx. {top}) a "
                      f"{', '.join(sorted({str(e.get('object')) for e in sql}))}",
                      "sql_audit", [e["event_id"] for e in sql], notable=True)
        if host:
            arch = [i for i in pack.timeline("RB-04.4 compresión en el equipo (24 h)", host, sources=["edr_events"],
                                             before_h=24, after_h=1)
                    if any(a in str(i["event"].get("command_line", "")).casefold() + " " +
                           str(i["event"].get("process_name", "")).casefold() for a in ARCHIVERS)]
            if arch:
                pack.find("RB-04.4 compresión", f"{len(arch)} procesos de compresión en {host}", "edr_events",
                          [i["event_id"] for i in arch], notable=True)
    if ev.get("file_encrypted"):
        pack.find("RB-04.1 cifrado", "fichero cifrado (no inspeccionable): cuenta como sospechoso (RB-04)", "alerta",
                  notable=True)
    matches = ev.get("matches") or ev.get("personal_data_matches")
    if matches:
        pack.find("RB-04.1 datos", f"coincidencias de datos personales: {matches}", "alerta", notable=True)


IAC_AGENTS = ("terraform", "pulumi", "aws-cdk", "cloudformation")


def _known_pipeline(pack: Pack, term: str, trail: list[dict]) -> None:
    """RB-06.5 "pipeline de Terraform conocido", checked in code: every cloud event the alert points at was
    made by infrastructure as code from an internal host of the CMDB, and that host is the only place this
    identity works from in the window. The finding is a code-verified authorization (prompts/builder.py
    AUTHORIZING_CHECKS); without it a risky cloud change is never BTP."""
    related = set(pack.alert.get("related_events") or [])
    changes = [e for e in trail if e.get("event_id") in related]
    if not changes:
        return
    origins = {str(e.get("sourceIPAddress")) for e in trail}
    if len(origins) != 1 or not all(is_internal(ip) for ip in origins):
        return
    if not all(str(e.get("userAgent", "")).casefold().startswith(IAC_AGENTS) for e in changes):
        return
    ip = origins.pop()
    host = data.get_asset(ip)
    if not host:
        return
    pack.find("RB-06.5 pipeline conocido",
              f"{term}: {', '.join(sorted({str(e.get('eventName')) for e in changes}))} hecho por "
              f"{str(changes[0].get('userAgent'))[:30]} desde {host.get('hostname')} ({host.get('type')}, {ip}), "
              f"el único origen de la identidad en ±7 días ({len(trail)} eventos)",
              "cloudtrail", [e["event_id"] for e in changes])


def rb06_cloud(pack: Pack) -> None:
    ev = pack.alert.get("evidence") or {}
    cloud = (pack.alert.get("entities") or {}).get("cloud") or {}
    key = cloud.get("access_key")
    identity = cloud.get("identity")
    ips = [ip for ip in pack.ents.get("ips", []) if not is_internal(ip)]
    term = key or identity
    if term:
        trail = pack.events("RB-06.1 uso de la identidad o clave (±7 días)", "cloudtrail", q=term,
                            before_h=24 * 7, after_h=24 * 2)
        by_src = Counter((str(e.get("sourceIPAddress")), str(e.get("userAgent", ""))[:25]) for e in trail)
        pack.find("RB-06.1 orígenes habituales", f"{term}: " + "; ".join(f"{ip} ({ua}) ×{n}" for (ip, ua), n in by_src.most_common(4)),
                  "cloudtrail", [e["event_id"] for e in trail[:5]])
        _known_pipeline(pack, term, trail)
        for ip in ips[:2]:
            mine = [e for e in trail if e.get("sourceIPAddress") == ip]
            if mine:
                first = min(e["timestamp"] for e in mine)
                calls = Counter(str(e.get("eventName")) for e in mine)
                pack.find("RB-06.2 origen nuevo", f"{ip}: primer uso {local_str(first)}; llamadas "
                          f"{', '.join(f'{k} ×{v}' for k, v in calls.most_common(6))}", "cloudtrail",
                          [e["event_id"] for e in mine[:10]], notable=True)
    for ip in ips[:2]:
        trail = pack.events("RB-06.3 escrituras IAM y descargas desde el origen (±48 h)", "cloudtrail", q=ip,
                            before_h=48, after_h=48)
        iam = [e for e in trail if e.get("eventName") in IAM_WRITES]
        gets = Counter(str((e.get("requestParameters") or {}).get("bucketName")) for e in trail
                       if e.get("eventName") == "GetObject")
        if iam:
            pack.find("RB-06.3 persistencia", f"{ip}: {', '.join(sorted({str(e['eventName']) for e in iam}))}",
                      "cloudtrail", [e["event_id"] for e in iam], notable=True)
        if gets:
            pack.find("RB-06.4 datos", f"{ip}: GetObject " + ", ".join(f"{b} ×{n}" for b, n in gets.most_common(3)),
                      "cloudtrail", notable=sum(gets.values()) > 100)
    if ev.get("bucket_classification") or ev.get("objects_prefix"):
        pack.find("RB-06.4 datos", f"bucket {ev.get('bucket_classification', '?')}, prefijo {ev.get('objects_prefix', '?')}, "
                  f"{ev.get('bytes_estimated', '?')}", "alerta", notable=True)


def rb07_ai(pack: Pack) -> None:
    ev = pack.alert.get("evidence") or {}
    session = ev.get("ai_session") or (pack.alert.get("entities") or {}).get("ai_session")
    sessions = [session] if isinstance(session, str) else []
    if not sessions:
        sessions = list(pack.ents.get("sessions", []))
    for sid in sessions[:2]:
        events = [e for e in pack.events("RB-07.1 sesión completa del asistente", "ai_gateway", q=sid,
                                         before_h=24, after_h=24) if e.get("session_id") == sid]
        if not events:
            continue
        auth = {e.get("customer_id") for e in events}
        other = [e for e in events for t in e.get("tool_calls", []) or []
                 if str((t.get("args") or {}).get("customer_id", "")) not in auth | {""}]
        blocked = [e for e in events if (e.get("guardrail") or {}).get("action") == "blocked"]
        silent = [e for e in events if not (e.get("guardrail") or {}).get("triggered")]
        pack.find("RB-07.1 sesión", f"sesión {sid}: {len(events)} mensajes, {len(blocked)} bloqueados por el "
                  f"guardarraíl, {len(silent)} sin disparar el guardarraíl", "ai_gateway", [e["event_id"] for e in events])
        if other:
            pack.find("RB-07.2 otros clientes", f"{len(other)} llamadas a herramientas con identificadores de otro cliente",
                      "ai_gateway", [e["event_id"] for e in other], notable=True)
        # 3. A leak can happen in a message that did NOT trigger an alert: show those responses as data
        for e in silent:
            pack.find("RB-07.3 respuesta sin alerta", f"{local_str(e['timestamp'])}: respuesta del modelo: "
                      f"«{str(e.get('response_summary', ''))[:160]}» (revisar si filtra datos o información interna)",
                      "ai_gateway", [e["event_id"]], notable=True)
        # 4. Same IP in other sessions
        for ip in {e.get("src_ip") for e in events if e.get("src_ip")}:
            others = {e.get("session_id") for e in pack.events("RB-07.4 otras sesiones de la misma IP (±7 días)",
                                                                   "ai_gateway", q=ip, before_h=24 * 7, after_h=24 * 7)
                      if e.get("src_ip") == ip} - {sid}
            if others:
                pack.find("RB-07.4 misma IP", f"{ip} también en las sesiones {', '.join(sorted(map(str, others))[:5])}",
                          "ai_gateway", notable=True)


def rb10_cicd(pack: Pack) -> None:
    ev = pack.alert.get("evidence") or {}
    build = ev.get("build")
    pipeline = ev.get("pipeline")
    if build or pipeline:
        steps = [e for e in pack.events("RB-10.4 pasos del build", "cicd_builds", q=build or pipeline, before_h=2,
                                        after_h=6) if (not build or e.get("build_id") == build)]
        if steps:
            done = ", ".join(f"{e.get('step')}={e.get('status')}" for e in steps[:6])
            deployed = any(e.get("step") == "deploy" and e.get("status") == "ok" for e in steps)
            pack.find("RB-10.4 despliegue", f"{build or pipeline}: pasos {done}"
                      + ("; el build llegó a desplegarse" if deployed else ""), "cicd_builds",
                      [e["event_id"] for e in steps], notable=deployed and bool(ev.get("expected_package")))
    secrets = [v for v in ev.get("env_vars_read", []) or [] if any(s in str(v) for s in SECRET_VARS)]
    if secrets:
        pack.find("RB-10.3 secretos", f"el script leyó {', '.join(secrets)}: rotar todas las credenciales del build",
                  "alerta", notable=True)
        # Later use of those keys from outside the runner
        runner_ips = {a["ip"] for a in pack.assets if a.get("ip")}
        trail = pack.events("RB-10.4 uso posterior de claves desde fuera del runner (72 h)", "cloudtrail",
                            before_h=0, after_h=72)
        outside = [e for e in trail if e.get("sourceIPAddress") not in runner_ips
                   and not is_internal(str(e.get("sourceIPAddress", "")))
                   and "console" not in str(e.get("userAgent", "")).casefold()]
        seen = Counter((str(e.get("sourceIPAddress")), str((e.get("userIdentity") or {}).get("accessKeyId"))) for e in outside)
        if seen:
            pack.find("RB-10.4 uso de claves", "en 72 h, uso de claves desde fuera del runner: "
                      + "; ".join(f"{ip} ({k}) ×{n}" for (ip, k), n in seen.most_common(4)), "cloudtrail",
                      [e["event_id"] for e in outside[:10]], notable=True)
    if ev.get("registry") or ev.get("expected_package"):
        pack.find("RB-10.2 registro", f"paquete {ev.get('package')}"
                  + (f" desde {ev['registry']}" if ev.get("registry") else "")
                  + (f"; se esperaba {ev['expected_package']} (posible dependency confusion)" if ev.get("expected_package") else ""),
                  "alerta", notable=bool(ev.get("expected_package")))
