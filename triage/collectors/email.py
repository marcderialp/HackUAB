"""RB-01 Phishing and malicious email (UC-EML-001..004)."""
from __future__ import annotations

from typing import Any

from triage.collectors.base import Pack, is_internal, local_str

SUSPICIOUS_UA = ("python-requests", "axios", "curl", "go-http-client", "bav2ropc")


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].casefold() if "@" in address else address.casefold()


def collect(pack: Pack) -> None:
    ev = pack.alert.get("evidence") or {}
    mids = list(pack.ents.get("message_ids", [])) or ([ev["message_id"]] if ev.get("message_id") else [])

    # 1. Sender: authentication, history, lookalike of a known supplier
    original = []
    for mid in mids[:3]:
        original += [e for e in pack.events("RB-01.1 correo original por message_id", "email", q=mid,
                                            before_h=24 * 7, after_h=24) if e.get("message_id") == mid]
    sender = ev.get("sender") or (original[0]["sender"] if original else "")
    # Is the sender suspicious? Clicks and reach only matter (are highlighted) for a suspicious sender:
    # 600 clicks on a legitimate newsletter are not an incident.
    suspicious: list[str] = []
    if original:
        o = original[0]
        failed = [k.upper() for k in ("spf", "dkim", "dmarc") if o.get(k) in ("fail", "softfail")]
        if failed:
            suspicious.append(f"falla {'/'.join(failed)}")
        if str(o.get("verdict")) in ("spam", "phishing", "suspicious", "malicious"):
            suspicious.append(f"veredicto «{o.get('verdict')}»")
        pack.find("RB-01.1 remitente", f"{o['sender']} → SPF {o.get('spf')}, DKIM {o.get('dkim')}, DMARC {o.get('dmarc')}; "
                  f"veredicto de la pasarela «{o.get('verdict')}», acción «{o.get('action')}»", "email",
                  [o["event_id"]], notable=bool(failed))
    if str(ev.get("rewrite_verdict_now", "")) == "phishing":
        suspicious.append("URL reclasificada como phishing")
    if sender and not _domain(sender).endswith("tarvia.example"):
        dom = _domain(sender)
        prior = [e for e in pack.events("RB-01.1 historial del dominio remitente", "email", q=dom,
                                        before_h=24 * 30, after_h=0)
                 if _domain(e.get("sender", "")) == dom and e.get("message_id") not in mids]
        if not prior:
            suspicious.append("dominio sin historial")
        pack.find("RB-01.1 remitente", f"{len(prior)} correos previos del dominio {dom} en 30 días"
                  + (" (dominio sin historial)" if not prior else ""), "email",
                  [e["event_id"] for e in prior[:5]], notable=not prior)
    legit = ev.get("legit_supplier_domain")
    if legit and sender and _domain(sender) != legit.casefold():
        suspicious.append(f"imita a {legit}")
        pack.find("RB-01.1 suplantación", f"el remitente {sender} imita al proveedor legítimo {legit}", "alerta",
                  notable=True)
    if any(i.get("tip") and i["tip"].get("reputation") == "malicious" for i in pack.intel):
        suspicious.append("indicador malicioso en el TIP")
    pack.find("RB-01.1 valoración del remitente",
              ("remitente sospechoso: " + ", ".join(suspicious)) if suspicious
              else "remitente sin señales de sospecha (autenticación correcta, con historial, sin TI)",
              "email", notable=bool(suspicious))

    # 2. URLs and attachments are covered by the common intel (TIP, GeoIP, sandbox); add the delivery facts
    if original:
        o = original[0]
        if o.get("attachments"):
            pack.find("RB-01.2 adjuntos", f"adjuntos: {', '.join(str(a.get('name', a)) if isinstance(a, dict) else str(a) for a in o['attachments'])}",
                      "email", [o["event_id"]])
        if o.get("urls"):
            pack.find("RB-01.2 URLs", f"{len(o['urls'])} URL(s) en el correo", "email", [o["event_id"]])

    # 3. Scope: who else received mail from the same sender
    if sender:
        same = [e for e in pack.events("RB-01.3 alcance: mismo remitente", "email", q=sender,
                                       before_h=24 * 3, after_h=24 * 3) if e.get("sender") == sender]
        rcpts = sorted({r for e in same for r in e.get("recipients", [])})
        delivered = sum(1 for e in same if e.get("action") == "delivered")
        if same:
            pack.find("RB-01.3 alcance", f"{len(same)} correos de {sender} a {len(rcpts)} buzones en ±3 días "
                      f"({delivered} entregados): purgar debe cubrirlos todos", "email",
                      [e["event_id"] for e in same[:10]], notable=len(rcpts) > 5 and bool(suspicious))

    # 4. Interaction: clicks, downloads, execution, sign-ins after
    clicks = []
    for mid in mids[:3]:
        clicks += [e for e in pack.events("RB-01.4 clics por message_id", "email_clicks", q=mid, before_h=24,
                                          after_h=24 * 3) if e.get("message_id") == mid]
    domains = [d for d in pack.ents.get("domains", []) if not d.endswith("tarvia.example")]
    for dom in domains[:3]:
        clicks += [e for e in pack.events("RB-01.4 clics al dominio", "email_clicks", q=dom, before_h=24,
                                          after_h=24 * 3) if e not in clicks]
    clickers = sorted({e.get("user") for e in clicks if e.get("user")})
    if clicks:
        allowed = sum(1 for e in clicks if e.get("action") == "allowed")
        pack.find("RB-01.4 interacción", f"{len(clicks)} clics de {len(clickers)} usuarios ({allowed} permitidos): "
                  f"{', '.join(clickers[:8])}", "email_clicks", [e["event_id"] for e in clicks],
                  notable=bool(suspicious))
    else:
        pack.find("RB-01.4 interacción", "ningún clic registrado en los enlaces del correo", "email_clicks")
    visits = []
    for dom in domains[:3]:
        visits += [e for e in pack.events("RB-01.4 navegación al dominio", "proxy", q=dom, before_h=24, after_h=24 * 3)
                   if dom in str(e.get("domain", ""))]
    if visits:
        hosts = sorted({str(e.get("hostname")) for e in visits})
        paths = sorted({str(e.get("url", "")).split("?")[0][-40:] for e in visits})[:5]
        pack.find("RB-01.4 interacción", f"{len(visits)} peticiones web al dominio desde {', '.join(hosts[:6])}: "
                  f"{'; '.join(paths)}", "proxy", [e["event_id"] for e in visits], notable=bool(suspicious))
    for h in pack.ents.get("hashes", [])[:3]:
        execs = [i for i in pack.timeline("RB-01.4 ejecución del adjunto", h, sources=["edr_events"],
                                          before_h=1, after_h=24 * 3)]
        if execs:
            pack.find("RB-01.4 ejecución", f"el adjunto aparece en {len(execs)} eventos EDR "
                      f"({', '.join(sorted({i['event'].get('hostname', '?') for i in execs}))})", "edr_events",
                      [i["event_id"] for i in execs], notable=True)
    for user in (clickers or [u for u in pack.ents.get("users", [])])[:5]:
        odd = unusual_signins(pack, user, "RB-01.4 inicios de sesión después", after_h=24)
        if odd:
            s = odd[0]
            pack.find("RB-01.4 sesión posterior", f"{user}: inicio de sesión correcto desde {s.get('src_ip')} "
                      f"({s.get('country')}, UA «{str(s.get('user_agent'))[:30]}», dispositivo "
                      f"{'conforme' if s.get('device_compliant') else 'no conforme'}) a las {local_str(s['timestamp'])}",
                      "idp_signins", [x["event_id"] for x in odd], notable=True)

    # 5. Payment-change requests (UC-EML-004): structured keys only
    if ev.get("new_iban_country") or ev.get("amount_mentioned"):
        pack.find("RB-01.5 petición de pago", f"petición de cambio de cuenta bancaria: importe "
                  f"{ev.get('amount_mentioned', '?')}, IBAN de {ev.get('new_iban_country', '?')}; verificar con el "
                  "proveedor por otro canal y retener el pago (RB-01)", "alerta", notable=True)


def unusual_signins(pack: Pack, user: str, step: str, before_h: float = 0, after_h: float = 24
                    ) -> list[dict[str, Any]]:
    """Successful sign-ins from an IP the user hasn't used in the previous 14 days, with a non-browser
    client or a non-compliant device (the AiTM / stolen-session pattern of RB-01 and RB-03)."""
    history = pack.timeline(f"{step} (historial 14 días)", user, sources=["idp_signins"], before_h=24 * 14, after_h=0)
    known = {i["event"].get("src_ip") for i in history if i["event"].get("result") == "success"}
    recent = [i["event"] | {"event_id": i["event_id"]}
              for i in pack.timeline(step, user, sources=["idp_signins"], before_h=before_h, after_h=after_h)]
    return [s for s in recent if s.get("result") == "success" and s.get("src_ip") not in known
            and not is_internal(str(s.get("src_ip", "")))
            and (any(k in str(s.get("user_agent", "")).casefold() for k in SUSPICIOUS_UA)
                 or not s.get("device_compliant", True))]
