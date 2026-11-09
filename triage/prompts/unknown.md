# Sin especialista: runbook no reconocido
Esta alerta no tiene un runbook reconocido (falta o no es uno de RB-01 a RB-10), así que no hay comprobaciones específicas recopiladas para ella.

- Aplica solo las reglas generales del rol y la política.
- No asumas qué comprobaciones se han hecho: razona únicamente con lo que contiene el paquete.
- Si la evidencia no basta para un veredicto argumentado, usa `needs_more_info`, explica en `open_questions` qué faltaría comprobar y sugiere `investigate`.
