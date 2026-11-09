# Tarvia (empresa ficticia del conjunto de datos de prueba)

> Descripción inventada para los datos de prueba de este repositorio, que genera `tools/make_mock_data.py`. No es el material del reto: el conjunto de datos original es privado.

Tarvia es un minorista ficticio de moda y hogar con sede en Barcelona. Vende en su tienda online y su app, donde atiende el asistente de compra «Vela», y en ocho tiendas físicas. Prepara los pedidos en un centro logístico en Martorell, con un clasificador automático.

## Qué importa proteger

1. La venta online (WEB-ECOM01..04) y los cobros (PAY-GW01).
2. Los datos de clientes: el CRM (SQL-CRM01) y sus exportaciones en el bucket `tarvia-crm-exports`.
3. La logística: el WMS (WMS01) y el clasificador (PLC-SORT01..03 y HMI-SORT01).

## Reglas internas

Son las reglas que comprueba el código (`triage/context.py`):

- Las cuentas de administración (`adm.*`) solo se usan desde JUMP01.
- A la red OT (LOGISTICS-OT) solo se entra desde ENG-WS01 y WMS01, salvo con un cambio aprobado.
- El proveedor del WMS (`ext.logisoft`) trabaja de lunes a viernes de 08:00 a 18:00, por VPN y JUMP01, desde su IP corporativa.
- La única herramienta de acceso remoto aprobada es TeamViewer Corporate, que gestiona IT.
- `svc_backup` está excluida de MFA por el agente de copias (riesgo aceptado).
- SCCM (`svc_sccm`) y el escáner de vulnerabilidades (`svc_scanner`) aparecen en los logs como su herramienta: CcmExec y NESSUS01.
