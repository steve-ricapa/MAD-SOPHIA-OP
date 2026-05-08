# Plan de Trabajo: Validación de Versiones y Compatibilidad

## Objetivo
Confirmar que InsightVM, OpenVAS, Nessus, Uptime Kuma y Zabbix estén en versiones objetivo, sean compatibles con su entorno y operen sin errores post-actualización.

## Versiones objetivo
- InsightVM `8.43.0`
- OpenVAS `26.13.0`
- Nessus `10.12.0`
- Uptime Kuma `2.2.1`
- Zabbix `7.4.9`

---

## Fase 1 - Levantamiento de línea base
**Duración sugerida:** 0.5-1 día  
**Responsable:** Infra + Seguridad

### Actividades
1. Inventariar por herramienta:
   - versión instalada actual
   - servidor/VM, SO y versión
   - motor DB y versión (si aplica)
   - integraciones activas (LDAP/AD, SMTP, webhooks, API, SIEM, agentes/proxies/sensores)
2. Consolidar en una matriz única (Excel/Sheets/Confluence).

### Entregable
- Matriz de línea base con estado actual por componente.

### Criterio de salida
- 100% de herramientas inventariadas con datos completos.

---

## Fase 2 - Validación documental oficial (compatibilidad)
**Duración sugerida:** 1 día  
**Responsable:** Seguridad + Arquitectura

### Actividades
1. Revisar documentación oficial por producto:
   - requisitos de SO/CPU/RAM
   - compatibilidad de DB y versiones soportadas
   - compatibilidad de agentes/proxies/sensores/plugins
   - notas de versión de la versión exacta objetivo
   - breaking changes, deprecaciones y prerequisitos
2. Registrar hallazgos con evidencia (URL + fecha de consulta).
3. Marcar gaps:
   - incompatibilidades duras (bloqueantes)
   - riesgos (warning) y mitigaciones

### Entregable
- Matriz de compatibilidad con columna `Compatible: Sí/No/Condicionado`.

### Criterio de salida
- Cada producto con validación documentada y decisión técnica.

---

## Fase 3 - Verificación técnica en plataforma
**Duración sugerida:** 1 día  
**Responsable:** Operaciones + Seguridad

### Actividades por herramienta
1. Confirmar versión en runtime (UI/API/CLI).
2. Validar salud del servicio:
   - servicio activo
   - consumo normal de recursos
   - conectividad a DB/servicios dependientes
3. Revisar logs (últimas 24-72h):
   - `error`, `failed`, `exception`, `migration`, `deprecated`, `schema`
4. Prueba funcional controlada:
   - InsightVM/OpenVAS/Nessus: escaneo de prueba, resultados, export/report
   - Uptime Kuma: monitor de prueba + alerta
   - Zabbix: ítem/trigger/acción de prueba + notificación

### Entregable
- Checklist técnico con evidencia (captura/log/comando) y estado `OK/FAIL`.

### Criterio de salida
- Todas las pruebas críticas en `OK`.

---

## Fase 4 - Pruebas de integración y regresión
**Duración sugerida:** 0.5-1 día  
**Responsable:** Seguridad + Monitoreo

### Actividades
1. Validar integraciones reales extremo a extremo:
   - autenticación (LDAP/AD, SSO si aplica)
   - correo SMTP
   - API tokens
   - SIEM/webhooks/tickets
2. Validar sincronización de componentes:
   - agentes/proxies/sensores compatibles y reportando
3. Ejecutar smoke test operativo:
   - crear evento -> detectar -> alertar -> notificar -> registrar

### Entregable
- Acta de pruebas E2E con resultados y observaciones.

### Criterio de salida
- Flujo operativo completo sin fallas.

---

## Fase 5 - Cierre y semáforo de riesgo
**Duración sugerida:** 0.5 día  
**Responsable:** Líder técnico

### Actividades
1. Clasificar cada herramienta:
   - **Verde:** versión correcta + compatibilidad confirmada + pruebas OK + logs limpios
   - **Amarillo:** operativa, pero con warnings/deprecaciones o deuda técnica
   - **Rojo:** incompatibilidad o falla funcional
2. Definir plan de acción para amarillos/rojos:
   - remediación
   - fecha objetivo
   - responsable
3. Emitir acta final de cumplimiento.

### Entregable
- Reporte final ejecutivo + técnico.

---

## Plantilla de control recomendada
Columnas sugeridas:

1. Producto  
2. Versión objetivo  
3. Versión instalada  
4. ¿Coincide?  
5. SO/DB compatible (docs)  
6. Breaking changes revisados  
7. Servicio saludable  
8. Logs sin críticos  
9. Prueba funcional OK  
10. Integraciones OK  
11. Estado (Verde/Amarillo/Rojo)  
12. Responsable  
13. Evidencia/URL  
14. Fecha validación

---

## Cronograma sugerido
- Día 1: Fase 1 + Fase 2
- Día 2: Fase 3
- Día 3: Fase 4 + Fase 5

---

## Gobierno operativo (prevención de errores futuros)
- Ventana mensual de revisión de versiones.
- Suscripción a release notes de los 5 productos.
- Ambiente de prueba antes de producción.
- Checklist obligatorio post-upgrade.
- Registro de cambios y rollback documentado.

