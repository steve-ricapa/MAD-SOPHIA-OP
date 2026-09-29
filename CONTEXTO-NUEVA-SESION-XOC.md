# Contexto de continuidad XOC / OpenVAS

**Actualizado:** 2026-09-29  
**Objetivo:** cerrar la calidad y reproducibilidad de los datos OpenVAS antes de entrenar el modelo.

## Repositorios

- API XOC: `C:\Users\Diego Ramos\Projects-TxDx\XOC-API-AWS`
- Collector MAD/OpenVAS: `C:\Users\Diego Ramos\Projects-TxDx\MAD-SOPHIA-OP`

El collector se ejecuta en el servidor desde `MAD-SOPHIA-OP/openVAS_integration`. No asumir que un cambio local está publicado hasta verificar `git log`, `git status` y el remoto.

## Estado validado

La evidencia más reciente está en:

```text
C:\Users\Diego Ramos\Downloads\para che
```

La ejecución produjo:

- 10 reportes XML descargados.
- 10 paquetes en `reports/<report_id>/`.
- Cada paquete contiene `report.xml`, `payload.json` y `metadata.json`.
- `sent_reports=10`.
- `delivery_success=true`.
- GVM respondió correctamente con versión 22.7.
- No hubo `NameError`, `Traceback` ni excepciones en la ejecución validada.
- Los hallazgos sin CVE se representan como `cve: null` y `cves: []`.
- Los CVE disponibles se extraen en `cve` y `cves`.

La corrección que evitó el fallo anterior fue agregar `import re` en:

```text
MAD-SOPHIA-OP/openVAS_integration/main.py
```

## Estado pendiente

La ejecución validada todavía mostró estos valores efectivos:

```text
GVM_PAGINATE_REPORT=False
GVM_FINDINGS_MAX=-1
OPENVAS_REPORT_MAX_KB=20000
OPENVAS_SNAPSHOT_ALWAYS_SEND=False
OPENVAS_FORCE_SEND_EVERY_CYCLES=6
```

Por tanto, el envío funciona, pero todavía no está demostrada la captura completa sin límite local. Varios payloads quedaron en 500 hallazgos.

El `.env` real del servidor debe contener, como mínimo:

```env
GVM_PAGINATE_REPORT=true
GVM_REPORT_PAGE_SIZE=250
GVM_MAX_PAGES=200
GVM_FINDINGS_MAX=0
OPENVAS_REPORT_MAX_KB=65536
OPENVAS_DETAIL_LEVEL=findings
OPENVAS_REPORT_ARTIFACTS_DIR=reports
OPENVAS_SNAPSHOT_ALWAYS_SEND=true
OPENVAS_FORCE_SEND_EVERY_CYCLES=1
```

## Siguiente validación

1. Confirmar qué commit está ejecutando el servidor y que contiene `import re`.
2. Actualizar el `.env` real; no escribir las variables solamente en la terminal.
3. Ejecutar un ciclo controlado.
4. Confirmar en consola que la paginación sea `True` y `GVM_FINDINGS_MAX=0`.
5. Comparar por reporte: resultados del XML, resultados extraídos, hallazgos enviados, CVE, severidades y `findings_discarded`.
6. Confirmar que no exista un límite de 500 hallazgos.
7. Confirmar que XOC y los dashboards muestren los mismos conteos.
8. Solo después de esta validación considerar estable la fuente para entrenamiento.

## Seguridad

Los logs revisados contienen información interna y pueden contener credenciales o API keys. No copiar secretos a este documento ni al repositorio. Rotar cualquier credencial que haya quedado expuesta y mantener los logs fuera de repositorios públicos.

## Prompt para la siguiente sesión

```text
Lee primero:

C:\Users\Diego Ramos\Projects-TxDx\MAD-SOPHIA-OP\CONTEXTO-NUEVA-SESION-XOC.md

Continúa desde el estado documentado. No entrenes todavía el modelo.

Prioridad:

1. Revisar la integración OpenVAS/MAD y confirmar qué commit está realmente desplegado.
2. Verificar el .env del servidor con GVM_PAGINATE_REPORT=true, GVM_REPORT_PAGE_SIZE=250, GVM_MAX_PAGES=200, GVM_FINDINGS_MAX=0, OPENVAS_REPORT_MAX_KB=65536, OPENVAS_SNAPSHOT_ALWAYS_SEND=true y OPENVAS_FORCE_SEND_EVERY_CYCLES=1.
3. Ejecutar una prueba controlada.
4. Comparar XML original, resultados extraídos, payload enviado, CVE, severidades y findings_discarded.
5. Confirmar los artefactos report.xml, payload.json y metadata.json por reporte.
6. Confirmar que no persista un límite de 500 hallazgos.
7. Confirmar que el backend XOC y los dashboards muestren los mismos conteos.
8. No mostrar ni copiar credenciales encontradas en logs; solicitar rotación si continúan expuestas.
```
