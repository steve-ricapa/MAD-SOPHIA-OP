# Incidencia 2026-08-24: muerte silenciosa del ETL en modo `--supervise`

**Repositorio:** MAD-SOPHIA-OP · **Rama:** `ETL-NEXUS` · **Estado:** corregido y probado localmente (pendiente de commit)

---

## 1. Contexto

Durante la validación del ETL contra Uptime Kuma (v1.23.17 en `http://172.31.252.117:3001`, contenedor Docker `uptime-kuma`), se ejecutó la **Prueba B**: detener el contenedor ~4 minutos y verificar que el ETL, que consulta `/metrics` cada 30s con Basic Auth, sobrevive a la caída de la fuente.

El ETL corrió con:

```powershell
PYTHONPATH=src python -m txdx_etl.cli --supervise
```

## 2. Evidencia del incidente

Timeline (UTC) reconstruido desde `runtime/etl.log`:

| Hora | Evento |
|---|---|
| 21:40:22Z | `docker stop uptime-kuma` (T3). Fuente muerta. |
| 21:40:30Z | Ciclo 1: `scrape=FALLO(TransientMetricsError)` |
| 21:41:15Z | Ciclo 2: `scrape=FALLO(TransientMetricsError)` |
| 21:42:00Z | Ciclo 3: `scrape=FALLO(TransientMetricsError)` |
| ~21:43:00Z | **Silencio total.** Ni mensaje de fallo ni de reinicio del supervisor. |
| 21:44:49Z | `docker start uptime-kuma` (T4) |
| 21:45:05Z | Kuma responde 200 (+16s de recuperación), pero el proceso ETL (PID 8956) **ya había desaparecido**. |

Observaciones clave:

- La cadencia de 45s = timeout de conexión (15s) + intervalo de ciclo (30s): el cliente funcionó **como fue diseñado** durante los 3 primeros ciclos.
- El 4º ciclo nunca produjo salida. Todo path de `Exception` en el código imprime mensajes (`flush=True`), por lo que ninguna excepción Python interna explica el silencio.
- `runtime/etl.err.log` no contenía información útil.

## 3. Causa raíz

### Defecto principal (el que mata al supervisor)

`run_session()` atrapaba `KeyboardInterrupt` internamente:

```python
# ANTES
except KeyboardInterrupt:
    print("interrumpido por el usuario", flush=True)
    return 0          # <- sale ANTES de que supervise() lo vea
```

Consecuencia: cualquier `Ctrl+C` o evento de consola extrayño (semántica de consola Windows: cierre del shell anfitrión, `GenerateConsoleCtrlEvent` al grupo de procesos, eventos de sesión RDP, otro proceso del grupo) terminaba la sesión interna con código 0 **sin que el supervisor registrara nada**. `--supervise` retornaba silenciosamente: proceso muerto, sin mensaje de reinicio — exactamente la firma del incidente.

Causa externa alternativa no descartable remotamente (`taskkill /F`, logoff cerrando la consola): produce la misma firma, pero el defecto de diseño era real e independiente — un Ctrl+C legítimo también debía quedar registrado por el supervisor.

### Defectos contribuyentes

| # | Defecto | Riesgo |
|---|---|---|
| 1 | `resource.close()` sin guardia en el `finally` | Un error de cierre **enmascaraba** la excepción original (diagnóstico imposible) |
| 2 | Recursos construidos fuera de tracking | Construcción parcial filtraba handles SQLite → churn `"database is locked"` en reintentos |
| 3 | Mensaje de reinicio sin contador/duración/motivo claro | Difícil distinguir reinicios normales de bucles de crash |
| 4 | Módulo `time` hardcodeado en `supervise()` | Supervisor intestable sin dormir de verdad |

## 4. Corrección aplicada

Archivo modificado: `src/txdx_etl/cli.py` (**+78 / −31 líneas**). No se tocó ningún otro módulo del paquete.

### a) Constantes de política (antes hardcodeadas)

```python
SUPERVISOR_INITIAL_PAUSE_SECONDS = 5
SUPERVISOR_MAX_PAUSE_SECONDS = 60
SESSION_STABLE_SECONDS = 300
```

### b) `build_runtime(..., resources_out=None)`

Registra cada recurso (state store, outbox, cycle log, client) con `track()` apenas se crea. Si la construcción falla a medias, el llamante puede cerrar lo ya abierto y el reintento no hereda handles colgados.

### c) `run_session(settings, *, builder=None)` — cambio clave

- Se **eliminó** el `except KeyboardInterrupt`: ahora el Ctrl+C **se propaga al llamante**, quien decide qué hacer (`main` en modo simple imprime "interrumpido por el usuario"; `supervise` en modo `--supervise` registra su salida limpia).
- `finally` cierra cada recurso en su propio `try/except`; un cierre roto solo emite un aviso sin tapar la causa original:
  `[hora] aviso: fallo cerrando SqliteOutbox: ...`
- Pasa `resources_out=tracked` al builder.
- Nuevo parámetro keyword-only `builder` para inyección de runtime falso en pruebas.

### d) `supervise(settings, *, run, sleep, monotonic, initial_pause_seconds, max_pause_seconds)`

Mensaje de reinicio antes/después:

```
ANTES: [stamp] sesion termino inesperadamente (RuntimeError: x); reiniciando en 5s
AHORA: [hora] sesion #1 termino inesperadamente (duro 2s; RuntimeError: x); reconstruyendo runtime y reiniciando en 5s
```

- Contador de reinicios `#N`, duración de la sesión caída, aviso explícito de reconstrucción del runtime.
- Backoff exponencial idéntico en comportamiento: duplica 5→10→20→40→60s, tope 60s, se **resetea a 5s** si la sesión previa duró más de 300s (estable).
- `KeyboardInterrupt` se maneja **solo aquí**: `supervisor detenido por el usuario`, salida 0.
- Inyección de `run/sleep/monotonic` y de las pausas: ahora es testeable sin esperas reales.

### e) `main()` modo simple

Envuelve `run_session` en try/except KeyboardInterrupt para conservar el mensaje "interrumpido por el usuario" cuando NO se usa `--supervise`.

## 5. Archivos nuevos

| Archivo | Propósito |
|---|---|
| `tests/unit/test_supervisor.py` | 10 pruebas unitarias del supervisor (ver §6) |
| `tools/demo_supervisor_recovery.py` | Reproducción controlada del incidente con cliente falso (`httpx.MockTransport`) |

**No modificado:** `app.py`, `.env` real, credenciales, SQLite operativo, tareas programadas de Windows, regla de firewall existente.

## 6. Pruebas

### Unitarias nuevas (`tests/unit/test_supervisor.py`)

Mapeadas a los requisitos de la investigación:

1. Excepción inesperada **no termina al supervisor** + mensaje claro con tipo y motivo.
2. Backoff duplica pero **nunca supera 60s** (`[5,10,20,40,60,60,60]`).
3. Backoff **se resetea** tras una sesión estable >300s.
4. Ctrl+C termina limpio vía supervisor ("supervisor detenido por el usuario", salida 0).
5. Runtime y recursos se **reconstruyen** tras fallo (2 construcciones, recursos cerrados en ambas generaciones).
6. Ctrl+C **no lo traga** `run_session` (contrato de propagación).
7. Error de `close()` **no enmascara** la excepción original (`RuntimeError("fallo original")` intacta + aviso registrado).
8. `build_runtime` registra los 4 recursos en `resources_out`.
9. Mensaje de reinicio incluye contador `sesion #N`.
10. `SystemExit` propaga por diseño (salida explícita del proceso, documentado como contrato).

### Reproducción controlada (`tools/demo_supervisor_recovery.py`)

Guion del "Kuma falso" igual al incidente: HTTP 500 → conexión rechazada → excepción cruda inesperada → Ctrl+C simulado.

```text
=== REPRODUCCION CONTROLADA DEL INCIDENTE ===
    [builder] construyendo runtime #1 (state/outbox/cycle_log/client nuevos)
    [kuma-falso] peticion #1: http_500
[hora] scrape=FALLO(TransientMetricsError) detectados=0 encolados=0 entregados=0 pendientes=0
    [kuma-falso] peticion #2: connect_error
[hora] scrape=FALLO(TransientMetricsError) ...
    [kuma-falso] peticion #3: raw_crash
[hora] sesion #1 termino inesperadamente (duro 2s; RuntimeError: fallo inesperado no clasificado);
       reconstruyendo runtime y reiniciando en 5s
    [builder] construyendo runtime #2 ...
    [kuma-falso] peticion #4: ctrl_c
supervisor detenido por el usuario
RESULTADO: CORRECTO - el supervisor sobrevive y reconstruye
```

### Resultados de suites

| Suite | Resultado |
|---|---|
| `python -m pytest tests/unit/test_supervisor.py -q` | **10 passed** |
| ETL: `tests/unit` + `tests/contract` | **145 passed** (línea base previa: 111) |
| Suite completa del repo | 194 passed / 3 failed |

Los 3 fallos de la suite completa son **preexistentes** en `tests/test_app_openvas_diagnostics.py` (funciones inexistentes de `app.py`: `_normalize_openvas_transport`, etc.), módulo ajeno a este cambio — verificado con `git status` (único tracked modificado: `src/txdx_etl/cli.py`).

## 7. Cómo repetir la prueba contra Kuma remoto

En la laptop ETL, tras sincronizar esta rama:

```powershell
cd <ruta>\MAD-SOPHIA-OP
git pull origin ETL-NEXUS
$env:PYTHONPATH="src"; python -m txdx_etl.cli --supervise *> runtime\etl.log
```

En la laptop servidor, repetir el guion de la Prueba B:

```powershell
docker stop uptime-kuma   # T3
Start-Sleep -Seconds 240
docker start uptime-kuma  # T4
```

Comportamiento esperado en `runtime/etl.log`:

1. Durante la caída: ciclos `scrape=FALLO(TransientMetricsError)` cada ~45s, indefinidamente (sin límite de intentos).
2. Si algo llega a matar una sesión internamente: línea explícita `sesion #N termino inesperadamente (...) ; reconstruyendo runtime y reiniciando en Xs` seguida de recuperación automática.
3. Tras la recuperación de Kuma: los ciclos reanudan `scrape=OK` sin intervención manual.
4. Nunca más un silencio sin explicación.

## 8. Pendiente

- [ ] Commit de los cambios en `ETL-NEXUS`.
- [ ] Re-ejecutar la prueba remota (§7) para validar en condiciones reales.
- [ ] (Opcional, fuera de alcance) Reparar los tests preexistentes rotos de `test_app_openvas_diagnostics.py`.
