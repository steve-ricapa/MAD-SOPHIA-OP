# AGENTE OPENVAS – LABORATORIO

## 1. Propósito y alcance

Este proyecto implementa un **agente recolector** pensado para **entornos de laboratorio**, cuyo propósito es simular/automatizar el flujo:

1) **Obtener reportes existentes** (en XML) desde un origen tipo OpenVAS/GVM  
2) **Procesar** los resultados para construir un resumen de severidades  
3) **Evitar duplicados** con estado local persistente (`state.json`)  
4) **Emitir** el payload (en backend o en consola, dependiendo del modo)

Este tipo de agente sirve para:

- Probar **integración** con backends (ingest)
- Entrenar equipos en **observabilidad** de pipelines (polling + estado)
- Depurar parsing de reportes OpenVAS/GVM

---

## 2. Qué hace y qué NO hace

### 2.1 Sí hace

- Lee configuración desde variables de entorno (`.env` o `export ...`)
- Corre en bucle con intervalo fijo (`POLL_SECONDS`)
- Obtiene XML de reportes (simulado o real, según tu implementación)
- Parsea XML y **clasifica severidades**
- Mantiene `state.json` para **deduplicación**
- Emite un payload (backend o consola)

### 2.2 NO hace

- ❌ No lanza escaneos
- ❌ No ejecuta pruebas de explotación
- ❌ No hace descubrimiento activo (más allá de consumir datos ya existentes)
- ❌ No persiste resultados en base de datos

---

## 3. Arquitectura (alto nivel)

```
+------------------------------+
|  OpenVAS / GVM               |
|  (reportes XML ya generados) |
+---------------+--------------+
                |
                v
+------------------------------+
|  Agente Python              |
|  - main.py                  |
|  - config.py                |
|  - services.py              |
|  - gvm_client.py            |
|  - openvas_client.py        |
+---------------+--------------+
                |
                v
+------------------------------+
|  Backend REST  (opcional)   |
|  o Console STDOUT (simple)  |
+------------------------------+
```

**Idea clave:** el agente se coloca “entre” el generador de reportes y el consumidor final (backend o consola).

---

## 4. Flujo interno (paso a paso)

A nivel operacional, el ciclo del agente suele verse así:

1. **Inicio**
   - Se carga configuración (host/usuario, polling, rutas, etc.)

2. **Carga de estado**
   - Se abre `STATE_PATH` (por defecto `state.json`) y se obtiene:
     - una lista de IDs ya enviados: `sent: ["id1","id2",...]`

3. **Inicio del loop**
   - El proceso entra en `while True`

4. **Obtención de tareas/reportes**
   - Se consulta el origen (GVM / OpenVAS client) para obtener:
     - lista de tareas, reportes, o IDs disponibles

5. **Selección de elementos nuevos**
   - Se filtra contra `state["sent"]`
   - Solo se procesan los que **no** existan en `sent`

6. **Descarga / lectura del XML del reporte**
   - Por cada reporte “nuevo”:
     - se obtiene `report_xml`

7. **Procesamiento**
   - Se parsea XML
   - Se cuentan severidades (critical/high/medium/low)

8. **Construcción del payload**
   - Se arma un dict con metadatos + resumen + conteos

9. **Emisión**
   - En modo simplificado: se imprime en consola
   - En modo backend: se envía por HTTP (si aplica)

10. **Actualización de estado**

- Si la emisión fue exitosa:
  - se agrega el ID a `state["sent"]`
  - se guarda `state.json`

1. **Sleep**

- `time.sleep(POLL_SECONDS)`

1. **Siguiente ciclo**

- Vuelve al paso 4

---

## 5. Estructura del proyecto (explicada)

> La carpeta puede variar, pero la idea se mantiene.

```
agente_OV_XOC/
│
├── main.py
│   └─ Orquestación: loop, polling, recolección, deduplicación
│
├── config.py
│   └─ Configuración: lee variables de entorno y expone constantes
│
├── services.py
│   ├─ load_state / save_state   (estado)
│   ├─ extract_severities        (parsing y conteo)
│   └─ send_to_backend           (en modo simple: imprime)
│
├── gvm_client.py
│   └─ Cliente GMP: login, TLS, obtención de tasks/reportes
│
├── openvas_client.py
│   └─ Alternativa/compatibilidad para OpenVAS (si aplica)
│
├── state.json
│   └─ Persistencia local: evita duplicados
│
├── .env
│   └─ Variables locales (NO versionar)
│
└── tests/
    └─ Pruebas básicas de lógica (ej. map_status, parsing)
```

---

## 6. Modelo de datos: payload emitido

El agente construye un payload típico que incluye:

- **Metadatos de la ejecución**
  - `collector`: identificador lógico del agente
  - `company_id`: identificador lógico de empresa/entorno (laboratorio)
  - `timestamp`: momento del evento (si lo incluyes)
- **Identidad del reporte**
  - `report_id` o equivalente
  - `task_id` (si aplica)
- **Resumen de severidades**
  - conteos por nivel: `critical/high/medium/low`
- **Detalles opcionales**
  - nombre del target, host, scanner, etc. (si el XML lo provee)

### Ejemplo de payload (orientativo)

```json
{
  "company_id": 1,
  "collector": "openvas",
  "report_id": "uuid-123",
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 7
  }
}
```

> En modo simplificado, este payload **solo se imprime**.  
> En modo backend, este payload se usa como cuerpo JSON del POST (si existiera).

---

## 7. Procesamiento de severidades (cómo se calcula)

La lógica típica de laboratorio mapea un valor numérico (ej. CVSS) a 4 niveles:

| Nivel | Rango |
|------|------:|
| Critical | `>= 9.0` |
| High     | `>= 7.0` |
| Medium   | `>= 4.0` |
| Low      | `< 4.0`  |

### ¿De dónde sale el valor?

En reportes OpenVAS/GVM suele aparecer un campo de severidad por resultado, por ejemplo:

- `result/severity`

El agente recorre cada `<result>` y:

- intenta leer `severity`
- convierte a float
- incrementa el contador del bucket correspondiente

> Nota: Si el XML trae severidad vacía/no numérica, el agente la ignora (comportamiento común en laboratorios).

---

## 8. Persistencia y deduplicación (`state.json`)

`state.json` es la “memoria” del agente para evitar reenvíos.

### 8.1 ¿Por qué existe?

Cuando el agente corre por polling, en cada ciclo podría “ver” los mismos reportes.  
Sin una memoria, enviaría duplicados infinitamente.

### 8.2 Formato esperado

```json
{
  "sent": [
    "report_uuid_1",
    "report_uuid_2"
  ]
}
```

### 8.3 Reglas típicas

- Si `state.json` no existe → se crea implícitamente al guardar, y se parte desde `{"sent":[]}`
- Un reporte se marca como “sent” **solo si** la emisión fue exitosa
- Si borras `state.json` → el agente “olvida” todo y volverá a procesar como si fuera primera ejecución

---

## 9. Variables de entorno (referencia extendida)

> En laboratorio puedes usar `.env` o `export`.  
> En esta documentación se describen variables comunes.

### 9.1 Backend (si existiera)

| Variable | Tipo | Ejemplo | Uso |
|---|---|---|---|
| `TXDXAI_INGEST_URL` | string | `https://host/ingest` | Endpoint destino |
| `TXDXAI_COMPANY_ID` | int | `1` | Identificador lógico |
| `TXDXAI_API_KEY` | string | `abc123` | Token simple |

> En modo simplificado, el URL puede ser informativo (`console://stdout`) y la API key puede ir vacía.

### 9.2 Control del agente

| Variable | Tipo | Ejemplo | Significado |
|---|---:|---|---|
| `POLL_SECONDS` | int | `60` | Tiempo de espera entre ciclos |
| `STATE_PATH` | string | `state.json` | Ruta del archivo de estado |
| `COLLECTOR` | string | `openvas` | Nombre lógico del recolector |
| `META_MAX_KB` | int | `64` | Límite de tamaño (si se usa) |

### 9.3 OpenVAS / GVM (conexión)

| Variable | Tipo | Ejemplo |
|---|---|---|
| `GVM_HOST` | string | `127.0.0.1` |
| `GVM_PORT` | string/int | `9390` |
| `GVM_USERNAME` | string | `admin` |
| `GVM_PASSWORD` | string | `password` |
| `GVM_TLS_VERIFY` | `true/false` | `true` |

---

## 10. Modos de ejecución

### 10.1 Modo “simplificado” (console-only)

- La “emisión” es imprimir el payload en stdout
- No depende de backend
- Ideal para:
  - Validar parsing
  - Depurar deduplicación
  - Ver payloads en vivo

### 10.2 Modo “backend” (si lo reactivas)

- La “emisión” es un POST HTTP con JSON
- Requiere:
  - URL válida
  - credenciales/token (si aplica)

> En esta guía priorizamos el **modo simplificado**.

---

## 11. Ejecución del agente simplificado (SIN instalación)

> ✅ **Solo instrucciones de ejecución** (sin pasos de instalación).  
> Asume que ya cuentas con Python y el entorno preparado.

### 11.1 Entrar al directorio del proyecto

```bash
cd agente_OV_XOC
```

### 11.2 Definir variables mínimas de ejecución (ejemplo)
>
> Si ya usas `.env`, puedes omitir y pasar al punto 11.3.

```bash
# Conexión a GVM/OpenVAS (si aplica en tu lab)
export GVM_HOST="127.0.0.1"
export GVM_PORT="9390"
export GVM_USERNAME="admin"
export GVM_PASSWORD="password"
export GVM_TLS_VERIFY="true"

# Control del loop
export POLL_SECONDS="60"

# Estado local (deduplicación)
export STATE_PATH="state.json"

# Identificador lógico
export COLLECTOR="openvas"
```

### 11.3 Ejecutar el agente

```bash
python3 main.py
```

### 11.4 Ejecutar remotamente en el servidor OpenVAS

Cuando el acceso a GVM/OpenVAS solo funciona desde el host remoto, puedes copiar el proyecto por `ssh`, preparar el entorno y lanzar el agente en una sola linea:

```bash
tar czf - . | ssh root@192.168.18.205 'rm -rf /tmp/agente_openvas && mkdir -p /tmp/agente_openvas && tar xzf - -C /tmp/agente_openvas && cd /tmp/agente_openvas && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt && python main.py'
```

Esto hace lo siguiente:

- empaqueta el proyecto actual y lo envía al servidor remoto
- recrea `/tmp/agente_openvas`
- descomprime el proyecto en ese directorio
- crea y activa un entorno virtual en `.venv`
- instala dependencias desde `requirements.txt`
- ejecuta `python main.py`

### 11.5 Detener el agente

En cualquier momento:

```text
Ctrl + C
```

### 11.6 Reiniciar desde cero (opcional)

Si quieres que el agente reprocesse como “primera vez”:

```bash
rm -f state.json
```

---

## 12. Verificación rápida y ejemplos de salida

### 12.1 Señales de ejecución correcta

- Se imprime un mensaje de arranque
- Empiezas a ver “ciclos” repetidos
- Cada ciclo ocurre aproximadamente cada `POLL_SECONDS`

### 12.2 Ejemplo de salida (modo simplificado)
>
> Lo importante es que veas el JSON completo en consola.

```json
{
  "company_id": 1,
  "collector": "openvas",
  "report_id": "uuid-123",
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 6,
    "low": 9
  }
}
```

### 12.3 Confirmar deduplicación

- En el primer ciclo se imprime el reporte
- En ciclos siguientes, si el `report_id` ya está en `state.json`, no debería reimprimirse

---

## 13. Manejo de errores y comportamiento ante fallos

En laboratorio, el patrón típico es:

- Si algo falla (conexión, parsing, timeout):
  - se registra el error en consola
  - el loop continúa
  - el agente vuelve a intentar en el siguiente ciclo

Esto permite demostrar:

- robustez básica ante fallos
- recuperación automática por polling

---

## 14. Operación en laboratorio (buenas prácticas)

- Mantén `.env` **fuera** del repositorio (se recomienda `.gitignore`)
- Evita poner tokens reales en archivos compartidos
- Usa un `STATE_PATH` por entorno (ej. `state_lab.json`, `state_demo.json`)
- Ajusta `POLL_SECONDS`:
  - 10–30s para demos
  - 60–300s para laboratorios estables

---

## 15. Troubleshooting: problemas comunes

### 15.1 “ModuleNotFoundError”

- Asegúrate de ejecutar desde la raíz del proyecto:

```bash
cd agente_OV_XOC
python3 main.py
```

### 15.2 No imprime nada / se queda “quieto”

- Verifica `POLL_SECONDS` (si es grande, el agente esperará)
- Revisa que el origen (GVM) esté disponible si el agente intenta consultarlo

### 15.3 Repite lo mismo muchas veces

- Verifica si `STATE_PATH` apunta al archivo correcto
- Confirma que `state.json` se está escribiendo y contiene `sent`

### 15.4 Quieres reprocesar todo desde cero

```bash
rm -f state.json
python3 main.py
```

---

## 16. Pruebas unitarias (opcional)

> Se incluye como referencia de ejecución.  
> (Sin pasos de instalación en esta sección.)

Ejecutar en la raíz del proyecto:

```bash
pytest
```

---

## 17. Seguridad (solo laboratorio)

⚠️ Este proyecto puede usar:

- credenciales en texto plano
- TLS opcional
- tokens simples

**No usar en producción.**  
Para producción se requeriría hardening (TLS estricto, secretos seguros, logging formal, controles de tamaño, etc.).

---

## 18. Límites y rendimiento

- Diseñado para bajo consumo
- Sin paralelismo
- XML procesado en memoria
- No recomendado para volúmenes masivos de reportes

---

## 19. Roadmap de mejoras (no implementadas)

- Parsing XML endurecido (defusedxml)
- TLS obligatorio por defecto
- Backoff exponencial ante fallos
- Persistencia transaccional (SQLite)
- Métricas (Prometheus)
- Estructura de logs (JSON logs)
- “Queue” local (buffer offline)

---
