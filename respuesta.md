# Dudas tecnicas para validar con documentacion oficial OpenVAS/GVMD (GMP)

Contexto actual observado en cliente:
- TCP a `GVM_HOST:GVM_PORT` responde.
- El handshake TLS falla con `SSLEOFError`.
- El puerto parece ser GMP en modo no-TLS.
- La version instalada de `python-gvm` no expone `SocketConnection`.

## 1) Transporte GMP soportado por el despliegue del cliente
- El endpoint GMP del cliente (`10.208.232.43:41000`) esta configurado como:
  - TLS obligatorio,
  - TCP plano (sin TLS),
  - o ambos?
- En GVMD/OpenVAS, cual es la forma oficial de verificar este modo en runtime?

## 2) Recomendacion oficial para acceso remoto
- Para acceso remoto a GMP, la recomendacion oficial es:
  - `TLSConnection` sobre puerto GMP,
  - `UnixSocketConnection` (local),
  - o existe recomendacion para TCP plano en produccion?
- Si TCP plano no es recomendado, cual es la alternativa oficial para entornos on-prem con segmentacion interna?

## 3) Compatibilidad de versiones `python-gvm`
- Desde que version de `python-gvm` existe/esta soportado `SocketConnection` en `gvm.connections`?
- Hubo cambios de API/import path entre versiones (por ejemplo mover o retirar `SocketConnection`)?
- Cual es la matriz de compatibilidad recomendada entre:
  - version de `python-gvm`,
  - version de GVM/GVMD,
  - version de GMP?

## 4) Deteccion de version GMP y handshake
- El handshake TLS es siempre requisito previo para `determine_remote_gmp_version()` cuando se usa `TLSConnection`?
- Existe flujo oficial para detectar GMP version en endpoints no-TLS sin romper el cliente?

## 5) Configuracion TLS en GVMD
- Si el endpoint debe usar TLS:
  - que flags/parametros de `gvmd` habilitan TLS remoto?
  - como validar certificados requeridos (CA, cert, key) del lado cliente?
- El error `UNEXPECTED_EOF_WHILE_READING` en handshake GMP-TLS suele indicar:
  - puerto en plano,
  - proxy/LB cerrando conexion,
  - mismatch de versiones TLS,
  - o configuracion de cert incompleta?

## 6) Uso de socket Unix en despliegue on-prem
- Si el agente corre en el mismo host de GVMD, es valido como patron oficial usar `GVM_SOCKET` para evitar problemas TLS remotos?
- Cual es el path tipico y permisos recomendados para el socket en distro Linux empresarial?

## 7) Buenas practicas oficiales para integraciones automatizadas
- Recomendacion oficial para autenticacion GMP de agentes:
  - usuario dedicado de solo lectura?
  - permisos minimos necesarios para `get_tasks` y `get_report`?
- Recomendaciones para timeouts/reintentos en clientes GMP automatizados?

## 8) Verificacion operativa recomendada (checklist oficial)
- Cual seria el checklist minimo oficial para confirmar que un endpoint GMP esta listo para integracion:
  1. DNS/host
  2. Puerto
  3. Modo transporte (TLS/plano/socket)
  4. Auth GMP
  5. `get_tasks`
  6. `get_report`

## 9) Decisiones para nuestro caso
Con base en doc oficial, necesitamos recomendacion concreta para este escenario:
- Endpoint actual: `10.208.232.43:41000`
- Error actual: `SSLEOFError` en handshake TLS
- Restriccion actual: `python-gvm` del cliente sin `SocketConnection`

Preguntas directas de decision:
- Conviene forzar `GVM_USE_TLS=true` y ajustar servidor/certs?
- Conviene migrar a `GVM_SOCKET` en ese cliente?
- Conviene actualizar `python-gvm` y mantener `GVM_USE_TLS=false`?

---

Objetivo final: elegir una ruta unica, estable y soportada oficialmente para evitar falsos positivos y errores de handshake en produccion on-prem.

## 10) Consultas adicionales por hallazgos del diagnostico

### 10.1) Coherencia entre precheck y ejecucion real
- En nuestro diagnostico, `env/dns/tcp` pasan, pero la ejecucion falla en `cycle.top_level` por TLS.
- Segun buenas practicas oficiales, para `TLSConnection` deberiamos considerar "listo" un endpoint solo si el handshake TLS y la negociacion inicial GMP tambien pasan?
- OpenVAS/GVMD recomienda algun "health check" oficial para validar endpoint GMP-TLS antes de ejecutar consultas (`get_tasks`, `get_report`)?

### 10.2) Interpretacion oficial de `SSLEOFError`
- En contexto GMP remoto, OpenVAS documenta `SSLEOFError: UNEXPECTED_EOF_WHILE_READING` como indicador principal de:
  - puerto GMP sin TLS,
  - TLS roto/interrumpido por middlebox (LB/proxy/firewall),
  - incompatibilidad de versiones/cifrados,
  - o cierre temprano por politica del servidor?
- Existe recomendacion oficial para diferenciar estas causas de forma rapida (orden de pruebas o comandos sugeridos)?

### 10.3) Listener recomendado para GMP remoto
- Para una arquitectura "MAD central" (agente en VM A, GVMD en VM B), cual es el patron oficial recomendado:
  - GMP remoto con TLS extremo a extremo,
  - tunel seguro y GMP local,
  - o co-localizar agente y GVMD con socket Unix?
- Si el recomendado es TLS remoto, cual es la configuracion minima de seguridad/certificados exigida por OpenVAS para produccion?

### 10.4) Puerto 41000 y terminacion TLS
- OpenVAS/GVMD define algun puerto convencional para GMP TLS o es totalmente configurable?
- Si se usa un puerto no estandar (ej. `41000`), hay consideraciones oficiales sobre inspeccion TLS de firewall/LB que puedan provocar EOF?

### 10.5) Compatibilidad de cliente Python y metodos de conexion
- Con versiones donde no aparece `SocketConnection`, cual es la ruta oficial soportada por el proyecto (`TLSConnection` / `UnixSocketConnection`)?
- OpenVAS recomienda fijar version de `python-gvm` para evitar cambios de API en despliegues productivos?

### 10.6) Recomendaciones de robustez para agentes automatizados
- Cual es la politica recomendada por OpenVAS para:
  - reintentos ante errores TLS transitorios,
  - backoff,
  - y umbral para declarar fallo permanente?
- Se recomienda registrar y alertar por categoria de falla (`dns`, `tcp`, `tls`, `auth`, `gmp`) para acelerar RCA?

### 10.7) Consultas directas para el equipo del cliente
- Pueden confirmar si `10.208.232.43:41000` expone **GMP con TLS real** de extremo a extremo?
- Hay proxy/LB/NAT/intercepcion TLS entre el agente y GVMD?
- El certificado presentado en ese listener corresponde al servicio GMP esperado y cadena valida para el cliente?
- El servidor acepta la version/cifrados TLS negociados por el cliente Python actual?
- Existe un endpoint alterno oficial del mismo GVMD para GMP-TLS validado por ustedes?

### 10.8) Criterio de aceptacion para cerrar incidencia
- El caso se considera resuelto oficialmente cuando se cumpla:
  1. Handshake TLS estable en `GVM_HOST:GVM_PORT`.
  2. Login GMP exitoso con usuario de integracion.
  3. `get_tasks` y `get_report` responden sin errores.
  4. El agente completa `--once` sin `cycle.top_level` ni `SSLEOFError`.
  5. Se documenta modo final elegido (`tls` remoto o `unix` local) y su runbook.

## 11) Respuesta operativa del cliente (confirmada)
- El endpoint `10.208.232.43:41000` llega directo a `gvmd`.
- El listener actual no tiene TLS (sin certificado/CA y sin endpoint alterno TLS).
- Con ese estado, `GVM_TRANSPORT=tls` va a fallar por diseno durante el handshake (`SSLEOFError`/EOF).
- Decision MAD: mantener arquitectura centralizada y no instalar collector completo por VM.
- Siguiente paso de infraestructura: habilitar GMP-TLS real en cliente o definir fallback posterior por SSH controlado.

## 12) Implementacion aplicada para este caso (MAD central)
- Se habilito transporte `plain` en OpenVAS para GMP por TCP sin TLS, alineado al script validado por cliente.
- Se mantiene soporte de `tls` y `unix`.
- Alias soportado: `GVM_TRANSPORT=tcp` se normaliza internamente a `plain`.
- Proteccion explicita: para usar `plain`, se requiere `GVM_ALLOW_PLAIN_TCP=true`.
- En precheck, modo `plain` valida cadena GMP real: `get_version -> authenticate -> get_tasks` (y `get_report` opcional con `OPENVAS_PRECHECK_REPORT_ID`).

Variables minimas para modo actual del cliente:
- `OPENVAS_COLLECTOR=gmp`
- `GVM_TRANSPORT=plain`
- `GVM_ALLOW_PLAIN_TCP=true`
- `GVM_HOST=10.208.232.43`
- `GVM_PORT=41000`
- `GVM_USERNAME=<usuario>`
- `GVM_PASSWORD=<password>`
