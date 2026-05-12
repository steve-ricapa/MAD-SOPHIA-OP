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
