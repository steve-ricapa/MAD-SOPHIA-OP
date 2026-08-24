# Plan Final V2
# Plataforma de Integracion de Eventos de Ciberseguridad con MAD y Nube

## 1. Estado y proposito del documento

Este documento define una proyeccion realista para evolucionar el proyecto actual hacia una plataforma multi-tenant de procesamiento de eventos de ciberseguridad.

No describe una plataforma ya terminada. Separa expresamente:

- lo que ya existe en el repositorio;
- lo que se validara primero en laboratorio;
- lo que pertenece al MAD instalado en cada cliente;
- lo que pertenece a la plataforma central en la nube;
- lo que se implementara solo cuando exista una necesidad operacional concreta.

El objetivo es evitar dos errores:

- convertir cada appliance en una copia completa de la plataforma cloud;
- construir servicios cloud antes de validar el flujo real con una fuente conectada.

## 2. Vision final

La plataforma recibira informacion de herramientas instaladas en diferentes clientes, la conservara de forma confiable, la normalizara a un contrato comun y permitira consultar eventos, activos, hallazgos y estado operativo desde un punto central.

El sistema se dividira en dos zonas con responsabilidades distintas:

```text
Fuentes del cliente
  -> MAD local
  -> ingreso seguro en la nube
  -> procesamiento central multi-tenant
  -> persistencia y dashboard central
```

La separacion no busca procesar dos veces el mismo problema. Busca colocar cada responsabilidad donde tiene mas sentido:

- el MAD conoce la red local, las credenciales de las fuentes y la conectividad del cliente;
- la nube conoce todos los eventos del tenant, aplica reglas globales y permite escalar varios appliances;
- el MAD debe continuar funcionando aunque la nube este temporalmente inaccesible;
- la nube no debe necesitar conectarse directamente a cada herramienta del cliente.

## 3. Estado real actual

### 3.1 Implementado

El repositorio actual ya contiene un nucleo funcional para el MAD:

- contrato canonico inicial con JSON Schema;
- identidad determinista para assets, records y deliveries;
- validacion cross-record de envelopes;
- parser Prometheus para Uptime Kuma;
- mapper de Uptime Kuma hacia el modelo canonico;
- cliente HTTP con Basic Auth, limites de lectura y clasificacion de errores;
- deteccion de estados `initial`, `refresh`, `change`, `discovered` y `disappeared`;
- confirmacion de desaparicion despues de varios scrapes validos;
- estado persistente del detector en SQLite;
- outbox durable en SQLite;
- deduplicacion exacta por `record_id` ya entregado;
- reintentos de delivery con espera creciente;
- separacion entre fallos transitorios y permanentes;
- registro de resultados de cada ciclo;
- dashboard local FastAPI para observar el MAD;
- CLI para ejecutar ciclos contra una instancia real de Uptime Kuma;
- fixtures de Uptime Kuma 1.23.x y 2.x;
- fixture anonimizado con forma real de laboratorio;
- 136 pruebas automatizadas pasando al momento de redactar este documento.

### 3.2 Validado en laboratorio

La investigacion y la prueba inicial de Uptime Kuma confirmaron:

- version observada: Uptime Kuma `1.23.17`;
- uso de `/metrics` como fuente principal de snapshot;
- autenticacion con usuario y contrasena mediante Basic Auth;
- presencia de diez monitores en la instancia evaluada;
- estados `up` y `down` correctamente observables;
- labels ausentes representados como literal `"null"`, ya normalizado por el parser;
- credenciales incorrectas clasificadas como error bloqueante;
- credenciales validas produciendo un snapshot parsable.

### 3.3 Todavia no implementado como producto

Las siguientes capacidades aun son objetivos y no deben considerarse terminadas:

- envio HTTP real a una plataforma cloud;
- enrolamiento seguro de appliances;
- aislamiento multi-tenant en el ingreso cloud;
- RabbitMQ cloud en una topologia operativa;
- procesamiento central distribuido;
- enriquecimiento con fuentes externas;
- deduplicacion global entre herramientas diferentes;
- correlacion de eventos;
- persistencia cloud definitiva;
- dashboard central de clientes;
- scheduler de produccion con control operacional;
- actualizacion automatica del MAD;
- observabilidad central con Prometheus y Grafana;
- busqueda historica avanzada con OpenSearch.

## 4. Alcance inicial y fuera de alcance

### 4.1 Alcance de la primera entrega util

La primera entrega util debe lograr lo siguiente:

- conectarse a Uptime Kuma desde un MAD instalado en otra laptop o appliance;
- ejecutar snapshots de forma programada;
- detectar cambios sin generar eventos repetidos innecesarios;
- conservar el estado y los envelopes ante reinicios;
- continuar leyendo aunque temporalmente no exista conectividad con el destino;
- mostrar en el dashboard local que ocurrio en cada ciclo;
- enviar posteriormente un envelope validado a un endpoint cloud de prueba;
- asociar cada envelope a un tenant autenticado;
- confirmar que un reinicio o reintento no duplica el hecho logico.

### 4.2 Fuera de alcance inicial

No se implementara inicialmente:

- correlacion avanzada de incidentes;
- inteligencia artificial o machine learning como dependencia del flujo;
- remediacion automatica;
- sistema de tickets;
- OpenSearch desde el primer dia;
- Redis dentro del MAD;
- RabbitMQ dentro de cada cliente;
- Prometheus y Grafana instalados en cada appliance;
- microservicios separados para cada etapa;
- soporte simultaneo de todas las fuentes antes de cerrar Uptime Kuma y Zabbix;
- garantia de entrega exactamente una vez a nivel de red.

La garantia realista sera `at-least-once` con idempotencia determinista.

## 5. Arquitectura final propuesta

### 5.1 Vista general

```text
                 ZONA DEL CLIENTE

  Uptime Kuma   Zabbix   Wazuh   Nessus   OpenVAS   InsightVM
       |           |       |        |        |          |
       +-----------+-------+--------+--------+----------+
                               |
                         MAD / appliance
                               |
                 HTTPS autenticado y comprimido
                               |
                         ZONA CLOUD
                               |
                    API de ingreso / auth tenant
                               |
                         Cola durable cloud
                               |
          validacion -> normalizacion -> enriquecimiento
                               |
                   deduplicacion y correlacion
                               |
                  persistencia -> API -> dashboard
```

### 5.2 Flujo local del MAD

```text
Scheduler local
  -> cliente de la fuente
  -> snapshot o extraccion incremental
  -> parser fuente
  -> mapper al contrato canonico
  -> deteccion de cambios y reconciliacion
  -> validacion
  -> identidad y deduplicacion local
  -> SQLite state store + SQLite outbox
  -> compresion y firma
  -> envio al ingreso cloud
```

El MAD debe incluir solo la logica necesaria para recolectar de forma confiable y entregar datos validos. No debe incluir RabbitMQ, Redis, Grafana, OpenSearch ni la correlacion global.

### 5.3 Flujo cloud

```text
HTTPS del MAD
  -> autenticacion del appliance
  -> identificacion confiable del tenant
  -> validacion del envelope
  -> cola cloud
  -> consumidor de normalizacion final
  -> enriquecimiento
  -> deduplicacion global
  -> correlacion
  -> persistencia multi-tenant
  -> API de consulta
  -> dashboard central
```

La nube no debe conectarse directamente a Uptime Kuma, salvo que en el futuro exista un caso especifico que lo justifique. La fuente permanece dentro de la red del cliente y el MAD es el intermediario controlado.

## 6. Responsabilidades por zona

### 6.1 MAD / appliance

El MAD sera un monolito modular Python dentro de un contenedor por appliance.

Responsabilidades:

| Capacidad | Motivo de ubicacion local |
| --- | --- |
| Conectores | Las herramientas y credenciales estan en la red del cliente |
| Scheduler | La lectura debe continuar aunque la nube no responda |
| Parser fuente | Evita transportar formatos innecesarios y permite detectar errores temprano |
| Deteccion de cambios | Compara snapshots de la misma fuente y conserva su estado local |
| Validacion inicial | Evita encolar payloads invalidos |
| Outbox | Protege datos durante cortes de red o reinicios |
| Retry de entrega | Recupera conectividad sin perder envelopes |
| Compresion y firma | Reduce trafico y permite verificar origen e integridad |
| Dashboard local | Facilita diagnostico del appliance y pruebas de laboratorio |

### 6.2 Plataforma cloud

Responsabilidades:

| Capacidad | Motivo de ubicacion central |
| --- | --- |
| Ingreso autenticado | Centraliza la confianza y el control de tenants |
| Cola durable | Desacopla ingreso y procesamiento para muchos appliances |
| Deduplicacion global | Compara eventos de diferentes fuentes y appliances |
| Enriquecimiento | Centraliza fuentes comunes, catalogos y reglas |
| Correlacion | Relaciona vulnerabilidades, alertas y disponibilidad |
| Persistencia historica | Permite consultas entre fuentes y periodos largos |
| Dashboard central | Presenta informacion agregada por tenant y por organizacion |
| Observabilidad | Permite operar toda la plataforma desde un punto central |

## 7. Reintentos, deduplicacion y confirmaciones

### 7.1 Reintentos del MAD

El MAD debe reintentar cuando:

- una fuente no responde;
- existe timeout;
- existe un error de transporte;
- el ingreso cloud devuelve un error temporal;
- el proceso se reinicia con envelopes pendientes.

Un fallo permanente no debe borrar el envelope. Debe quedar apartado con razon visible para diagnostico y reproceso controlado.

### 7.2 Reintentos cloud

La nube debe tener su propia politica para:

- consumidor temporalmente caido;
- error de dependencia externa;
- saturacion controlada;
- mensaje que excede los intentos permitidos;
- envio a una cola de mensajes no procesables.

Los reintentos cloud no sustituyen al outbox del MAD. El outbox protege el tramo appliance-cloud; RabbitMQ protege el tramo ingreso-procesamiento.

### 7.3 Deduplicacion local

La deduplicacion local evita que una misma observacion vuelva a salir por:

- un nuevo scrape sin cambio;
- una repeticion del ciclo;
- un reinicio del MAD;
- un reintento del mismo envelope.

Su identidad depende de la fuente, el asset, el tipo de observacion, el estado y la ventana temporal definida.

### 7.4 Deduplicacion cloud

La deduplicacion cloud resuelve problemas de alcance mayor:

- el mismo hallazgo enviado por OpenVAS y Nessus;
- el mismo evento recibido desde dos appliances;
- reenvio del mismo envelope por falta de confirmacion;
- duplicados generados por consumidores paralelos.

La nube debe conservar tambien las evidencias de origen. Deduplicar no significa borrar la procedencia.

### 7.5 Semantica de entrega

La plataforma utilizara `at-least-once` como garantia operacional.

Esto significa:

- un evento no se elimina antes de tener una confirmacion durable;
- un timeout puede provocar una repeticion del mensaje;
- el consumidor debe ser idempotente;
- `delivery_id` identifica el envelope;
- `record_id` identifica el hecho logico;
- el backend debe aceptar un `Idempotency-Key` o aplicar una regla equivalente.

## 8. Multi-tenancy

### 8.1 Modelo inicial

La primera topologia recomendada es:

```text
Un appliance -> un cliente/tenant -> varias fuentes de ese cliente
```

Esto reduce el riesgo de mezclar credenciales, estados y datos durante la primera implementacion.

El modelo puede evolucionar posteriormente a varios grupos de fuentes por appliance, pero el tenant debe continuar siendo una identidad segura y no un campo libre enviado por el conector.

### 8.2 Enrolamiento

Cada MAD debe registrarse antes de enviar datos. El proceso esperado es:

1. La plataforma crea un tenant.
2. La plataforma genera una credencial o certificado de enrolamiento.
3. El operador configura el MAD con esa credencial.
4. El MAD solicita o recibe una identidad permanente.
5. La nube asocia esa identidad con un tenant y un appliance.
6. Los envelopes posteriores se aceptan solo si la identidad es valida.

No se debe confiar solamente en un `tenant_id` enviado dentro del JSON.

### 8.3 Aislamiento

El tenant debe estar presente y validado en:

- identidad del appliance;
- autenticacion del ingreso;
- envelope;
- record y asset cuando corresponda;
- clave de persistencia;
- filtros de consulta;
- logs y metricas;
- permisos del dashboard.

Un error de tenant debe ser tratado como fallo de seguridad, no como un error normal de procesamiento.

## 9. Persistencia

### 9.1 Persistencia local

SQLite es suficiente para el MAD inicial porque se ejecutara como un proceso local por appliance y necesita durabilidad simple.

Debe conservar:

- estado del detector;
- cursores o fronteras de extraccion;
- envelopes pendientes;
- intentos y errores de entrega;
- records ya entregados para deduplicacion;
- resultados de ciclos para diagnostico.

Payloads excepcionalmente grandes podran pasar a un spool de archivos con referencia desde SQLite.

### 9.2 Persistencia cloud

DynamoDB es una opcion adecuada para la primera persistencia cloud si el acceso principal es por tenant, asset, record y tiempo.

La decision final debe considerar:

- volumen esperado;
- consultas reales del dashboard;
- retencion;
- costo;
- necesidades de busqueda libre;
- requisitos de auditoria.

No se debe incorporar OpenSearch solo porque permite busquedas avanzadas si aun no existe ese volumen o necesidad.

## 10. Componentes cloud por etapas

### 10.1 RabbitMQ

RabbitMQ se ubicara en la nube y no en cada MAD.

Se implementara cuando exista un ingreso cloud real y al menos una necesidad comprobada de desacoplar productores y consumidores.

Colas iniciales posibles:

- `ingestion`;
- `processing`;
- `failed` o dead-letter.

No se empezara con una cola por cada microservicio. Las colas se separaran cuando haya consumidores, escalamiento o politicas distintas que lo justifiquen.

### 10.2 Redis

Redis sera una optimizacion cloud, no un requisito del MAD.

Se incorporara si aparece alguna de estas necesidades:

- varios workers que requieren locks distribuidos;
- cache de enriquecimiento con alto volumen;
- rate limiting central;
- deduplicacion temporal de muy baja latencia;
- coordinacion de tareas que DynamoDB no resuelva de forma simple.

Mientras el sistema tenga pocos workers, la persistencia principal y las operaciones atomicas pueden resolverse con el almacenamiento cloud elegido.

### 10.3 Prometheus y Grafana

No son necesarios para probar la extraccion inicial. El dashboard local y los logs son suficientes para el laboratorio.

En la nube si seran recomendables desde el primer entorno operativo estable para medir:

- ciclos por tenant;
- latencia de ingreso;
- mensajes pendientes;
- reintentos;
- errores por conector;
- profundidad de colas;
- consumo y saturacion.

Prometheus recolectara metricas tecnicas. Grafana mostrara la salud de la plataforma. No reemplazan el dashboard de eventos de seguridad.

### 10.4 OpenSearch

OpenSearch sera una fase posterior.

Se justificara cuando exista:

- volumen historico elevado;
- necesidad de texto libre o filtros complejos;
- tendencias de largo plazo;
- analisis exploratorio de multiples campos;
- consultas que ya no sean practicas en DynamoDB y APIs especializadas.

La ausencia inicial de OpenSearch no impide entregar eventos, estados, hallazgos ni un dashboard basico.

## 11. Dashboard local y dashboard central

### 11.1 Dashboard local del MAD

El dashboard local actual es una herramienta de operacion y diagnostico.

Debe mostrar:

- ultimo ciclo ejecutado;
- resultado de la lectura;
- monitores en seguimiento;
- eventos detectados;
- envelopes pendientes;
- entregas exitosas;
- envelopes apartados;
- ultimos errores;
- estado de los reintentos.

No debe considerarse el dashboard multi-tenant definitivo.

### 11.2 Dashboard central

El dashboard central sera una aplicacion cloud con autenticacion y autorizacion por tenant.

Debe mostrar progresivamente:

- activos y su estado;
- eventos de disponibilidad;
- hallazgos de vulnerabilidad;
- evidencias por fuente;
- tendencias;
- incidentes correlacionados;
- salud de los appliances;
- filtros por tenant, fuente, severidad y tiempo.

El dashboard central debe consumir la API cloud y no leer directamente las bases SQLite de los MAD.

## 12. Plan de implementacion

### Fase 0: cierre del modelo actual

Objetivo: confirmar que el nucleo actual representa correctamente una fuente real.

Trabajo:

- aprobar contrato canonico y versionado;
- aprobar identidad de asset, record y delivery;
- aprobar politica de nulos;
- aprobar regla de desaparicion y latido;
- validar el fixture real anonimizado;
- documentar la configuracion de Uptime Kuma.

Salida:

- contrato aprobado;
- fixture reproducible;
- criterios de aceptacion definidos.

### Fase 1: laboratorio MAD con Uptime Kuma remoto

Objetivo: probar el MAD contra una instancia en otra laptop o appliance.

Trabajo:

- configurar IP, puerto y credenciales;
- validar conectividad y firewall;
- ejecutar un ciclo unico;
- ejecutar ciclos continuos;
- observar el dashboard local;
- probar cambio `up` a `down` y regreso;
- probar desaparicion temporal;
- cortar la red y verificar el outbox;
- reiniciar el MAD y verificar continuidad;
- corregir credenciales y verificar recuperacion.

Salida:

- reporte de conectividad;
- eventos capturados;
- prueba de reinicio aprobada;
- evidencia de que no se pierde ni duplica el hecho logico.

### Fase 2: ingreso cloud minimo

Objetivo: sustituir el sink local por un endpoint cloud controlado.

Trabajo:

- crear endpoint HTTPS de ingreso;
- autenticar el appliance;
- validar envelope y version de schema;
- validar tenant desde la identidad del appliance;
- aceptar `delivery_id` y `record_id` de forma idempotente;
- confirmar solo despues de persistir el mensaje;
- devolver respuestas diferenciadas para errores temporales y permanentes;
- medir latencia y tamano de payload.

Salida:

- MAD enviando a un receptor cloud;
- reintento verificado;
- duplicado controlado por idempotencia;
- tenant rechazado cuando la credencial no corresponde.

### Fase 3: persistencia y procesamiento cloud inicial

Objetivo: separar ingreso, procesamiento y consulta.

Trabajo:

- incorporar cola cloud, inicialmente con una topologia simple;
- persistir envelopes y records por tenant;
- validar y normalizar de nuevo en la frontera cloud;
- conservar proveniencia y decisiones;
- exponer API de consulta;
- crear dashboard central minimo.

Salida:

- eventos consultables desde la nube;
- aislamiento probado entre tenants;
- reproceso controlado de mensajes fallidos;
- API estable para el dashboard.

### Fase 4: primeros conectores adicionales

Orden recomendado:

1. Zabbix;
2. Wazuh;
3. OpenVAS;
4. Nessus;
5. InsightVM.

El orden puede cambiar segun acceso, APIs disponibles y valor de negocio. Cada conector debe pasar por un ciclo completo propio antes de agregarlo al procesamiento central.

### Fase 5: enriquecimiento, deduplicacion y correlacion

Objetivo: agregar inteligencia central sin bloquear la ingestion.

Orden:

1. catalogos y metadatos basicos;
2. CVSS, EPSS u otras fuentes aprobadas;
3. deduplicacion entre fuentes;
4. agrupacion de evidencias;
5. correlacion de vulnerabilidad, alerta y disponibilidad;
6. reglas de severidad y routing.

La correlacion debe generar registros separados y trazables. No se deben modificar silenciosamente los eventos originales.

### Fase 6: observabilidad cloud

Objetivo: operar la plataforma de forma medible.

Trabajo:

- metricas Prometheus;
- dashboards Grafana;
- alertas de cola y errores;
- salud por appliance;
- salud por tenant;
- latencia por etapa;
- capacidad y retencion.

Esta fase es prioritaria antes de incorporar muchos clientes, pero no bloquea la prueba funcional del primer appliance.

### Fase 7: busqueda avanzada

Objetivo: habilitar analitica historica cuando los requisitos lo justifiquen.

Trabajo:

- evaluar volumen y consultas reales;
- decidir si DynamoDB es suficiente;
- incorporar OpenSearch solo con un caso de uso concreto;
- definir retencion, indices, costo y ciclo de vida;
- mover al indice solo la proyeccion necesaria, no necesariamente todo el payload.

## 13. Seguridad

Requisitos minimos:

- HTTPS obligatorio fuera del laboratorio;
- TLS verificado por defecto;
- credenciales de fuentes fuera del payload de negocio;
- secretos fuera del repositorio;
- autenticacion por appliance;
- identificacion cloud del tenant;
- rotacion de credenciales;
- permisos minimos por componente;
- redaccion de URLs que puedan contener tokens;
- validacion estricta de envelopes;
- limites de bytes, tiempo y frecuencia;
- logs sin contrasenas ni tokens;
- actualizaciones controladas del MAD.

El flag de HTTP inseguro solo debe usarse en la red local de laboratorio.

## 14. Operacion y fallos esperados

### Fuente Uptime Kuma no disponible

- el ciclo registra el error;
- el detector no avanza el contador de desaparicion;
- el estado anterior se conserva;
- el siguiente ciclo reintenta la lectura.

### Nube no disponible

- la lectura local puede continuar segun la capacidad del outbox;
- los envelopes se conservan en SQLite;
- el delivery reintenta con backoff;
- la cola local debe tener limites de cantidad y bytes;
- ante backpressure se debe pausar o reducir la lectura antes de borrar pendientes.

### Reinicio del MAD

- se carga el estado del detector;
- se recuperan envelopes pendientes;
- no se reinicia todo como `initial` sin razon;
- los deliveries se reintentan con idempotencia.

### Error permanente de contrato

- el envelope queda apartado;
- se conserva la razon;
- no bloquea todos los siguientes;
- debe existir una forma de inspeccion y reproceso despues de corregir la causa.

## 15. Criterios de aceptacion de la primera entrega cloud

La primera entrega cloud no se considerara lista hasta comprobar:

- un MAD puede enrolarse sin editar manualmente el tenant dentro de cada envelope;
- una fuente real puede ser consultada desde la red del cliente;
- una caida de red no pierde envelopes;
- un reinicio no reemite todos los monitores como nuevos;
- un cambio de estado produce un record estable;
- un mismo record reenviado no se almacena dos veces;
- un envelope de otro tenant es rechazado;
- un error temporal vuelve a intentarse;
- un error permanente queda visible sin detener los demas mensajes;
- el dashboard central nunca puede consultar datos de otro tenant;
- los secretos no aparecen en logs, payloads ni repositorio;
- el sistema produce metricas suficientes para diagnosticar un fallo.

## 16. Riesgos y decisiones pendientes

### Riesgos

- depender de credenciales y APIs diferentes por cliente;
- cambios de version de las fuentes;
- crecimiento de la cola local durante cortes largos;
- costos cloud por retencion y consultas;
- errores de aislamiento multi-tenant;
- incorporar demasiados servicios antes de validar el flujo basico;
- duplicar normalizacion o deduplicacion sin definir identidades;
- crear una correlacion dificil de explicar o auditar.

### Decisiones pendientes

- proveedor y modalidad del RabbitMQ cloud;
- API de ingreso definitiva;
- mecanismo de enrolamiento de appliances;
- formato final de firma y compresion;
- retencion cloud por tipo de dato;
- modelo exacto de tablas DynamoDB;
- reglas de deduplicacion entre scanners;
- primer caso de correlacion;
- estrategia de actualizacion del contenedor MAD;
- requerimientos de disponibilidad y soporte.

## 17. Proyeccion de la solucion

### Corto plazo

Un MAD ejecutandose en un appliance, conectado a Uptime Kuma remoto, con SQLite, outbox, reintentos y dashboard local. Esta etapa demuestra la confiabilidad de la recoleccion y del estado local.

### Mediano plazo

Varios appliances enviando envelopes a un ingreso cloud autenticado. La nube valida, persiste y ofrece un dashboard central basico con aislamiento por tenant.

### Largo plazo

La plataforma incorpora multiples fuentes, procesamiento cloud desacoplado, enriquecimiento, deduplicacion global, correlacion y observabilidad central. Redis, Prometheus, Grafana y OpenSearch se agregan como capacidades cloud cuando los volumenes, los usuarios y los requisitos operativos los justifiquen.

## 18. Resultado esperado

La solucion final sera una plataforma multi-tenant con estas propiedades:

- cada cliente mantiene sus fuentes dentro de su red;
- el MAD recolecta y protege datos durante fallos locales o de red;
- la nube procesa y correlaciona de forma centralizada;
- los eventos mantienen identidad y proveniencia;
- los reintentos no producen duplicados logicos;
- el sistema puede comenzar pequeno sin instalar una plataforma completa en cada cliente;
- la arquitectura puede crecer sin obligar a redisenar el conector de cada fuente;
- la operacion puede observarse primero localmente y despues de forma centralizada;
- los componentes avanzados se incorporan por necesidad, no por anticipacion.

La primera meta no es construir todos los servicios de una plataforma SIEM. La primera meta es demostrar un flujo confiable, trazable y multi-tenant desde una fuente real hasta un destino controlado. Cada fase posterior debe conservar esa simplicidad y agregar solo la complejidad que resuelva un problema comprobado.
