---
description: Cómo desplegar el agente InsightVM como servicio persistente
---

# Despliegue del Agente

Sigue estas instrucciones para asegurar que el agente corra de forma ininterrumpida.

## 1. Requisitos Previos
- Tener el entorno configurado y `.env` con credenciales válidas.
- Probar manualmente una vez para verificar la conexión al backend.

## 2. Despliegue en Linux (systemd)
1. Copia el archivo de servicio proporcionado en la guía de despliegue.
2. Ejecuta `sudo systemctl enable insightvm-agent.service`.
3. Verifica con `sudo systemctl status insightvm-agent.service`.

## 3. Despliegue en Windows (NSSM)
1. Usa `nssm install InsightVMAgent`.
2. Introduce las rutas de Python y el script.
3. Inicia el servicio desde `services.msc`.
