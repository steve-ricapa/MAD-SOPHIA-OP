FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY openVAS_integration /app/openVAS_integration
COPY insightVM_integration /app/insightVM_integration
COPY wazuh_integration /app/wazuh_integration
COPY zabix_integration /app/zabix_integration

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Cambia AGENT_PATH para elegir integracion:
# - wazuh_integration/main.py
# - zabix_integration/agent.py
# - openVAS_integration/main.py
# - insightVM_integration/main.py
ENV AGENT_PATH=wazuh_integration/main.py

CMD ["sh", "-c", "python ${AGENT_PATH}"]
