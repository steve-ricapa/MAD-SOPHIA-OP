FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

EXPOSE 8080

# Cambia AGENT_PATH para elegir integracion:
# - wazuh_integration/main.py
# - zabix_integration/agent.py
# - openVAS_integration/main.py
# - insightVM_integration/main.py
# - uptimekuma_integration/agent.py
ENV AGENT_PATH=wazuh_integration/main.py

CMD ["sh", "-c", "python ${AGENT_PATH}"]
