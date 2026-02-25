FROM python:3.12-slim

RUN apt update && apt install -y \
    bash \
    iproute2 \
    iptables \
    iputils-ping \
    ca-certificates \
    nmap \
    dnsutils \
    && update-ca-certificates \
    && apt clean

COPY services/kali-engine/requirements.txt /opt/kali/requirements.txt

RUN pip install --no-cache-dir \
    --trusted-host pypi.org \
    --trusted-host files.pythonhosted.org \
    -r /opt/kali/requirements.txt

COPY services/kali-engine/app /opt/kali/app
WORKDIR /opt/kali/app

COPY services/kali-engine/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5000