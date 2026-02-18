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

COPY services/recon-engine/requirements.txt /opt/recon/requirements.txt

RUN pip install --no-cache-dir \
    --trusted-host pypi.org \
    --trusted-host files.pythonhosted.org \
    -r /opt/recon/requirements.txt

COPY services/recon-engine/app /opt/recon/app
WORKDIR /opt/recon/app

COPY services/recon-engine/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5000