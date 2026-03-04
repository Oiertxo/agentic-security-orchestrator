FROM python:3.12-slim

RUN echo "Acquire::https::Verify-Peer \"false\";" > /etc/apt/apt.conf.d/99verify-peer.conf && \
    echo "deb http://cdn-fastly.deb.debian.org/debian trixie main" > /etc/apt/sources.list && \
    echo "deb http://cdn-fastly.deb.debian.org/debian trixie-updates main" >> /etc/apt/sources.list

RUN apt-get update && \
    apt-get install -y \
    bash \
    iproute2 \
    iptables \
    iputils-ping \
    ca-certificates \
    nmap \
    dnsutils \
    curl \
    git \
    gnupg \
    build-essential \
    && update-ca-certificates \
    && GIT_SSL_NO_VERIFY=true git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]