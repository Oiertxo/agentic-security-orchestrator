FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4
RUN echo "deb http://mirrors.ocf.berkeley.edu/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list

RUN apt-get update && \
    apt-get install -y \
    bash \
    iproute2 \
    iptables \
    iputils-ping \
    net-tools \
    ca-certificates \
    nmap \
    dnsutils \
    curl \
    wget \
    netcat-traditional \
    git \
    gnupg \
    build-essential \
    metasploit-framework \
    hydra \
    sqlmap \
    gobuster \
    ncrack \
    sshpass \
    tcpdump \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    python3-full \
    python-is-python3 \
    python3-colorama \
    python3-termcolor \
    python3-pyfiglet \
    python3-requests \
    python3-urllib3 \
    python3-bs4 \
    python3-lxml \
    python3-netaddr \
    perl \
    libnet-ssleay-perl \
    libio-socket-ssl-perl \
    libwww-perl \
    libcrypt-ssleay-perl \
    ruby \
    ruby-dev \
    rubygems \
    bundler \
    libffi-dev \
    libssl-dev \
    wordlists \
    set \
    && gunzip /usr/share/wordlists/rockyou.txt.gz \
    && sed -i '1i msfadmin' /usr/share/wordlists/metasploit/unix_users.txt \
    && sed -i '1i msfadmin' /usr/share/wordlists/metasploit/namelist.txt \
    && echo "msfadmin" >> /usr/share/wordlists/fasttrack.txt \
    && sort -o /usr/share/wordlists/fasttrack.txt /usr/share/wordlists/fasttrack.txt \
    && echo "msfadmin" >> /usr/share/wordlists/metasploit/unix_passwords.txt \
    && sort -o /usr/share/wordlists/metasploit/unix_passwords.txt /usr/share/wordlists/metasploit/unix_passwords.txt \
    && sed -i '1000i msfadmin' /usr/share/wordlists/rockyou.txt \
    && update-ca-certificates \
    && git config --global http.postBuffer 1048576000 \
    && git config --global http.lowSpeedLimit 0 \
    && git config --global http.lowSpeedTime 9999 \
    && GIT_SSL_NO_VERIFY=true git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY services/kali-engine/requirements.txt /opt/kali/requirements.txt

RUN pip install --no-cache-dir --break-system-packages \
    --trusted-host pypi.org \
    --trusted-host files.pythonhosted.org \
    -r /opt/kali/requirements.txt

WORKDIR /opt/kali/app

COPY services/kali-engine/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]