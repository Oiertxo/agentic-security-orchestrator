FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    nmap \
    metasploit-framework \
    iputils-ping \
    && apt-get clean

WORKDIR /tools
CMD ["sleep", "infinity"]