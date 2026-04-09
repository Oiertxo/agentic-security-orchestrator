FROM ubuntu:16.04

# Install vulnerable OpenSSH config
RUN apt update && apt install -y openssh-server && \
    mkdir /var/run/sshd && \
    sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config && \
    echo 'root:password' | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]