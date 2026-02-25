FROM ubuntu:22.04

# Install vulnerable OpenSSH config
RUN apt update && apt install -y openssh-server && \
    mkdir /var/run/sshd && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config && \
    echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]