# Lab target only (never shipped): a stock Alpine OpenSSH server with password login disabled.
FROM alpine:3.22
RUN apk add --no-cache openssh-server \
    && ssh-keygen -A \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
