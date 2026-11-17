FROM alpine:3.22
RUN apk add --no-cache git curl ca-certificates \
 && mkdir -p /overlay /mnt /var/tmp
COPY init /sbin/burner-init
RUN chmod 0755 /sbin/burner-init
