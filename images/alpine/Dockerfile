# pinned by digest like firecracker and the kernel. bump both lines together
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache git curl ca-certificates \
 && mkdir -p /overlay /mnt /var/tmp
COPY init /sbin/burner-init
RUN chmod 0755 /sbin/burner-init
