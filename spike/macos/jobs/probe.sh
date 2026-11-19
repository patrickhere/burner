for t in curl wget nslookup nc ip busybox; do printf '%s: ' $t; command -v $t || echo missing; done
nc 2>&1 | head -3
head -2 /etc/os-release
ip addr show eth0
ip route
cat /etc/resolv.conf
