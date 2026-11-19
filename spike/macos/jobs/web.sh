# web mode checks, run inside the guest. MACIP is the mac's own lan address
MACIP=${MACIP:-10.1.0.81}
t() {
    echo "\$ $*"
    s=$(date +%s)
    "$@" > /tmp/out 2>&1
    rc=$?
    head -6 /tmp/out
    echo "-> rc=$rc in $(( $(date +%s) - s ))s"
}
# allowed
t curl -sI -m 15 https://github.com
t curl -sI -m 15 http://github.com
t nslookup github.com
t nc -z -w 3 9.9.9.9 53
# 10 at once to the same address and port: each must land on its own host connection
parallel() {
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        curl -s -m 15 -o /dev/null -w '%{http_code}\n' https://api.github.com/zen &
    done | sort | uniq -c
}
t parallel
t curl -s -m 60 -o /dev/null -w '%{http_code} %{size_download} bytes %{speed_download} B/s\n' 'https://speed.cloudflare.com/__down?bytes=50000000'
# blocked
t nc -z -w 3 10.1.0.63 22
t nc -z -w 3 10.1.0.1 443
t nc -z -w 3 "$MACIP" 22
t nc -z -w 3 "$MACIP" 443
t nc -z -w 3 github.com 22
t nslookup github.com 8.8.8.8
t nc -z -w 3 8.8.8.8 53
t ping -c 1 -W 3 1.1.1.1
