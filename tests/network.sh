#!/bin/bash
# network tests: what a VM can reach. run as a sudoer, after burner net up. prints PASS/FAIL per test.
set -u
cd /tmp || exit 1
T=$(mktemp -d /tmp/burner-net-XXXX)
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  ($2)"; fail=$((fail+1)); }

if ! sudo burner config | grep -qx 'net = "open"'; then
    echo "network.sh tests --net open too: set net = \"open\" under [limits] in /etc/burner/config.toml"
    exit 1
fi

# targets a VM must never reach, found on this host: the default gateway, the
# host's own addresses and something behind every other route (VPNs, LANs,
# docker). only ones the host itself can reach count, so a BLOCKED result means
# burner blocked it, not that nothing was listening. add your own as
#   BURNER_TEST_TARGETS="10.0.0.5:22 192.168.1.10:8080" sudo -E bash tests/network.sh
reach() { timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }
candidates=()
gw=$(ip -4 route show default | awk '{print $3; exit}')
[ -n "$gw" ] && for port in 53 80 443 22; do candidates+=("gateway $gw $port"); done
for a in $(ip -4 -o addr show scope global | awk '{split($4, x, "/"); print x[1]}'); do
    case "$a" in 172.29.217.*) continue ;; esac
    for port in 22 80 443 53; do candidates+=("host-addr $a $port"); done
done
while read -r dst; do
    net=${dst%/*}; last=${net##*.}
    ip=${net%.*}.$((last + 1))
    for port in 22 80 443 53; do candidates+=("route-$dst $ip $port"); done
done < <(ip -4 route show table all | awk '$1 ~ /^[0-9]/ && $1 ~ /\// && $0 !~ /dev bn[0-9]/ {print $1}' \
    | grep -vE '^(127\.|172\.29\.217\.|224\.)' | sort -u)
for t in ${BURNER_TEST_TARGETS:-}; do candidates+=("extra ${t%:*} ${t##*:}"); done

declare -A seen
probes=""; blocked=()
for c in "${candidates[@]}"; do
    read -r kind ip port <<< "$c"
    [ -n "${seen[$ip]:-}" ] && continue
    reach "$ip" "$port" || continue
    seen[$ip]=1
    name="$kind-$ip-$port"
    probes+="p $name \"nc -z -w 4 $ip $port\""$'\n'
    blocked+=("$name")
done
[ -n "$gw" ] && probes+="p ping-gateway \"ping -c1 -W3 $gw\""$'\n' && blocked+=(ping-gateway)
# arp: the host must only answer for the tap's own gateway address
arp_target=$(ip -4 -o addr show scope global | awk '{split($4, x, "/"); print x[1]}' | grep -v '^172\.29\.217\.' | head -n 1)
[ -n "$arp_target" ] && probes+="p arp-host-$arp_target \"arping -c 2 -w 3 -I eth0 $arp_target\""$'\n' && blocked+=("arp-host-$arp_target")
echo "      ${#blocked[@]} host-side targets the host can reach"

# probes run inside the VM; each prints OPEN or BLOCKED, or MISSING when the
# image lacks its tool and BROKEN when the tool refused its arguments, so a
# probe that couldn't run never reads as blocked
# all probes at once: most of them are blocked and would each wait out their timeout
PROBES='
n=0
p() { n=$((n + 1)); (
    if ! command -v timeout >/dev/null || ! command -v grep >/dev/null || ! command -v "${2%% *}" >/dev/null; then echo "MISSING $1"
    elif timeout 6 sh -c "$2" >/tmp/probe-out.$n 2>&1; then echo "OPEN $1"
    elif grep -qiE "usage:|invalid option|unrecognized option|illegal option|applet not found" /tmp/probe-out.$n; then echo "BROKEN $1"
    else echo "BLOCKED $1"; fi ) > /tmp/probe.$n & }
'"$probes"'
p tap-host-side      "nc -z -w 4 172.29.217.1 22"
p metadata           "nc -z -w 4 169.254.169.254 80"
p other-vm           "nc -z -w 4 172.29.217.2 22"
p dns-other-resolver "nslookup github.com 8.8.8.8"
p smtp-out           "nc -z -w 4 gmail-smtp-in.l.google.com 25"
p ssh-out            "nc -z -w 4 github.com 22"
p dns                "nslookup github.com"
p ping-internet      "ping -c1 -W3 1.1.1.1"
p https-github       "curl -sfS -m 10 -o /dev/null https://github.com"
p https-pypi         "curl -sfS -m 10 -o /dev/null https://pypi.org/simple/requests/"
p https-npm          "curl -sfS -m 10 -o /dev/null https://registry.npmjs.org/"
p https-crates       "curl -sfS -m 10 -o /dev/null https://index.crates.io/config.json"
p ipv6-global        "ip -6 addr show scope global | grep -q inet6"
wait
cat /tmp/probe.*
'

expect() {  # file name OPEN|BLOCKED
    if grep -qx "$3 $2" "$1"; then ok "$4: $2 $3"; else bad "$4: $2" "got $(grep " $2\$" "$1" | cut -d' ' -f1)"; fi
}

# a second VM sits at 172.29.217.2 (it starts first) so other-vm is a real target
( sudo burner run --net web --ttl 8m --tag peer -- 'nc -lk -p 22 >/dev/null 2>&1 & sleep 400' </dev/null >/dev/null 2>&1 ) &
sleep 6

sudo burner run --net web -- "$PROBES" </dev/null > "$T/web.txt" 2>&1
for t in "${blocked[@]}" tap-host-side metadata other-vm dns-other-resolver smtp-out ssh-out ipv6-global; do
    expect "$T/web.txt" "$t" BLOCKED web
done
# some clouds (github's runners on azure) drop all icmp from the host itself
web_open="dns https-github https-pypi https-npm https-crates"
if ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; then web_open+=" ping-internet"; else echo "SKIP  web: ping-internet  (the host can't ping out either)"; fi
for t in $web_open; do expect "$T/web.txt" "$t" OPEN web; done

sudo burner run --net open -- "$PROBES" </dev/null > "$T/open.txt" 2>&1
for t in "${blocked[@]}" tap-host-side metadata other-vm dns-other-resolver smtp-out ipv6-global; do
    expect "$T/open.txt" "$t" BLOCKED open
done
for t in ssh-out https-github dns; do expect "$T/open.txt" "$t" OPEN open; done
pv=$(sudo burner ls | awk '/ peer /{print $1}'); [ -n "$pv" ] && sudo burner kill "$pv" >/dev/null; wait 2>/dev/null

# fail closed: when the filter refresh fails, VMs lose their network, open
# connections included (a 90M download, cloudflare refuses over 100M). a config
# with a net.block entry that doesn't parse makes the refresh fail. the reaper
# timer is stopped meanwhile so a normal pass can't put the network back early
sudo burner config | sed 's|^block = \[\]|block = ["not-an-address"]|' | sudo tee /etc/burner/broken-block.toml >/dev/null
sudo systemctl stop burner-reap.timer
sudo burner reap
( sudo burner run --net web --ttl 90s -- 'curl -s -o /var/tmp/d "https://speed.cloudflare.com/__down?bytes=90000000" & for i in $(seq 20); do sleep 2; wc -c < /var/tmp/d; done' </dev/null > "$T/fc.txt" 2>&1 ) &
fc=$!
sleep 12
emptied=no
for _ in 1 2 3 4 5; do
    sudo burner --config /etc/burner/broken-block.toml reap
    if ! sudo nft list set inet burner tap_ip | grep -q 'elements'; then emptied=yes; break; fi
    sleep 2
done
wait "$fc"
sudo rm -f /etc/burner/broken-block.toml
sudo burner reap
sudo systemctl start burner-reap.timer
# 20 samples, 2s apart: growing before, flat for the last 10 (from ~5s after the flush)
grew=$(head -n 5 "$T/fc.txt" | sort -un | wc -l)
flat=$(tail -n 10 "$T/fc.txt" | sort -u | wc -l)
after=$(sudo burner run --net web -- 'nslookup github.com >/dev/null 2>&1 && echo ok' </dev/null 2>&1)
[ "$emptied" = yes ] && [ "$grew" -ge 3 ] && [ "$flat" = 1 ] && [ "$after" = ok ] \
  && ok "failed refresh: open connection cut, network back after the next good pass" \
  || bad "fail closed" "emptied=$emptied grew=$grew flat=$flat after=$after samples=$(tr '\n' ' ' < "$T/fc.txt")"

# spoofing: a VM that takes another address gets nothing through. nc has to
# get out from the real address first and the new address has to take, so a
# missing tool or a VM with no network can't read as held
out=$(sudo burner run --net open -- 'for t in ip nc; do command -v $t >/dev/null || { echo "MISSING $t"; exit 0; }; done; nc -z -w 4 1.1.1.1 443 || { echo "NO BASELINE"; exit 0; }; ip addr flush dev eth0 && ip addr add 172.29.217.6/30 dev eth0 || { echo "SPOOF FAILED"; exit 0; }; ip route add default via 172.29.217.5 2>/dev/null; ip route add default via 172.29.217.1 dev eth0 onlink 2>/dev/null; if nc -z -w 4 1.1.1.1 443; then echo LEAK; else echo HELD; fi' </dev/null 2>&1)
[ "$out" = HELD ] && ok "spoofed source address dropped" || bad "spoofing" "$out"

# none: no network interface at all
out=$(sudo burner run -- 'ls /sys/class/net | tr "\n" " "' </dev/null)
[ "$out" = "lo " ] && ok "--net none: only lo" || bad "--net none" "$out"

# bandwidth: ~2.5 MB/s each way. best of two, since one slow transfer over the
# internet says nothing about the cap, and the cap is checked on the best one
best() { tr ' ' '\n' | sort -g | tail -n 1; }
down=$(sudo burner run --net web --ttl 180s -- 'for i in 1 2; do curl -s -m 60 -o /dev/null -w "%{speed_download} " "https://speed.cloudflare.com/__down?bytes=25000000"; done' </dev/null | best)
up=$(sudo burner run --net web --ttl 180s -- 'head -c 15000000 /dev/zero > /var/tmp/u; for i in 1 2; do curl -s -m 60 -o /dev/null -w "%{speed_upload} " -X POST --data-binary @/var/tmp/u https://speed.cloudflare.com/__up; done' </dev/null | best)
awk -v d="$down" -v u="$up" 'BEGIN{exit !(d > 500000 && d < 3300000 && u > 300000 && u < 5000000)}' \
  && ok "rate limited both ways: down $(awk -v d="$down" 'BEGIN{printf "%.1f", d/1e6}') MB/s, up $(awk -v u="$up" 'BEGIN{printf "%.1f", u/1e6}') MB/s" \
  || bad "rate limits" "down=$down up=$up"

# cleanup: no taps, set elements or state left
sleep 1
taps=$(ip -br link | grep -c '^bn')
elems=$(sudo nft -j list set inet burner tap_ip | grep -c '"elem"')
[ "$taps" = 0 ] && [ "$elems" = 0 ] && [ -z "$(sudo ls /run/burner/vms/)" ] && ok "no leftover taps, nft elements or state" \
  || bad "leftovers" "taps=$taps elems=$elems"

echo "---- $pass passed, $fail failed"
[ "$fail" = 0 ]
