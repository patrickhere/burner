#!/bin/bash
# network tests: what a VM can reach. run as a sudoer, after burner net up. prints PASS/FAIL per test.
set -u
cd /tmp || exit 1
T=$(mktemp -d /tmp/burner-net-XXXX)
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  ($2)"; fail=$((fail+1)); }
check() { if [ "$1" = 0 ]; then ok "$2"; else bad "$2" "$3"; fi; }

# the run id from the json burner writes last on stderr with --json-fd 2
run_id() { tail -n 1 "$1" | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["result"]["id"])' 2>/dev/null; }
# logq FILE key=value ... : the stored log (burner log --json) has a row with
# all of them. key~value: value is in that list or string field
logq() { python3 -I - "$@" <<'PY'
import json, sys
log = json.load(open(sys.argv[1]))["result"]
def match(e, cond):
    if "~" in cond:
        k, v = cond.split("~", 1)
        return v in (e.get(k) or [])
    k, v = cond.split("=", 1)
    got = e.get(k)
    return (str(got).lower() if isinstance(got, bool) else str(got)) == v
sys.exit(0 if any(all(match(e, c) for c in sys.argv[2:]) for e in log["events"]) else 1)
PY
}
# logf FILE field : a top-level field of the stored log
logf() { python3 -I -c 'import json, sys; v = json.load(open(sys.argv[1]))["result"][sys.argv[2]]; print(str(v).lower() if isinstance(v, bool) else v)' "$@"; }

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

declare -A seen rebound
probes=""; blocked=(); targets=(); rebinds=()
# dns rebinding: a name that resolves to a blocked address is refused when the
# VM connects, the filter goes by address. sslip.io answers 10-1-0-1.sslip.io
# with 10.1.0.1. resolves-* says the resolver did hand out the private
# address; a resolver that refuses those makes the check moot, not passed
rebind() {  # name ip port
    local host="${2//./-}.sslip.io"
    probes+="p resolves-$1 \"nslookup $host | grep -qx 'Address: $2'\""$'\n'
    probes+="p rebind-$1 \"nc -z -w 4 $host $3\""$'\n'
    rebinds+=("$1 $2 $3 $host")
}
for c in "${candidates[@]}"; do
    read -r kind ip port <<< "$c"
    [ -n "${seen[$ip]:-}" ] && continue
    reach "$ip" "$port" || continue
    seen[$ip]=1
    name="$kind-$ip-$port"
    probes+="p $name \"nc -z -w 4 $ip $port\""$'\n'
    blocked+=("$name")
    targets+=("$ip $port")
    k=${kind%%-*}
    [ -z "${rebound[$k]:-}" ] && rebound[$k]=1 && rebind "$k" "$ip" "$port"
done
rebind metadata 169.254.169.254 80
rebind tap 172.29.217.1 22
[ -n "$gw" ] && probes+="p ping-gateway \"ping -c1 -W3 $gw\""$'\n' && blocked+=(ping-gateway)
# arp: the host must only answer for the tap's own gateway address
arp_target=$(ip -4 -o addr show scope global | awk '{split($4, x, "/"); print x[1]}' | grep -v '^172\.29\.217\.' | head -n 1)
[ -n "$arp_target" ] && probes+="p arp-host-$arp_target \"arping -c 2 -w 3 -I eth0 $arp_target\""$'\n' && blocked+=("arp-host-$arp_target")
echo "      ${#blocked[@]} host-side targets the host can reach"

# a name nobody else asks for, to find byte for byte in the log
capture="burner-$RANDOM$RANDOM.example.com"

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
p ipv6-route         "ip -6 route show | grep -v ^fe80 | grep -q ."
p ipv6-link          "ping -6 -c 2 -W 2 -I eth0 ff02::1 2>&1 | grep \"bytes from\" | grep -v \"from \$(ip -6 addr show dev eth0 scope link | grep -oE fe80[0-9a-f:]+):\" | grep -q ."
p name-capture       "nslookup '"$capture"'"
wait
cat /tmp/probe.*
'

expect() {  # file name OPEN|BLOCKED
    if grep -qx "$3 $2" "$1"; then ok "$4: $2 $3"; else bad "$4: $2" "got $(grep " $2\$" "$1" | cut -d' ' -f1)"; fi
}

# a second VM sits at 172.29.217.2 (it starts first) so other-vm is a real target
( sudo burner run --net web --ttl 8m --tag peer -- 'nc -lk -p 22 >/dev/null 2>&1 & sleep 400' </dev/null >/dev/null 2>&1 ) &
sleep 6

sudo burner run --net web --json-fd 2 -- "$PROBES" </dev/null > "$T/web.txt" 2> "$T/web.err"
for t in "${blocked[@]}" tap-host-side metadata other-vm dns-other-resolver smtp-out ssh-out ipv6-global ipv6-route ipv6-link; do
    expect "$T/web.txt" "$t" BLOCKED web
done
rebind_expect() {  # file mode
    for r in "${rebinds[@]}"; do
        read -r k _ _ host <<< "$r"
        if grep -qx "OPEN resolves-$k" "$1"; then
            expect "$1" "rebind-$k" BLOCKED "$2"
        else
            echo "SKIP  $2: rebind-$k  (the resolver didn't hand out $host's private address)"
        fi
    done
}
rebind_expect "$T/web.txt" web
# some clouds (github's runners on azure) drop all icmp from the host itself
web_open="dns https-github https-pypi https-npm https-crates"
if ping -c1 -W3 1.1.1.1 >/dev/null 2>&1; then web_open+=" ping-internet"; else echo "SKIP  web: ping-internet  (the host can't ping out either)"; fi
for t in $web_open; do expect "$T/web.txt" "$t" OPEN web; done

sudo burner run --net open -- "$PROBES" </dev/null > "$T/open.txt" 2>&1
for t in "${blocked[@]}" tap-host-side metadata other-vm dns-other-resolver smtp-out ipv6-global ipv6-route ipv6-link; do
    expect "$T/open.txt" "$t" BLOCKED open
done
rebind_expect "$T/open.txt" open
for t in ssh-out https-github dns; do expect "$T/open.txt" "$t" OPEN open; done
pv=$(sudo burner ls | awk '/ peer /{print $1}'); [ -n "$pv" ] && sudo burner kill "$pv" >/dev/null; wait 2>/dev/null

# the connection log of the web run, recorded on the host: the guest ran the
# probes, but every row here is what the host's filter saw
id=$(run_id "$T/web.err")
sudo burner log "$id" --json > "$T/web.log" 2>/dev/null
missing=""
for t in "${targets[@]}"; do
    read -r ip port <<< "$t"
    logq "$T/web.log" verdict=blocked kind=conn "dst=$ip" "port=$port" || missing+=" $ip:$port"
done
[ -n "$gw" ] && { logq "$T/web.log" verdict=blocked proto=icmp "dst=$gw" || missing+=" ping-$gw"; }
for t in "169.254.169.254 80" "172.29.217.1 22" "172.29.217.2 22"; do
    read -r ip port <<< "$t"
    logq "$T/web.log" verdict=blocked kind=conn "dst=$ip" "port=$port" || missing+=" $ip:$port"
done
[ -n "$id" ] && [ -z "$missing" ] && ok "log: every blocked target has a blocked row (${#targets[@]} host-side and 3 more)" \
  || bad "log: blocked rows" "id=$id missing:$missing"
logq "$T/web.log" verdict=blocked kind=conn dst=169.254.169.254 reason=special && \
  logq "$T/web.log" verdict=blocked kind=conn dst=172.29.217.1 reason=host
check $? "log: blocked rows say why (metadata special, the tap's gateway host)" "$(head -c 300 "$T/web.log")"
logq "$T/web.log" verdict=allowed kind=conn port=443 names~github.com outcome=answered
check $? "log: https to github allowed, answered, named github.com" "no such row"
logq "$T/web.log" verdict=allowed kind=dns dst=9.9.9.9 name=github.com qtype=A || logq "$T/web.log" verdict=allowed kind=dns dst=1.1.1.1 name=github.com qtype=A
check $? "log: the dns lookup for github.com, allowed" "no such row"
logq "$T/web.log" verdict=blocked kind=dns dst=8.8.8.8 name=github.com reason=not_resolver
check $? "log: dns to 8.8.8.8 blocked, with the name asked" "no such row"
logq "$T/web.log" kind=dns "name=$capture"
check $? "log: a name the guest made up, byte for byte ($capture)" "not in the log"
named=""
for r in "${rebinds[@]}"; do
    read -r k ip port host <<< "$r"
    grep -qx "OPEN resolves-$k" "$T/web.txt" || continue
    logq "$T/web.log" verdict=blocked "dst=$ip" "port=$port" "names~$host" && named+=" $k"
done
[ -n "$named" ] && ok "log: rebinding attempts show the name that pointed at the blocked address ($named)" \
  || bad "log: rebinding names" "none of ${#rebinds[@]} rows had the sslip.io name"
[ "$(logf "$T/web.log" complete)" = true ] && [ "$(logf "$T/web.log" lost)" = 0 ] && ok "log: complete, nothing lost" \
  || bad "log: complete" "complete=$(logf "$T/web.log" complete) lost=$(logf "$T/web.log" lost)"
# the summary is the last thing burner says before the json
last=$(grep '^burner: net web:' "$T/web.err" | tail -n 1)
[[ "$last" == *"burner log $id for all of it"* ]] && tail -n 2 "$T/web.err" | head -n 1 | grep -q '^burner: '
check $? "summary: on stderr, last before the json" "$last"

# what the guest says can't get into the log: a forged event line and a fake
# summary on both streams, garbage and a compression loop sent as dns, then
# a real connection. the reader survives the hostile dns and logs what follows
loop_dns='\000\001\001\000\000\001\000\000\000\000\000\000\300\014\000\001\000\001'
fake='{"k":"conn","proto":"tcp","sport":1,"dst":"6.6.6.6","port":443,"verdict":"allowed","reason":null}'
sudo burner run --net web --json-fd 2 -- "echo '$fake'; echo '$fake' >&2; echo 'burner: net web: 0 connections out, 0 blocked, 0 dns lookups (burner log burner-000000000000 for all of it)' >&2; printf 'garbage%.0s' 1 2 3 | nc -u -w 1 9.9.9.9 53; printf '$loop_dns' | nc -u -w 1 9.9.9.9 53; curl -s -o /dev/null https://github.com; echo done" </dev/null > "$T/forge.txt" 2> "$T/forge.err"; rc=$?
id=$(run_id "$T/forge.err")
sudo burner log "$id" --json > "$T/forge.log" 2>/dev/null
! logq "$T/forge.log" dst=6.6.6.6 && grep -q "^burner: net web: 1 connection out.*burner log $id " "$T/forge.err"
check $? "log: a guest can't forge rows or the summary" "$(grep '^burner: net' "$T/forge.err" | tr '\n' ' ')"
[ "$rc" = 0 ] && logq "$T/forge.log" kind=dns malformed=true && logq "$T/forge.log" verdict=allowed port=443 outcome=answered
check $? "log: hostile dns is logged as malformed, the reader lives on" "rc=$rc $(head -c 300 "$T/forge.log")"

# a flood of blocked attempts: past the itemization limit they're counted,
# not listed, and the allowed connection after it is still there
sudo burner run --net web --ttl 3m --json-fd 2 -- 'for b in $(seq 0 7); do for i in $(seq 1 200); do nc -z -w 1 10.254.$b.$i 80 & done; wait; done 2>/dev/null; curl -s -o /dev/null https://github.com; echo done' </dev/null > "$T/flood.txt" 2> "$T/flood.err"
id=$(run_id "$T/flood.err")
sudo burner log "$id" --json > "$T/flood.log" 2>/dev/null
ni=$(logf "$T/flood.log" not_itemized 2>/dev/null)
size=$(sudo stat -c %s "/run/burner/logs/$id.json" 2>/dev/null)
logq "$T/flood.log" verdict=allowed port=443 && [ "${ni:-0}" -gt 0 ] && [ "$(logf "$T/flood.log" complete)" = true ] && [ "${size:-9999999}" -le 1048576 ]
check $? "log: a flood of 1600 blocked attempts is counted ($ni not listed), the allowed one after it is listed, log ${size}B" "ni=$ni size=$size complete=$(logf "$T/flood.log" complete 2>/dev/null)"

# the reader going away under a running VM stops the VM: nothing unrecorded
( sudo burner run --net web --ttl 2m -- 'sleep 60' </dev/null > "$T/death.txt" 2>&1; echo "rc=$?" >> "$T/death.txt" ) &
dp=$!
for _ in $(seq 30); do pgrep -u burner-parse -f -- __read-netlog >/dev/null && break; sleep 1; done
sudo pkill -u burner-parse -f -- __read-netlog
wait "$dp"
grep -qx 'rc=125' "$T/death.txt" && grep -q 'network log reader stopped, VM stopped' "$T/death.txt" && [ -z "$(sudo burner ls | grep -v '^no VMs')" ]
check $? "log: a dead reader stops its VM (125)" "$(tr '\n' ' ' < "$T/death.txt")"

# the summary leaves stdout alone, and --log none says nothing
sudo burner run --net web --result tar -- 'echo hi > /out/a; nslookup github.com >/dev/null' </dev/null > "$T/res.tar" 2> "$T/res.err"
tar -tf "$T/res.tar" | grep -qx out/a && grep -q '^burner: net web: ' "$T/res.err"
check $? "summary: --result tar is still a tar, the summary on stderr" "$(tail -n 3 "$T/res.err" | tr '\n' ' ')"
out=$(sudo burner run --net web --log none -- 'nslookup github.com >/dev/null; echo ok' </dev/null 2>&1)
[ "$out" = ok ] && ok "summary: --log none prints nothing of the log" || bad "summary: --log none" "$out"

# explain names every target the suite found, or the range it's in, as blocked
sudo burner explain --net web --json > "$T/explain.json"; erc=$?
python3 -I - "$T/explain.json" "${targets[@]%% *}" 169.254.169.254 172.29.217.1 <<'PY'
import ipaddress, json, sys
e = json.load(open(sys.argv[1]))["result"]
nets = [ipaddress.ip_network(b["net"], strict=False) for b in e["blocked"]]
missing = [ip for ip in sys.argv[2:] if not any(ipaddress.ip_address(ip) in n for n in nets)]
print(" ".join(missing))
sys.exit(1 if missing else 0)
PY
check $? "explain: every blocked target is in a blocked range it lists (exit $erc)" "not listed"
[ "$erc" = 0 ] && ok "explain: the loaded filter matches this config" || bad "explain: filter" "exit $erc"
sudo nft list chain inet burner ingress | grep -q 'iifname "bn\*" meta nfproto ipv6 drop'
check $? "ipv6: taps' ipv6 is dropped before anything else sees it" "no such rule"

# doctor --probe: a VM per mode tries what it must not reach, the host's
# log and witness counters judge it. nothing may leak, ipv6 included
sudo burner doctor --probe --json > "$T/probe.json"; prc=$?
python3 -I - "$T/probe.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))["result"]
rows = [r for run in p["runs"] for r in run["rows"]]
bad = [r["target"] + ": " + r["host_saw"] for r in rows if not r["ok"] or r["host_saw"] == "leaked"]
v6 = [r for r in rows if r["kind"] == "ipv6"]
print("; ".join(bad))
sys.exit(1 if bad or not rows or not v6 or any(r["host_saw"] != "blocked" for r in v6) else 0)
PY
r=$?
[ "$prc" = 0 ] && [ "$r" = 0 ] && ok "doctor --probe: every row as expected, nothing leaked, ipv6 sent and dropped" \
  || bad "doctor --probe" "exit $prc $(head -c 400 "$T/probe.json")"
sudo nft list tables | grep -q burner_probe
[ $? = 1 ] && ok "doctor --probe: its witness table is gone after" || bad "probe leftovers" "$(sudo nft list tables)"

# the runs below compare what they print, so they leave out the network
# summary burner adds on stderr (--log none)

# fail closed: when the filter refresh fails, VMs lose their network, open
# connections included (a 90M download, cloudflare refuses over 100M). a config
# with a net.block entry that doesn't parse makes the refresh fail. the reaper
# timer is stopped meanwhile so a normal pass can't put the network back early
sudo burner config | sed 's|^block = \[\]|block = ["not-an-address"]|' | sudo tee /etc/burner/broken-block.toml >/dev/null
sudo systemctl stop burner-reap.timer
sudo burner reap
( sudo burner run --net web --log none --ttl 90s -- 'curl -s -o /var/tmp/d "https://speed.cloudflare.com/__down?bytes=90000000" & for i in $(seq 20); do sleep 2; wc -c < /var/tmp/d; done' </dev/null > "$T/fc.txt" 2>&1 ) &
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
after=$(sudo burner run --net web --log none -- 'nslookup github.com >/dev/null 2>&1 && echo ok' </dev/null 2>&1)
[ "$emptied" = yes ] && [ "$grew" -ge 3 ] && [ "$flat" = 1 ] && [ "$after" = ok ] \
  && ok "failed refresh: open connection cut, network back after the next good pass" \
  || bad "fail closed" "emptied=$emptied grew=$grew flat=$flat after=$after samples=$(tr '\n' ' ' < "$T/fc.txt")"

# spoofing: a VM that takes another address gets nothing through. nc has to
# get out from the real address first and the new address has to take, so a
# missing tool or a VM with no network can't read as held
out=$(sudo burner run --net open --log none -- 'for t in ip nc; do command -v $t >/dev/null || { echo "MISSING $t"; exit 0; }; done; nc -z -w 4 1.1.1.1 443 || { echo "NO BASELINE"; exit 0; }; ip addr flush dev eth0 && ip addr add 172.29.217.6/30 dev eth0 || { echo "SPOOF FAILED"; exit 0; }; ip route add default via 172.29.217.5 2>/dev/null; ip route add default via 172.29.217.1 dev eth0 onlink 2>/dev/null; ip route show default | grep -q . || { echo "NO ROUTE"; exit 0; }; if nc -z -w 4 1.1.1.1 443; then echo LEAK; else echo HELD; fi' </dev/null 2>&1)
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
logs=$(sudo nft list table inet burner | grep -cE 'chain l[tud]_bn|: jump l[tud]_bn|counter (n|over|up|down)_bn')
readers=$(pgrep -f -- '__read-netlog' | wc -l)
[ "$taps" = 0 ] && [ "$elems" = 0 ] && [ "$logs" = 0 ] && [ "$readers" = 0 ] && [ -z "$(sudo ls /run/burner/vms/)" ] \
  && [ -z "$(sudo ls /run/burner/netcount/ 2>/dev/null)" ] && ok "no leftover taps, nft elements, log chains, readers or state" \
  || bad "leftovers" "taps=$taps elems=$elems log=$logs readers=$readers"

echo "---- $pass passed, $fail failed"
[ "$fail" = 0 ]
