#!/bin/bash
# network tests: what a VM can reach. run as a sudoer, after burner net up. prints PASS/FAIL per test.
set -u
cd /tmp || exit 1
# the image every VM here boots: BURNER_TEST_IMG=debian sudo -E bash tests/network.sh
IMG=${BURNER_TEST_IMG:-alpine}
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
    probes+="p resolves-$1 \"nslookup $host | grep -qE '^Address( [0-9]+)?: $2( |\\\$)'\""$'\n'
    probes+="p rebind-$1 \"tcp $host $3\""$'\n'
    rebinds+=("$1 $2 $3 $host")
}
for c in "${candidates[@]}"; do
    read -r kind ip port <<< "$c"
    [ -n "${seen[$ip]:-}" ] && continue
    reach "$ip" "$port" || continue
    seen[$ip]=1
    name="$kind-$ip-$port"
    probes+="p $name \"tcp $ip $port\""$'\n'
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

# the tools the probes use, in any image: what the image lacks comes from its
# busybox if that has it, and tcp HOST PORT is a tcp connect with nc -z, or
# with bash where nc has no -z (debian's busybox). udp HOST PORT sends stdin
# as one datagram the same way, nc -u or bash. a tool that's still missing
# stays missing, and the probe that needs it says MISSING
PRE='
mkdir -p /tmp/probe-bin; PATH=/tmp/probe-bin:$PATH
for t in nc nslookup arping; do
    command -v $t >/dev/null || ! busybox --list 2>/dev/null | grep -qx $t || ln -s "$(command -v busybox)" /tmp/probe-bin/$t
done
if command -v nc >/dev/null && ! nc -z -w 1 127.0.0.1 9 2>&1 | grep -qiE "usage|invalid option|unrecognized option"; then
    printf "#!/bin/sh\nexec nc -z -w 4 \"\$1\" \"\$2\"\n" > /tmp/probe-bin/tcp
elif [ -x /bin/bash ]; then
    printf "#!/bin/bash\nexec 3<>\"/dev/tcp/\$1/\$2\"\n" > /tmp/probe-bin/tcp
fi
if command -v nc >/dev/null && ! nc -u -w 1 127.0.0.1 9 </dev/null 2>&1 | grep -qiE "usage|invalid option|unrecognized option"; then
    printf "#!/bin/sh\nexec nc -u -w 1 \"\$1\" \"\$2\"\n" > /tmp/probe-bin/udp
elif [ -x /bin/bash ]; then
    printf "#!/bin/bash\nexec cat > \"/dev/udp/\$1/\$2\"\n" > /tmp/probe-bin/udp
fi
for t in tcp udp; do [ -f /tmp/probe-bin/$t ] && chmod 755 /tmp/probe-bin/$t; done
'

# probes run inside the VM; each prints OPEN or BLOCKED, or MISSING when the
# image lacks its tool and BROKEN when the tool refused its arguments, so a
# probe that couldn't run never reads as blocked
# all probes at once: most of them are blocked and would each wait out their timeout
PROBES="$PRE"'
n=0
p() { n=$((n + 1)); (
    if ! command -v timeout >/dev/null || ! command -v grep >/dev/null || ! command -v "${2%% *}" >/dev/null; then echo "MISSING $1"
    elif timeout 6 sh -c "$2" >/tmp/probe-out.$n 2>&1; then echo "OPEN $1"
    elif grep -qiE "usage:|invalid option|unrecognized option|illegal option|applet not found" /tmp/probe-out.$n; then echo "BROKEN $1"
    else echo "BLOCKED $1"; fi ) > /tmp/probe.$n & }
'"$probes"'
p tap-host-side      "tcp 172.29.217.1 22"
p metadata           "tcp 169.254.169.254 80"
p other-vm           "tcp 172.29.217.2 22"
p dns-other-resolver "nslookup github.com 8.8.8.8"
p smtp-out           "tcp gmail-smtp-in.l.google.com 25"
p ssh-out            "tcp github.com 22"
p dns                "nslookup github.com"
p ping-internet      "ping -c1 -W3 1.1.1.1"
p https-github       "curl -sfS -m 10 -o /dev/null https://github.com"
p https-pypi         "curl -sfS -m 10 -o /dev/null https://pypi.org/simple/requests/"
p https-npm          "curl -sfS -m 10 -o /dev/null https://registry.npmjs.org/"
p https-crates       "curl -sfS -m 10 -o /dev/null https://index.crates.io/config.json"
p ipv6-global        "ip -6 addr show scope global | grep -q inet6"
p ipv6-route         "ip -6 route show | grep -v ^fe80 | grep -q ."
p ipv6-link          "ping -6 -c 2 -W 2 -I eth0 ff02::1 2>&1 | grep \"bytes from\" | grep -vE \"from \$(ip -6 addr show dev eth0 scope link | grep -oE fe80[0-9a-f:]+)(%eth0)?:\" | grep -q ."
p name-capture       "nslookup '"$capture"'"
wait
cat /tmp/probe.*
'

expect() {  # file name OPEN|BLOCKED
    if grep -qx "$3 $2" "$1"; then ok "$4: $2 $3"; else bad "$4: $2" "got $(grep " $2\$" "$1" | cut -d' ' -f1)"; fi
}

# a second VM sits at 172.29.217.2 (it starts first) so other-vm is a real
# target. it says PEER-READY with its address once its own listener takes a
# connection, and other-vm only counts as blocked after that, while it's
# still up
( sudo burner run --img "$IMG" --net web --ttl 8m --tag peer -- "$PRE"'(while :; do nc -l -p 22 </dev/null >/dev/null 2>&1; done) &
up=""; for i in $(seq 20); do tcp 127.0.0.1 22 2>/dev/null && { up=1; break; }; sleep 0.5; done
[ -n "$up" ] && echo "PEER-READY $(ip -4 -o addr show dev eth0 | awk "{print \$4}")"
sleep 400' </dev/null > "$T/peer.out" 2>&1 ) &
peer=no
for _ in $(seq 60); do grep -q '^PEER-READY 172\.29\.217\.2/' "$T/peer.out" 2>/dev/null && { peer=yes; break; }; sleep 1; done
# other-vm in mode $2's results $1, only with the peer listening
peer_check() {
    if [ "$peer" = yes ] && sudo burner ls | grep -q ' peer '; then
        expect "$1" other-vm BLOCKED "$2"
    else
        bad "$2: other-vm" "the peer VM wasn't up and listening at 172.29.217.2: $(tr '\n' ' ' < "$T/peer.out" | head -c 200)"
    fi
}

sudo burner run --img "$IMG" --net web --json-fd 2 -- "$PROBES" </dev/null > "$T/web.txt" 2> "$T/web.err"
for t in "${blocked[@]}" tap-host-side metadata dns-other-resolver smtp-out ssh-out ipv6-global ipv6-route ipv6-link; do
    expect "$T/web.txt" "$t" BLOCKED web
done
peer_check "$T/web.txt" web
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

sudo burner run --img "$IMG" --net open -- "$PROBES" </dev/null > "$T/open.txt" 2>&1
for t in "${blocked[@]}" tap-host-side metadata dns-other-resolver smtp-out ipv6-global ipv6-route ipv6-link; do
    expect "$T/open.txt" "$t" BLOCKED open
done
peer_check "$T/open.txt" open
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
sudo burner run --img "$IMG" --net web --json-fd 2 -- "$PRE""echo '$fake'; echo '$fake' >&2; echo 'burner: net web: 0 connections out, 0 blocked, 0 dns lookups (burner log burner-000000000000 for all of it)' >&2; printf 'garbage%.0s' 1 2 3 | udp 9.9.9.9 53; printf '$loop_dns' | udp 9.9.9.9 53; curl -s -o /dev/null https://github.com; echo done" </dev/null > "$T/forge.txt" 2> "$T/forge.err"; rc=$?
id=$(run_id "$T/forge.err")
sudo burner log "$id" --json > "$T/forge.log" 2>/dev/null
! logq "$T/forge.log" dst=6.6.6.6 && grep -q "^burner: net web: 1 connection out.*burner log $id " "$T/forge.err"
check $? "log: a guest can't forge rows or the summary" "$(grep '^burner: net' "$T/forge.err" | tr '\n' ' ')"
[ "$rc" = 0 ] && logq "$T/forge.log" kind=dns malformed=true && logq "$T/forge.log" verdict=allowed port=443 outcome=answered
check $? "log: hostile dns is logged as malformed, the reader lives on" "rc=$rc $(head -c 300 "$T/forge.log")"

# a flood of blocked attempts: past the itemization limit they're counted,
# not listed, and the allowed connection after it is still there. a bash
# connect per attempt (debian) is too slow to get past the limit, so where
# there's python3 one process sends them, 2ms apart
flood='import socket, time
for b in range(8):
    for i in range(1, 201):
        s = socket.socket()
        s.setblocking(False)
        try:
            s.connect((socket.inet_ntoa(bytes([10, 254, b, i])), 80))
        except OSError:
            pass
        s.close()
        time.sleep(0.002)'
sudo burner run --img "$IMG" --net web --ttl 3m --json-fd 2 -- "$PRE"'if command -v python3 >/dev/null; then python3 -c "'"$flood"'"; else for b in $(seq 0 7); do for i in $(seq 1 200); do timeout 1 tcp 10.254.$b.$i 80 & done; wait; done 2>/dev/null; fi; curl -s -o /dev/null https://github.com; echo done' </dev/null > "$T/flood.txt" 2> "$T/flood.err"
id=$(run_id "$T/flood.err")
sudo burner log "$id" --json > "$T/flood.log" 2>/dev/null
ni=$(logf "$T/flood.log" not_itemized 2>/dev/null)
# the log as the run's record keeps it, serialized the way burner caps it
size=$(sudo burner log "$id" --json 2>/dev/null | python3 -I -c 'import json, sys; r = json.load(sys.stdin)["result"]; r.pop("run"); print(len(json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode()))' 2>/dev/null)
logq "$T/flood.log" verdict=allowed port=443 && [ "${ni:-0}" -gt 0 ] && [ "$(logf "$T/flood.log" complete)" = true ] && [ "${size:-9999999}" -le 1048576 ]
check $? "log: a flood of 1600 blocked attempts is counted ($ni not listed), the allowed one after it is listed, log ${size}B" "ni=$ni size=$size complete=$(logf "$T/flood.log" complete 2>/dev/null)"

# a run stopped (ctrl-c) while its VM keeps trying blocked addresses: the
# reader stays until the VM is gone, so the log is still complete
( sudo burner run --tag intlog --img "$IMG" --net web --ttl 2m --json-fd 2 -- "$PRE"'i=0; while :; do i=$((i + 1)); timeout 1 tcp 10.254.9.$((i % 200 + 1)) 80; sleep 0.02; done' </dev/null >/dev/null 2>"$T/int.err"; echo "rc=$?" > "$T/int.rc" ) &
ip=$!
for _ in $(seq 60); do sudo burner ls | grep -q ' intlog ' && break; sleep 0.5; done
sleep 5
sudo pkill -INT -f '^burner run --tag intlog'
wait "$ip"
id=$(run_id "$T/int.err")
sudo burner log "$id" --json > "$T/int.log" 2>/dev/null
grep -qx 'rc=130' "$T/int.rc" && logq "$T/int.log" verdict=blocked port=80 && [ "$(logf "$T/int.log" complete)" = true ]
check $? "log: a run stopped mid-attempts still has a complete log" "$(cat "$T/int.rc") complete=$(logf "$T/int.log" complete 2>/dev/null) lost=$(logf "$T/int.log" lost 2>/dev/null)"

# the reader going away under a running VM stops the VM: nothing unrecorded
( sudo burner run --img "$IMG" --net web --ttl 2m -- 'sleep 60' </dev/null > "$T/death.txt" 2>&1; echo "rc=$?" >> "$T/death.txt" ) &
dp=$!
for _ in $(seq 30); do pgrep -u burner-parse -f -- __read-netlog >/dev/null && break; sleep 1; done
sudo pkill -u burner-parse -f -- __read-netlog
wait "$dp"
grep -qx 'rc=125' "$T/death.txt" && grep -q 'network log reader stopped, VM stopped' "$T/death.txt" && [ -z "$(sudo burner ls | grep -v '^no VMs')" ]
check $? "log: a dead reader stops its VM (125)" "$(tr '\n' ' ' < "$T/death.txt")"

# the same while the VM is still starting: the reader killed as soon as it
# shows up, before or after it said it's ready. the run never goes on
# without it, it ends 125 either way
( sudo burner run --img "$IMG" --net web --ttl 2m -- 'echo RAN; sleep 30' </dev/null > "$T/early.txt" 2>&1; echo "rc=$?" >> "$T/early.txt" ) &
ep=$!
for _ in $(seq 600); do sudo pkill -u burner-parse -f -- __read-netlog && break; sleep 0.05; done
wait "$ep"
grep -qx 'rc=125' "$T/early.txt" && grep -qE "network log reader (stopped|didn't start)" "$T/early.txt" && [ -z "$(sudo burner ls | grep -v '^no VMs')" ]
check $? "log: a reader killed while its VM starts ends the run (125)" "$(tr '\n' ' ' < "$T/early.txt")"

# the summary leaves stdout alone, and --log none says nothing
sudo burner run --img "$IMG" --net web --result tar -- "$PRE"'echo hi > /out/a; nslookup github.com >/dev/null' </dev/null > "$T/res.tar" 2> "$T/res.err"
tar -tf "$T/res.tar" | grep -qx out/a && grep -q '^burner: net web: ' "$T/res.err"
check $? "summary: --result tar is still a tar, the summary on stderr" "$(tail -n 3 "$T/res.err" | tr '\n' ' ')"
out=$(sudo burner run --img "$IMG" --net web --log none -- "$PRE"'nslookup github.com >/dev/null; echo ok' </dev/null 2>&1)
[ "$out" = ok ] && ok "summary: --log none prints nothing of the log" || bad "summary: --log none" "$out"

# the run log: every run and shell is kept, with a network or without, in
# paths.root (it outlives a reboot), root's alone, with its command line
# escaped and cut at 300 characters
cmd="$PRE"'curl -s -o /dev/null https://github.com; : '"$(printf 'x%.0s' $(seq 400))"'; exit 3'
sudo burner run --img "$IMG" --net web --tag rlog --json-fd 2 -- "$cmd" </dev/null >/dev/null 2>"$T/rl.err"
rid=$(run_id "$T/rl.err")
sudo burner run --img "$IMG" --json-fd 2 -- 'echo none' </dev/null >/dev/null 2>"$T/rn.err"
nid=$(run_id "$T/rn.err")
sudo burner log --list --json > "$T/rl.list" 2>/dev/null; lrc=$?
sudo burner log "$rid" --json > "$T/rl.log" 2>/dev/null
sudo burner log "$nid" --json > "$T/rn.log" 2>/dev/null
sudo burner log "$rid" > "$T/rl.txt" 2>/dev/null
# the owner is who sudo says ran it: you, or root when the suite runs as root
owner=$(sudo sh -c 'echo "${SUDO_UID:-0}"')
python3 -I - "$T" "$rid" "$nid" "$owner" "$lrc" <<'PY'
import json, sys
t, rid, nid, me, lrc = sys.argv[1:]
runs = json.load(open(t + "/rl.list"))["result"]["runs"]
ids = [r["id"] for r in runs]
r = next(x for x in runs if x["id"] == rid)
n = next(x for x in runs if x["id"] == nid)
assert lrc == "0" and ids.index(nid) < ids.index(rid), ids[:5]
assert (r["host"], r["net"], r["tag"], r["exit"], r["rc"], r["outcome"], r["owner"]) == (None, "web", "rlog", 3, 3, "exited", int(me)), r
assert r["allowed"] >= 1 and n["net"] == "none" and n["allowed"] is None and "result" not in r, (r, n)
log = json.load(open(t + "/rl.log"))["result"]
assert log["id"] == rid and log["events"] and log["run"]["id"] == rid and "network" not in log["run"]["result"], log["run"]
c = log["run"]["command"]
assert len(c) == 300 and "\n" not in c and c.startswith("\\nmkdir -p /tmp/probe-bin"), c[:80]
none = json.load(open(t + "/rn.log"))["result"]
assert (none["net"], none["events"], none["complete"], none["run"]["result"]["outcome"]) == ("none", [], True, "exited"), none
PY
check $? "run log: a web run and a --net none run are both kept, newest first, command cut at 300" "$(head -c 300 "$T/rl.list")"
head -n 1 "$T/rl.txt" | grep -qE "^20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}  local  $IMG  exit 3  \\\\nmkdir" \
  && sed -n 2p "$T/rl.txt" | grep -q "^$rid: net web, "
check $? "run log: burner log opens with date, host, image, exit and command" "$(head -n 2 "$T/rl.txt" | cut -c 1-120 | tr '\n' ' ')"
grep -q '^burner:   reached: github.com' "$T/rl.err"
check $? "summary: says where the run went (reached: github.com)" "$(grep '^burner: ' "$T/rl.err" | tr '\n' ' ')"
rec=/var/lib/burner/logs/$owner/$rid.json
[ "$(sudo stat -c '%U %a' "$rec" 2>/dev/null)" = "root 600" ] && [ "$(sudo stat -c '%U %a' "$(dirname "$rec")" 2>/dev/null)" = "root 700" ] \
  && [ "$(sudo stat -c '%a' /var/lib/burner/logs)" = 700 ] && ! sudo test -e "/run/burner/logs/$rid.json"
check $? "run log: kept in /var/lib/burner/logs, root only, nothing in the state dir" "rec=$rec $(sudo ls -la /var/lib/burner/logs 2>&1 | head -n 3 | tr '\n' ' ')"
# without sudo: only your -H copies, and a line on how to see this machine's.
# the suite can run as root itself (sudo bash tests/network.sh): then "you"
# is the sudo caller, or nobody when there's none
if [ "$(id -u)" = 0 ]; then me=${SUDO_UID:-0}; else me=$(id -u); fi
[ "$me" = 0 ] && me=$(id -u nobody 2>/dev/null || echo 0)
as_me() {
    if [ "$(id -u)" = 0 ]; then
        sudo -u "#$me" env -u SUDO_UID -u SUDO_GID -u SUDO_USER -u SUDO_COMMAND "$@"
    else
        "$@"
    fi
}
# root through sudo, as the caller would be
as_sudo() { if [ "$(id -u)" = 0 ]; then env SUDO_UID="$me" "$@"; else sudo "$@"; fi; }
if [ "$me" = 0 ]; then
    echo "SKIP  run log without sudo  (no user to be: no sudo caller and no nobody)"
else
    out=$(as_me burner log --list 2>&1); prc=$?
    as_me burner log "$rid" >/dev/null 2>"$T/pl.err"; pirc=$?
    [ "$prc" = 0 ] && [[ "$out" == *"sudo burner log --list"* ]] && [[ "$out" != *"$rid"* ]] && [ "$pirc" = 1 ] && grep -q "need root (sudo burner log $rid)" "$T/pl.err"
    check $? "run log: without sudo only your -H copies, and how to see this machine's runs" "rc=$prc/$pirc $(printf '%s' "$out" | head -c 200) $(head -c 200 "$T/pl.err")"
    # root reads the caller's -H copies only from files the caller owns, never
    # through a link, and none that claims to be this machine's own run
    U=$(as_me mktemp -d /tmp/burner-netu-XXXX)
    trap 'rm -rf "$T"; sudo rm -rf "$U"' EXIT
    as_me mkdir -p "$U/state/burner/logs" "$U/elsewhere"
    as_me python3 -I - "$U" "$me" <<'PY'
import json, sys
t, me = sys.argv[1], int(sys.argv[2])
def rec(id, host):
    h = {"record": 1, "burner": "0.3.1", "id": id, "host": host, "shell": False, "command": "echo copy", "img": "alpine",
         "net": "none", "tag": None, "owner": me, "started_unix": 1795000000, "secs": 1.0, "exit": 0, "outcome": "exited",
         "rc": 0, "allowed": None, "blocked": None, "newer": "a field this burner doesn't know"}
    return json.dumps(h) + "\n" + json.dumps({"id": id, "outcome": "exited", "rc": 0, "network": None}) + "\n"
d = t + "/state/burner/logs/"
open(d + "burner-aaaaaaaaaaaa@fakehost.json", "w").write(rec("burner-aaaaaaaaaaaa", "fakehost"))
open(t + "/elsewhere/burner-bbbbbbbbbbbb@fakehost.json", "w").write(rec("burner-bbbbbbbbbbbb", "fakehost"))
open(d + "burner-dddddddddddd.json", "w").write(rec("burner-dddddddddddd", None))
open(t + "/rootcopy", "w").write(rec("burner-cccccccccccc", "fakehost"))
PY
    as_me ln -s "$U/elsewhere/burner-bbbbbbbbbbbb@fakehost.json" "$U/state/burner/logs/burner-bbbbbbbbbbbb@fakehost.json"
    sudo install -o root -m 644 "$U/rootcopy" "$U/state/burner/logs/burner-cccccccccccc@fakehost.json"
    as_sudo env XDG_STATE_HOME="$U/state" burner log --list --json > "$T/sl.json" 2>/dev/null
    as_me env XDG_STATE_HOME="$U/state" burner log --list --json > "$T/ul.json" 2>/dev/null
    as_me env XDG_STATE_HOME="$U/state" burner log burner-aaaaaaaaaaaa > "$T/ua.txt" 2>/dev/null; uarc=$?
    python3 -I - "$T" "$rid" <<'PY'
import json, sys
t, rid = sys.argv[1:]
s = json.load(open(t + "/sl.json"))["result"]
u = json.load(open(t + "/ul.json"))["result"]
fake = {"burner-aaaaaaaaaaaa", "burner-bbbbbbbbbbbb", "burner-cccccccccccc", "burner-dddddddddddd"}
si = {r["id"] for r in s["runs"]}
ui = {r["id"] for r in u["runs"]}
assert si & fake == {"burner-aaaaaaaaaaaa"} and s["this_machine"], (si & fake, s["this_machine"])
assert ui & fake == {"burner-aaaaaaaaaaaa"} and rid not in ui and not u["this_machine"], (ui, u["this_machine"])
assert [r["host"] for r in s["runs"] if r["id"] == "burner-aaaaaaaaaaaa"] == ["fakehost"]
PY
    check $? "run log: -H copies are read only from files you own, never through a link, and never as this machine's" "$(head -c 300 "$T/sl.json")"
    [ "$uarc" = 0 ] && head -n 1 "$T/ua.txt" | grep -q '  fakehost  alpine  exit 0  echo copy$'
    check $? "run log: burner log ID finds a -H copy without sudo" "rc=$uarc $(head -c 200 "$T/ua.txt")"
    sudo rm -rf "$U"
    trap 'rm -rf "$T"' EXIT
fi

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
sudo burner doctor --probe --img "$IMG" --json > "$T/probe.json"; prc=$?
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
( sudo burner run --img "$IMG" --net web --log none --ttl 90s -- 'curl -s -o /var/tmp/d "https://speed.cloudflare.com/__down?bytes=90000000" & for i in $(seq 20); do sleep 2; wc -c < /var/tmp/d; done' </dev/null > "$T/fc.txt" 2>&1 ) &
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
after=$(sudo burner run --img "$IMG" --net web --log none -- "$PRE"'nslookup github.com >/dev/null 2>&1 && echo ok' </dev/null 2>&1)
[ "$emptied" = yes ] && [ "$grew" -ge 3 ] && [ "$flat" = 1 ] && [ "$after" = ok ] \
  && ok "failed refresh: open connection cut, network back after the next good pass" \
  || bad "fail closed" "emptied=$emptied grew=$grew flat=$flat after=$after samples=$(tr '\n' ' ' < "$T/fc.txt")"

# spoofing: a VM that takes another address gets nothing through. nc has to
# get out from the real address first and the new address has to take, so a
# missing tool or a VM with no network can't read as held
out=$(sudo burner run --img "$IMG" --net open --log none -- "$PRE"'for t in ip tcp timeout; do command -v $t >/dev/null || { echo "MISSING $t"; exit 0; }; done; timeout 6 tcp 1.1.1.1 443 2>/dev/null || { echo "NO BASELINE"; exit 0; }; ip addr flush dev eth0 && ip addr add 172.29.217.6/30 dev eth0 || { echo "SPOOF FAILED"; exit 0; }; ip route add default via 172.29.217.5 2>/dev/null; ip route add default via 172.29.217.1 dev eth0 onlink 2>/dev/null; ip route show default | grep -q . || { echo "NO ROUTE"; exit 0; }; if timeout 6 tcp 1.1.1.1 443 2>/dev/null; then echo LEAK; else echo HELD; fi' </dev/null 2>&1)
[ "$out" = HELD ] && ok "spoofed source address dropped" || bad "spoofing" "$out"

# none: no network interface at all
out=$(sudo burner run --img "$IMG" -- 'ls /sys/class/net | tr "\n" " "' </dev/null)
[ "$out" = "lo " ] && ok "--net none: only lo" || bad "--net none" "$out"

# bandwidth: ~2.5 MB/s each way. best of two, since one slow transfer over the
# internet says nothing about the cap, and the cap is checked on the best one
best() { tr ' ' '\n' | sort -g | tail -n 1; }
down=$(sudo burner run --img "$IMG" --net web --ttl 180s -- 'for i in 1 2; do curl -s -m 60 -o /dev/null -w "%{speed_download} " "https://speed.cloudflare.com/__down?bytes=25000000"; done' </dev/null | best)
up=$(sudo burner run --img "$IMG" --net web --ttl 180s -- 'head -c 15000000 /dev/zero > /var/tmp/u; for i in 1 2; do curl -s -m 60 -o /dev/null -w "%{speed_upload} " -X POST --data-binary @/var/tmp/u https://speed.cloudflare.com/__up; done' </dev/null | best)
awk -v d="$down" -v u="$up" 'BEGIN{exit !(d > 500000 && d < 3300000 && u > 300000 && u < 5000000)}' \
  && ok "rate limited both ways: down $(awk -v d="$down" 'BEGIN{printf "%.1f", d/1e6}') MB/s, up $(awk -v u="$up" 'BEGIN{printf "%.1f", u/1e6}') MB/s" \
  || bad "rate limits" "down=$down up=$up"

# debian: apt-get update, the thing people use it for, works with --net web
# and fails with --net none, where it would otherwise only warn
if [ "$IMG" = debian ]; then
    w=$(sudo burner run --img "$IMG" --net web --log none --ttl 300s -- 'apt-get update -qq --error-on=any >/dev/null 2>&1; echo $?' </dev/null 2>&1)
    n=$(sudo burner run --img "$IMG" --ttl 120s -- 'timeout 60 apt-get update -qq --error-on=any >/dev/null 2>&1; echo $?' </dev/null 2>&1)
    [ "$w" = 0 ] && [ "$n" = 100 ] && ok "apt-get update works with --net web, fails with --net none" \
      || bad "apt-get update" "web=$w none=$n"
fi

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
