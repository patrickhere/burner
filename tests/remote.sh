#!/bin/bash
# burner -H tests, over ssh to a private sshd on localhost. run as yourself,
# not root: the client refuses root. prints PASS/FAIL per test.
#
#   bash tests/remote.sh --fake-only   a stand-in burner on the far end: every
#                                      rule the client has, no kvm, mac or linux
#   bash tests/remote.sh               that, then the real burner installed at
#                                      /usr/local/bin through sudo -n (linux, kvm)
#
# BURNER picks the client binary (default: burner on PATH). nothing outside a
# temp dir is touched: the sshd, its keys, known_hosts, ssh config and
# hosts.toml all live there and go at the end. on a mac the client's copies
# of -H runs go in burner's own log store, and the stand-ins' go at the end
set -u
FAKE_ONLY=0
[ "${1:-}" = --fake-only ] && FAKE_ONLY=1
if [ "$(id -u)" = 0 ]; then
    echo "run this as yourself, not root: burner -H refuses root" >&2
    exit 2
fi
B=${BURNER:-$(command -v burner)}
case $B in /*) ;; *) B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B") ;; esac
# hosts.toml has to sit where nobody else can write, all the way up, and
# /tmp doesn't count: on linux the temp dir goes in your home
case $(uname -s) in
    Darwin) T=$(mktemp -d "${TMPDIR:-/tmp}/burner-remote-XXXX") ;;
    *) T=$(mktemp -d "$HOME/.burner-remote-XXXX") ;;
esac
T=$(cd "$T" && pwd -P)
chmod 700 "$T"
SSHD_PID=
cleanup() {
    [ -n "$SSHD_PID" ] && kill "$SSHD_PID" 2>/dev/null
    rm -rf "$T"
    # a mac keeps -H copies in burner's own store: the stand-ins' ids go
    [ "$(uname -s)" = Darwin ] && rm -f "$HOME/Library/Application Support/burner/logs/$(id -u)"/burner-{0123456789ab,feedfacecafe}@*.json
}
trap cleanup EXIT
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  ($2)"; fail=$((fail+1)); }
short() { tr '\n' ' ' < "$1" | head -c 300; }
# a python expression over the json on stdin, d
json_is() { python3 -I -c "import json,sys; d=json.loads(sys.stdin.read()); sys.exit(0 if ($1) else 1)"; }

# ---- the far end: a private sshd as you, three ports. the second one puts a
# sudo that always says no first on PATH, for the no-sudo-rule case, the third
# one a sudo rule without the lines for burner log and explain
ME=$(id -un)
ssh-keygen -q -t ed25519 -N '' -f "$T/hostkey" -C burner-test
ssh-keygen -q -t ed25519 -N '' -f "$T/otherkey" -C burner-test-other
ssh-keygen -q -t ed25519 -N '' -f "$T/userkey" -C burner-test-user
cp "$T/userkey.pub" "$T/authorized_keys"
mkdir -p "$T/nosudo-bin" "$T/xdg/burner"
printf '#!/bin/sh\nexit 1\n' > "$T/nosudo-bin/sudo"
chmod 755 "$T/nosudo-bin/sudo"
mkdir -p "$T/partsudo-bin"
printf '#!/bin/sh\n[ "$1 $2" = "-n -l" ] && case $4 in log|explain) exit 1 ;; esac\nexec /usr/bin/sudo "$@"\n' > "$T/partsudo-bin/sudo"
chmod 755 "$T/partsudo-bin/sudo"
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
P1=$(free_port); P2=$(free_port); P3=$(free_port); PDOWN=$(free_port)
cat > "$T/sshd_config" <<EOF
Port $P1
Port $P2
Port $P3
ListenAddress 127.0.0.1
HostKey $T/hostkey
AuthorizedKeysFile $T/authorized_keys
PidFile $T/sshd.pid
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers $ME
Match LocalPort $P2
    SetEnv PATH=$T/nosudo-bin:/usr/bin:/bin:/usr/sbin:/sbin
Match LocalPort $P3
    SetEnv PATH=$T/partsudo-bin:/usr/bin:/bin:/usr/sbin:/sbin
EOF
/usr/sbin/sshd -f "$T/sshd_config" -D -E "$T/sshd.log" &
SSHD_PID=$!
for _ in $(seq 50); do
    up=$(grep -c 'Server listening' "$T/sshd.log" 2>/dev/null)
    [ "${up:-0}" -ge 3 ] && break
    sleep 0.1
done
key=$(cut -d' ' -f1,2 "$T/hostkey.pub")
other=$(cut -d' ' -f1,2 "$T/otherkey.pub")
printf '[127.0.0.1]:%s %s\n' "$P1" "$key" "$P2" "$key" "$P3" "$key" > "$T/known_hosts"
printf '[127.0.0.1]:%s %s\n' "$P1" "$other" > "$T/bad_known_hosts"
: > "$T/empty_known_hosts"
cat > "$T/ssh_config" <<EOF
Host lo nokey badkey nosudo partsudo down
    HostName 127.0.0.1
    User $ME
Host lo nokey badkey
    Port $P1
Host nosudo
    Port $P2
Host partsudo
    Port $P3
Host down
    Port $PDOWN
Host nokey
    UserKnownHostsFile $T/empty_known_hosts
Host badkey
    UserKnownHostsFile $T/bad_known_hosts
Host *
    IdentityFile $T/userkey
    IdentitiesOnly yes
    IdentityAgent none
    UserKnownHostsFile $T/known_hosts
    GlobalKnownHostsFile /dev/null
    PasswordAuthentication no
    KbdInteractiveAuthentication no
EOF
printf '#!/bin/sh\nexec ssh -F %s "$@"\n' "$T/ssh_config" > "$T/ssh"
# an ssh that leaves something holding its output, like a ProxyCommand can
printf '#!/bin/sh\n[ "$1" = -G ] || sleep 20 &\nexec ssh -F %s "$@"\n' "$T/ssh_config" > "$T/ssh-linger"
chmod 755 "$T/ssh" "$T/ssh-linger"
export BURNER_SSH=$T/ssh XDG_CONFIG_HOME=$T/xdg
unset BURNER_HOST BURNER_BATCH
# the client's copies of -H runs, on linux. a mac keeps them in burner's own store
export XDG_STATE_HOME=$T/state

# ---- the stand-in burner: does what the command after -- asks
VERSION=$("$B" --version | head -n 1)
cat > "$T/fake-burner" <<EOF
#!/bin/sh
if [ "\$1" = --version ]; then echo "$VERSION"; exit 0; fi
T=$T
EOF
cat >> "$T/fake-burner" <<'EOF'
cmd=$1; shift
all=" $* "
n=; scen=
while [ $# -gt 0 ]; do
    case $1 in
        --remote) n=${2#1:}; shift 2 ;;
        --) shift; scen=${1:-}; break ;;
        *) shift ;;
    esac
done
rec() { printf 'burner-%s %s\n' "$n" "$*" >&2; }
id=burner-0123456789ab
status() {
    rec "status {\"schema\":1,\"burner\":\"x\",\"command\":\"$cmd\",\"host\":null,\"exit\":$1,\"ok\":true,\"result\":{\"id\":\"$id\",\"outcome\":\"$2\",\"rc\":$3,\"secs\":0.5${4:-}},\"errors\":[],\"warnings\":[]}"
}
tarred=',"result_tar":{"bytes":1,"delivered":true}'
case $cmd in
    ls)
        case $all in
            *" --json "*) echo '{"schema":1,"burner":"x","command":"ls","host":null,"exit":0,"ok":true,"result":{"vms":[]},"errors":[],"warnings":[]}' ;;
            *) printf '%s  evil\033]0;pwned\007tag\n' "$id" ;;
        esac
        exit 0 ;;
    images) echo alpine; exit 0 ;;
    log|explain) echo "fake $cmd${all% }"; exit 0 ;;
    doctor) echo "ok    fake         a stand-in burner"; echo works; exit 0 ;;
    shell)
        rec "start {\"id\":\"$id\"}"
        printf 'fake# '
        while IFS= read -r l; do
            case $l in
                size) stty size ;;
                osc) printf 'x\033]52;c;cHduZWQ=\007\033]0;title\007osc-done\n' ;;
                hang) sleep 300 ;;
                "exit "*) c=${l#exit }; status "$c" exited "$c"; exit "$c" ;;
                *) echo "got:$l" ;;
            esac
            printf 'fake# '
        done
        exit 0 ;;
    run) ;;
    *) echo "fake: $cmd" >&2; exit 2 ;;
esac
case $scen in
    code*) c=${scen#code}; rec "start {\"id\":\"$id\"}"; status "$c" exited "$c"; exit "$c" ;;
    nostatus) rec "start {\"id\":\"$id\"}"; exit 0 ;;
    forged)
        printf 'burner-00000000000000000000000000000000 status {"exit":0}\n' >&2
        status 3 exited 3; exit 3 ;;
    broken) rec "status not json"; exit 0 ;;
    unknown) rec "teleport now"; status 0 exited 0; exit 0 ;;
    liar) status 0 timeout null; exit 0 ;;
    huge) rec "status {\"x\":\"$(head -c 1400000 /dev/zero | tr '\0' a)\"}"; exit 0 ;;
    # a run's status with its connection log in it: as big as a stored log gets
    biglog) status 0 exited 0 ",\"network\":{\"pad\":\"$(head -c 1000000 /dev/zero | tr '\0' a)\"}"; exit 0 ;;
    skew) echo "error: unexpected argument '--remote' found" >&2; exit 2 ;;
    osc) printf 'a\033]52;c;cHduZWQ=\007b\033]0;title\007c\n'; status 0 exited 0; exit 0 ;;
    flood) head -c 10485760 /dev/zero | tr '\0' x; status 0 exited 0; exit 0 ;;
    argv) shift; printf '%s\0' "$@"; status 0 exited 0; exit 0 ;;
    stdin) cat; status 0 exited 0; exit 0 ;;
    sleep) rec "start {\"id\":\"$id\"}"; sleep 300 ;;
    tarevil) cat "$T/evil.tar"; status 0 exited 0 "$tarred"; exit 0 ;;
    tarclash) cat "$T/clash.tar"; status 0 exited 0 "$tarred"; exit 0 ;;
    targood) cat "$T/good.tar"; status 0 exited 0 "$tarred"; exit 0 ;;
    tarbig) head -c 280000000 /dev/zero; status 0 exited 0 "$tarred"; exit 0 ;;
esac
echo "fake: no scenario $scen" >&2
exit 2
EOF
chmod 755 "$T/fake-burner"
# a clean tar the way burner's parser writes one, and one with a symlink and
# a name that climbs out
python3 -I - "$T" <<'EOF'
import io, sys, tarfile
t = sys.argv[1]
def add(tf, name, data=b"", kind=tarfile.REGTYPE, link=""):
    i = tarfile.TarInfo(name); i.type = kind; i.linkname = link
    i.size = len(data) if kind == tarfile.REGTYPE else 0
    i.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
    tf.addfile(i, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
with tarfile.open(t + "/good.tar", "w", format=tarfile.GNU_FORMAT) as tf:
    add(tf, "out", kind=tarfile.DIRTYPE); add(tf, "out/f", b"hello\n"); add(tf, "log.txt", b"log\n"); add(tf, "rc", b"0\n")
with tarfile.open(t + "/evil.tar", "w", format=tarfile.GNU_FORMAT) as tf:
    add(tf, "out/l", kind=tarfile.SYMTYPE, link="/etc/passwd"); add(tf, "../../escape", b"x")
    add(tf, "out/dev", kind=tarfile.CHRTYPE); add(tf, "rc", b"0\n")
with tarfile.open(t + "/clash.tar", "w", format=tarfile.GNU_FORMAT) as tf:
    add(tf, "out/a", b"x"); add(tf, "out/a/b", b"y"); add(tf, "rc", b"0\n")
EOF

# drives a command on a pty: steps are "expect TEXT", "send TEXT" (with \r and
# \x03 escapes), "size ROWS COLS", "wait SECS", split by ";;". the whole
# terminal output goes to $T/pty.log
cat > "$T/drive.py" <<'EOF'
import os, pty, sys, time, select, struct, fcntl, termios, signal
i = sys.argv.index("--")
steps = [s.strip() for s in " ".join(sys.argv[1:i]).split(";;") if s.strip()]
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[i + 1], sys.argv[i + 1:])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
buf, pos, ok = b"", 0, True
def pump(t):
    global buf
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                d = os.read(fd, 65536)
            except OSError:
                return False
            if not d:
                return False
            buf += d
    return True
for s in steps:
    kind, _, arg = s.partition(" ")
    a = arg.encode().decode("unicode_escape").encode("latin-1")
    if kind == "expect":
        end = time.time() + 90
        while buf.find(a, pos) < 0 and time.time() < end and pump(0.1):
            pass
        j = buf.find(a, pos)
        if j < 0:
            print("MISSING", arg); ok = False; break
        pos = j + len(a)
    elif kind == "send":
        os.write(fd, a)
    elif kind == "size":
        r, c = map(int, arg.split())
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))
    elif kind == "wait":
        pump(float(arg))
t0, st = time.time(), None
while time.time() < t0 + 30:
    pump(0.1)
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        break
else:
    os.kill(pid, signal.SIGKILL); p, st = os.waitpid(pid, 0)
pump(0.2)
open(os.environ["DRIVE_LOG"], "wb").write(buf)
print("EXIT", os.waitstatus_to_exitcode(st), "SECS", round(time.time() - t0, 1), "OK" if ok else "FAILED")
EOF
drive() { DRIVE_LOG=$T/pty.log python3 -I "$T/drive.py" "$@"; }

# kills the far end's sshd processes for this test's sessions, not the listener
cut_sessions() {
    python3 -I - "$SSHD_PID" <<'EOF'
import os, signal, subprocess, sys
top = int(sys.argv[1])
kids = {}
for l in subprocess.run(["ps", "-A", "-o", "pid=,ppid=,comm="], capture_output=True, text=True).stdout.splitlines():
    f = l.split(None, 2)
    if len(f) >= 2:
        kids.setdefault(int(f[1]), []).append((int(f[0]), f[2] if len(f) > 2 else ""))
todo, found = [top], []
while todo:
    for pid, comm in kids.get(todo.pop(), []):
        todo.append(pid)
        if "sshd" in comm:
            found.append(pid)
for pid in found:
    os.kill(pid, signal.SIGKILL)
EOF
}

N=0123456789abcdef0123456789abcdef
cat > "$T/xdg/burner/hosts.toml" <<EOF
[hosts.lo]
addrs = ["192.0.2.1", "lo"]
connect_timeout = "1s"

[hosts.fake]
addrs = ["lo"]
burner = "$T/fake-burner"

[hosts.nosudo]
addrs = ["nosudo"]
burner = "$T/fake-burner"

[hosts.partsudo]
addrs = ["partsudo"]

[hosts.nokey]
addrs = ["nokey"]

[hosts.badkey]
addrs = ["badkey", "lo"]

[hosts.down]
addrs = ["192.0.2.1", "down"]
connect_timeout = "1s"

[hosts.nobin]
addrs = ["lo"]
burner = "$T/no-such-burner"
EOF
chmod 600 "$T/xdg/burner/hosts.toml"

if ! "$T/ssh" -o BatchMode=yes lo true </dev/null 2>"$T/ssh.err"; then
    echo "FAIL  the test sshd doesn't take the test key ($(short "$T/ssh.err"); $(short "$T/sshd.log"))"
    exit 1
fi

# ==== the client against the stand-in

# F1 the exit code is the one in the far end's record, 255 included
"$B" -H fake run -- code7 </dev/null >/dev/null 2>"$T/e"; r7=$?
"$B" -H fake run -- code255 </dev/null >/dev/null 2>"$T/e"; r255=$?
"$B" -H fake run -- code0 </dev/null >/dev/null 2>"$T/e"; r0=$?
[ "$r7" = 7 ] && [ "$r255" = 255 ] && [ "$r0" = 0 ] && ok "exit codes from the record: 7, 255, 0" \
  || bad "exit codes from the record" "7->$r7 255->$r255 0->$r0"

# F2 no record, a broken one, one of a kind nobody knows, one over the cap: 125
codes=
for s in nostatus broken unknown huge liar; do
    "$B" -H fake run -- "$s" </dev/null >/dev/null 2>"$T/e.$s"
    codes="$codes $s=$?"
done
[ "$codes" = " nostatus=125 broken=125 unknown=125 huge=125 liar=125" ] && grep -q "nothing it said counts" "$T/e.broken" \
  && grep -q "doesn't add up (outcome timeout with exit 0)" "$T/e.liar" \
  && ok "no end record, a broken one, an unknown kind, an oversized one, one that doesn't add up: 125" \
  || bad "broken records" "$codes $(short "$T/e.broken")"

# F2b a status with a 1M connection log in it is still a status
"$B" -H fake run --json-fd 3 -- biglog </dev/null >/dev/null 2>"$T/e" 3>"$T/biglog.js"; rc=$?
[ "$rc" = 0 ] && json_is 'len(d["result"]["network"]["pad"]) == 1000000 and d["host"] == "fake"' < "$T/biglog.js" \
  && ok "a status with a 1M network log gets through whole (0)" || bad "big status" "rc=$rc $(short "$T/e")"

# F3 a lookalike record without the nonce is only text, and changes nothing
"$B" -H fake run -- forged </dev/null >/dev/null 2>"$T/e"; rc=$?
[ "$rc" = 3 ] && grep -q 'burner-00000000000000000000000000000000 status' "$T/e" \
  && ok "a forged record is text, the real one decides (3)" || bad "forged record" "rc=$rc $(short "$T/e")"

# F4 a far end that doesn't take the arguments: the version message, 125
"$B" -H fake run -- skew </dev/null >/dev/null 2>"$T/e"; rc=$?
[ "$rc" = 125 ] && grep -q "didn't take the arguments (error: unexpected argument '--remote' found). update burner on fake" "$T/e" \
  && ok "version skew: 125 and says so" || bad "version skew" "rc=$rc $(short "$T/e")"

# F5 terminal escapes from the far end: escaped on a terminal, raw into a pipe
"$B" -H fake run -- osc </dev/null >"$T/o" 2>/dev/null; rc=$?
grep -q $'\033]52' "$T/o"; raw=$?
drive 'expect c ;; wait 0.5' -- "$B" -H fake run -- osc >/dev/null
if [ "$rc" = 0 ] && [ "$raw" = 0 ] && ! grep -q $'\033]' "$T/pty.log" && grep -q 'x1b]52' "$T/pty.log"; then
    ok "OSC 52 and titles from the far end escaped on a terminal, raw in a pipe"
else
    bad "escapes" "rc=$rc raw=$raw $(od -c "$T/pty.log" | head -3 | tr '\n' ' ')"
fi

# F6 a 10M flood comes through whole
"$B" -H fake run -- flood </dev/null 2>/dev/null | wc -c | tr -d ' ' > "$T/n"; n=$(cat "$T/n")
[ "$n" = 10485760 ] && ok "10M of output arrives whole" || bad "flood" "bytes=$n"

# F7 argv: the command reaches the far end as the same bytes
nasty=$'it\'s "q" \\ $(id) `id` ;!*~ %s =x\nline two\t\xc3\xa9'
"$B" -H fake run -- argv "$nasty" '' '--net open' -x </dev/null >"$T/argv" 2>"$T/e"; rc=$?
printf '%s\0' "$nasty" '' '--net open' -x > "$T/argv.want"
[ "$rc" = 0 ] && cmp -s "$T/argv" "$T/argv.want" && ok "hostile arguments arrive byte for byte" \
  || bad "argv" "rc=$rc $(od -c "$T/argv" | head -2 | tr '\n' ' ') $(short "$T/e")"

# F8 stdin goes to the far end as it is
head -c 300000 /dev/urandom > "$T/in"
"$B" -H fake run --in stdin -- stdin <"$T/in" >"$T/out" 2>"$T/e"; rc=$?
[ "$rc" = 0 ] && cmp -s "$T/in" "$T/out" && ok "--in stdin: 300K of random bytes there and back" \
  || bad "stdin" "rc=$rc $(short "$T/e")"

# F9 result tars, parsed again here: a clean one comes out as it was; links,
# devices and names that climb out are dropped; a file/dir clash, and a tar
# past the cap, are 125 with nothing written
names() { tar -tf "$1" 2>/dev/null | sed 's|/$||' | tr '\n' ' '; }
"$B" -H fake run --result tar -- targood </dev/null >"$T/good.out" 2>"$T/e"; rg=$?
"$B" -H fake run --result tar -- tarevil </dev/null >"$T/evil.out" 2>"$T/e.evil"; re=$?
"$B" -H fake run --result tar -- tarclash </dev/null >"$T/clash.out" 2>"$T/e.clash"; rc=$?
"$B" -H fake run --result tar -- tarbig </dev/null >"$T/big.out" 2>"$T/e.big"; rb=$?
[ "$rg" = 0 ] && [ "$(names "$T/good.out")" = "out out/f log.txt rc " ] && [ "$re" = 0 ] && [ "$(names "$T/evil.out")" = "rc " ] \
  && [ "$rc" = 125 ] && [ ! -s "$T/clash.out" ] && grep -q "didn't check out here" "$T/e.clash" \
  && [ "$rb" = 125 ] && [ ! -s "$T/big.out" ] \
  && ok "result tar parsed again here: clean passes, hostile entries dropped, a clash or oversize is 125 and empty" \
  || bad "result tar" "good=$rg ($(names "$T/good.out")) evil=$re ($(names "$T/evil.out")) clash=$rc $(short "$T/e.clash") big=$rb"

# the spool for a result tar goes whatever happened, an end that never came too
"$B" -H fake run --result tar -- nostatus </dev/null >/dev/null 2>&1
left=$(find "${XDG_RUNTIME_DIR:-/nonexistent}/burner" "/tmp/burner-$(id -u)" \
    "$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null)burner-$(id -u)" -name 'result-*' 2>/dev/null | wc -l | tr -d ' ')
[ "$left" = 0 ] && ok "no result spool left behind, after a good run or a broken one" || bad "spool left" "$left files"

# F10 --status-fd and --json-fd: the line as before, the json with the host
"$B" -H fake run --status-fd 3 --json-fd 4 -- code5 </dev/null >/dev/null 2>/dev/null 3>"$T/st" 4>"$T/js"; rc=$?
[ "$rc" = 5 ] && grep -q '^{"exit":5,"id":"burner-0123456789ab","outcome":"exited","rc":5,"secs":0.5}$' "$T/st" \
  && json_is 'd["host"] == "fake" and d["exit"] == 5 and d["result"]["outcome"] == "exited"' < "$T/js" \
  && ok "--status-fd line as before, --json-fd has the host" || bad "status and json fds" "rc=$rc $(short "$T/st") $(short "$T/js")"

# F11 no burner there, no sudo rule there: 125 with what to do
"$B" -H nobin run -- true </dev/null >/dev/null 2>"$T/e.nobin"; rn=$?
if [ "$(uname -s)" = Linux ]; then
    "$B" -H nosudo run -- code0 </dev/null >/dev/null 2>"$T/e.nosudo"; rs=$?
    grep -q "sudo wants a password for burner run" "$T/e.nosudo" || rs="$rs: $(short "$T/e.nosudo")"
else
    rs=125
fi
[ "$rn" = 125 ] && grep -q "no burner at $T/no-such-burner" "$T/e.nobin" && [ "$rs" = 125 ] \
  && ok "no burner there, no sudo rule there: 125 and what to do" || bad "nobin and nosudo" "nobin=$rn nosudo=$rs $(short "$T/e.nobin")"

# F12 nothing answers: 125, outcome unreachable in the json, never ssh's 255
"$B" -H down run --status-fd 3 --json-fd 4 -- true </dev/null >/dev/null 2>"$T/e" 3>"$T/st" 4>"$T/js"; rc=$?
[ "$rc" = 125 ] && grep -q '"outcome":"sandbox_error"' "$T/st" \
  && json_is 'd["host"] == "down" and d["errors"][0]["kind"] == "unreachable"' < "$T/js" \
  && grep -q "no address answered" "$T/e" && ok "unreachable: 125, kind unreachable, never 255" \
  || bad "unreachable" "rc=$rc $(short "$T/e") $(short "$T/js")"

# F13 a host key ssh doesn't know, and one that changed: refused, nothing
# added to known_hosts, and the changed one doesn't fall through to the next address
for f in known_hosts empty_known_hosts bad_known_hosts; do cp "$T/$f" "$T/$f.before"; done
"$B" -H nokey ls </dev/null >/dev/null 2>"$T/e.nokey"; rk=$?
"$B" -H badkey ls </dev/null >/dev/null 2>"$T/e.bad"; rb=$?
same=yes
for f in known_hosts empty_known_hosts bad_known_hosts; do cmp -s "$T/$f" "$T/$f.before" || same=no; done
[ "$rk" = 125 ] && grep -q "isn't known yet" "$T/e.nokey" && [ "$rb" = 125 ] \
  && grep -q "ssh refused badkey's host key. burner never accepts host keys itself: check it with ssh badkey, or use -H lo" "$T/e.bad" \
  && [ "$same" = yes ] && ok "unknown and changed host keys refused, known_hosts untouched" \
  || bad "host keys" "nokey=$rk changed=$rb untouched=$same $(short "$T/e.nokey") $(short "$T/e.bad")"

# F14 ls: a hostile tag escaped on a terminal, raw into a pipe, json has the host
drive 'expect tag ;; wait 0.3' -- "$B" -H fake ls >/dev/null
"$B" -H fake ls >"$T/ls.raw" 2>/dev/null; rl=$?
"$B" -H fake --json ls >"$T/ls.json" 2>/dev/null; rj=$?
! grep -q $'\033]' "$T/pty.log" && grep -q 'x1b]0;pwned' "$T/pty.log" && grep -q $'\033]0;pwned' "$T/ls.raw" \
  && [ "$rl" = 0 ] && [ "$rj" = 0 ] && json_is 'd["host"] == "fake" and d["command"] == "ls"' < "$T/ls.json" \
  && ok "ls: escaped on a terminal, raw in a pipe, --json names the host" \
  || bad "ls" "rl=$rl rj=$rj $(short "$T/ls.json")"

# F15 what doesn't go over -H, and -H as root
"$B" -H fake net show >/dev/null 2>"$T/e"; rn=$?
"$B" -H fake reap >/dev/null 2>&1; rr=$?
# a kill id that would be a flag on the far end never gets there
"$B" -H fake kill -Hother >/dev/null 2>&1; rk=$?
[ "$rk" = 2 ] || rr="$rr kill=$rk"
rroot=2
# linux only: sudo there is what a client user would type
if [ "$(uname -s)" = Linux ] && sudo -n true 2>/dev/null; then
    sudo -n env XDG_CONFIG_HOME="$XDG_CONFIG_HOME" BURNER_SSH="$BURNER_SSH" "$B" -H fake ls >/dev/null 2>"$T/e.root"; rroot=$?
    grep -q "drop the sudo" "$T/e.root" || rroot="$rroot: $(short "$T/e.root")"
fi
[ "$rn" = 2 ] && grep -q "runs on the machine itself" "$T/e" && [ "$rr" = 2 ] && [ "$rroot" = 2 ] \
  && ok "net and reap stay local, a kill id like a flag and -H as root are refused: exit 2" \
  || bad "refusals" "net=$rn reap+kill=$rr root=$rroot"

# F15b log and explain go over -H, their argv rebuilt from what was parsed
"$B" -H fake log burner-0123456789ab >"$T/lg" 2>&1; rl=$?
"$B" -H fake explain --net open --rules >"$T/ex" 2>&1; rx=$?
"$B" -H fake log ../../x >/dev/null 2>&1; rb=$?
"$B" -H fake explain --net lan >/dev/null 2>&1; rxb=$?
"$B" -H fake doctor --probe >/dev/null 2>"$T/e"; rp=$?
[ "$rl" = 0 ] && grep -qx "fake log burner-0123456789ab" "$T/lg" && [ "$rx" = 0 ] && grep -qx "fake explain --net open --rules" "$T/ex" \
  && [ "$rb" = 2 ] && [ "$rxb" = 2 ] && [ "$rp" = 2 ] && grep -q "doctor --probe runs on the machine itself" "$T/e" \
  && ok "log and explain go over -H as parsed, a bad log id, a bad --net and doctor --probe don't: exit 2" \
  || bad "log and explain over -H" "log=$rl explain=$rx badid=$rb badnet=$rxb probe=$rp $(short "$T/lg") $(short "$T/ex")"

# F16 BURNER_HOST picks the host, -H local overrides it
BURNER_HOST=fake "$B" run -- code9 </dev/null >/dev/null 2>&1; re=$?
BURNER_HOST=fake "$B" -H local version >"$T/v" 2>&1; rl=$?
[ "$re" = 9 ] && [ "$rl" = 0 ] && grep -q "^burner " "$T/v" && ok "BURNER_HOST, and -H local beats it" \
  || bad "BURNER_HOST" "env=$re local=$rl $(short "$T/v")"

# ssh's output still held open after it exited: nothing that came back counts
BURNER_SSH=$T/ssh-linger "$B" -H fake run -- code0 </dev/null >/dev/null 2>"$T/e.linger"; rr=$?
BURNER_SSH=$T/ssh-linger "$B" -H fake ls </dev/null >/dev/null 2>&1; rl=$?
[ "$rr" = 125 ] && [ "$rl" = 125 ] && grep -q "didn't close after it exited" "$T/e.linger" \
  && ok "output held open past ssh's exit: run and ls end 125" || bad "held output" "run=$rr ls=$rl $(short "$T/e.linger")"

# F17 the connection cut during a run: lost, 125, with the VM's id
"$B" -H fake run --json-fd 3 -- sleep </dev/null >/dev/null 2>"$T/e" 3>"$T/js" &
cp=$!
sleep 3
cut_sessions
wait "$cp"; rc=$?
[ "$rc" = 125 ] && grep -q "lost the connection to fake while burner-0123456789ab was running" "$T/e" \
  && json_is 'd["errors"][0]["kind"] == "lost" and d["result"]["id"] == "burner-0123456789ab"' < "$T/js" \
  && ok "connection cut mid-run: lost, 125, names the VM" || bad "lost" "rc=$rc $(short "$T/e") $(short "$T/js")"

# F18 ctrl-c here: 130, says the VM stops there
python3 -I - "$B" "$T" <<'EOF'
import os, signal, subprocess, sys, time
b, t = sys.argv[1], sys.argv[2]
with open(t + "/e.int", "wb") as e:
    p = subprocess.Popen([b, "-H", "fake", "run", "--", "sleep"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=e, start_new_session=True)
    time.sleep(3)
    os.killpg(p.pid, signal.SIGINT)
    open(t + "/int.rc", "w").write(str(p.wait(timeout=20)))
EOF
rc=$(cat "$T/int.rc")
[ "$rc" = 130 ] && grep -q "interrupted, burner-0123456789ab on fake stops when burner there sees ssh go" "$T/e.int" \
  && ok "ctrl-c here: 130" || bad "ctrl-c" "rc=$rc $(short "$T/e.int")"

# F19 shell on the stand-in: keys there and back, the terminal filter, a
# resize, the far end's exit code, and ~. getting out of a far end that hangs
drive 'expect fake# ;; send hello\r ;; expect got:hello ;; send osc\r ;; expect osc-done ;; size 40 120 ;; wait 0.5 ;; send size\r ;; expect 40 120 ;; send exit 7\r' -- "$B" -H fake shell > "$T/d1"
d1=$(cat "$T/d1")
grep -q $'\033]' "$T/pty.log"; leaked=$?
drive 'expect fake# ;; send hang\r ;; wait 1 ;; send \r~.' -- "$B" -H fake shell > "$T/d2"
d2=$(cat "$T/d2")
case $d1 in "EXIT 7 "*OK) e1=ok ;; *) e1=no ;; esac
case $d2 in "EXIT 0 "*OK) e2=ok ;; *) e2=no ;; esac
[ "$e1" = ok ] && [ "$leaked" = 1 ] && [ "$e2" = ok ] && grep -q "left the shell, the VM on fake stops with it" "$T/pty.log" \
  && ok "shell: keys, filter, resize, exit code, and ~. out of a hung far end" \
  || bad "shell on the stand-in" "$d1 / $d2 leaked=$leaked"

# F20 doctor and burner hosts
"$B" -H fake doctor >"$T/doc" 2>&1; rd=$?
"$B" hosts --check >"$T/hosts" 2>&1; rh=$?
"$B" --json hosts >"$T/hosts.json" 2>&1
[ "$rd" = 0 ] && grep -q "fake's own doctor" "$T/doc" && grep -q '  | ok    fake' "$T/doc" \
  && [ "$rh" = 0 ] && grep -q "^lo .*192.0.2.1 (" "$T/hosts" && grep -q "lo (0 ms)\|lo ([0-9]* ms)" "$T/hosts" \
  && json_is 'len(d["result"]["hosts"]) == 8' < "$T/hosts.json" \
  && ok "doctor over -H, burner hosts --check and --json" || bad "doctor and hosts" "doctor=$rd hosts=$rh $(short "$T/doc")"

# F21 a hosts.toml others can write is refused
chmod 666 "$T/xdg/burner/hosts.toml"
"$B" -H fake ls >/dev/null 2>"$T/e"; rc=$?
chmod 600 "$T/xdg/burner/hosts.toml"
[ "$rc" = 2 ] && grep -q "someone other than you" "$T/e" && ok "a hosts.toml others can write is refused" \
  || bad "hosts.toml trust" "rc=$rc $(short "$T/e")"

# F22 the client keeps its own copy of every -H run and shell, with the host
# in it: here the ~. from F19 is the newest. what the far end said is cleaned,
# read leniently, and shown escaped
case $(uname -s) in
    Darwin) copies="$HOME/Library/Application Support/burner/logs/$(id -u)" ;;
    *) copies=$T/state/burner/logs ;;
esac
"$B" log --list --json >"$T/cl.json" 2>"$T/e"; rc=$?
[ "$rc" = 0 ] && json_is '[(r["host"], r["shell"], r["outcome"], r["exit"]) for r in d["result"]["runs"] if r["id"] == "burner-0123456789ab"][:1] == [("fake", True, "detached", 0)]' < "$T/cl.json" \
  && ok "copy: a shell left with ~. over -H is kept here" || bad "copy of ~." "rc=$rc $(short "$T/cl.json")"
python3 -I - "$T" <<'PY'
import json, sys
t = sys.argv[1]
ev = {"t": 0.5, "last": 0.5, "count": 1, "dir": "out", "kind": "conn", "proto": "tcp", "dst": "140.82.112.3", "port": 443,
      "verdict": "allowed", "reason": None, "detail": None, "outcome": "answered", "names": ["github.com\u009b31m"],
      "bytes_up": None, "bytes_down": None, "name": None, "qtype": None, "rcode": None, "answers": [], "malformed": False}
blocked = dict(ev, verdict="blocked", reason="geo", detail="a reason from later\u0085", outcome=None, dst="10.0.0.1", names=[])
http = dict(ev, kind="http", path="/x")
net = {"id": "burner-feedfacecafe", "net": "web", "platform": "linux", "owner": 1000, "started_unix": 1795000000, "secs": 1.0,
       "complete": True, "lost": 0, "not_itemized": 0, "invalid": 0, "newer": 1,
       "summary": {"allowed": 2, "blocked": 1, "blocked_attempts": 1, "dns": 0, "unknown": 0, "http": 1},
       "events": [ev, blocked, http]}
res = {"id": "burner-feedfacecafe", "outcome": "exited", "rc": 0, "secs": 1.0, "guest_error": "g\u0085",
       "vm": {"img": "evil\u009b31m", "net": "web", "tag": "t\u001b]0;x", "backend": "firecracker"}, "report": {"x": 1}, "network": net}
env = {"schema": 1, "burner": "9.9.9", "command": "run", "host": None, "exit": 0, "ok": True, "result": res, "errors": [], "warnings": []}
open(t + "/fake2.json", "w").write(json.dumps(env))
PY
cat > "$T/fake2-burner" <<EOF
#!/bin/sh
if [ "\$1" = --version ]; then echo "$VERSION"; exit 0; fi
T=$T
EOF
cat >> "$T/fake2-burner" <<'EOF'
n=
while [ $# -gt 0 ]; do case $1 in --remote) n=${2#1:}; shift 2 ;; --) break ;; *) shift ;; esac; done
printf 'burner: net web: 2 connections out, 1 blocked, 0 dns lookups (burner log burner-feedfacecafe for all of it)\n' >&2
printf 'burner-%s status %s\n' "$n" "$(cat "$T/fake2.json")" >&2
exit 0
EOF
chmod 755 "$T/fake2-burner"
printf '\n[hosts.fake2]\naddrs = ["lo"]\nburner = "%s"\n' "$T/fake2-burner" >> "$T/xdg/burner/hosts.toml"
"$B" -H fake2 run --net web -- 'echo hi' </dev/null >/dev/null 2>"$T/e.f2"; rc=$?
"$B" -H fake2 run --net web --log none -- 'echo hi' </dev/null >/dev/null 2>"$T/e.f2n"; rcn=$?
"$B" log --list --json >"$T/cl.json" 2>/dev/null
"$B" log burner-feedfacecafe --json >"$T/f2.json" 2>/dev/null; rj=$?
"$B" log burner-feedfacecafe >"$T/f2.txt" 2>/dev/null; rt=$?
[ "$rc" = 0 ] && [ "$rcn" = 0 ] && grep -q '^burner: kept here too, burner log burner-feedfacecafe$' "$T/e.f2" && ! grep -q 'kept here too' "$T/e.f2n"
s1=$?
python3 -I - "$T" "$copies" "$rj" "$rt" <<'PY'
import json, os, stat, sys
t, copies, rj, rt = sys.argv[1:]
runs = json.load(open(t + "/cl.json"))["result"]["runs"]
r = [x for x in runs if x["id"] == "burner-feedfacecafe"][0]
assert (r["host"], r["allowed"], r["blocked"], r["img"], r["tag"], r["net"], r["command"]) == \
    ("fake2", 2, 1, "evil?31m", "t\\x1b]0;x", "web", "echo hi"), r
raw = open(t + "/f2.json", "rb").read()
assert rj == "0" and rt == "0"
for b in [b"\x1b"] + [bytes([0xc2, c]) for c in range(0x80, 0xa0)]:
    assert b not in raw, b
l = json.loads(raw)["result"]
assert [e["kind"] for e in l["events"]] == ["conn", "conn"] and not l["complete"], l["events"]
assert l["events"][1]["reason"] is None and l["events"][0]["names"] == ["github.com?31m"]
assert l["run"]["host"] == "fake2" and l["run"]["result"]["guest_error"] == "g?" and l["run"]["result"]["report"] == {"x": 1}
txt = open(t + "/f2.txt", "rb").read()
assert b"\x1b" not in txt and not any(bytes([0xc2, c]) in txt for c in range(0x80, 0xa0)), txt[:300]
first = txt.split(b"\n")[0].decode()
assert "  fake2  evil?31m  exit 0  echo hi" in first and b"burner-feedfacecafe: net web" in txt, first
m = os.stat(copies + "/burner-feedfacecafe@fake2.json").st_mode
assert stat.S_IMODE(m) == 0o600 and stat.S_IMODE(os.stat(copies).st_mode) == 0o700, oct(m)
PY
s2=$?
[ "$s1" = 0 ] && [ "$s2" = 0 ] \
  && ok "copy: a far end's json is cleaned, read leniently, shown escaped, kept 0600; the summary says it's kept here" \
  || bad "copy of a -H run" "rc=$rc/$rcn hint=$s1 read=$s2 $(short "$T/e.f2")"
# log --list still asks the far end with -H or BURNER_HOST, and -H local doesn't
"$B" -H fake log --list --from x --limit 3 >"$T/lg" 2>&1; rl=$?
BURNER_HOST=fake "$B" log --list >"$T/lg2" 2>&1; re=$?
BURNER_HOST=fake "$B" -H local log --list --from fake2 >"$T/lg3" 2>&1; rlo=$?
[ "$rl" = 0 ] && grep -qx "fake log --list --from=x --limit=3" "$T/lg" && [ "$re" = 0 ] && grep -qx "fake log --list" "$T/lg2" \
  && [ "$rlo" = 0 ] && grep -q '^burner-feedfacecafe  .*  fake2  evil?31m  web' "$T/lg3" && ! grep -q 'fake log' "$T/lg3" \
  && ok "copy: log --list goes over -H and BURNER_HOST, -H local lists the copies here" \
  || bad "log --list over -H" "h=$rl env=$re local=$rlo $(short "$T/lg") $(short "$T/lg3")"

if [ "$FAKE_ONLY" = 1 ]; then
    echo "---- $pass passed, $fail failed"
    [ "$fail" = 0 ]
    exit
fi

# ==== the real burner on the far end, through sudo -n. the first address in
# hosts.lo never answers, so every run here also goes past it
vms_gone() {
    for _ in $(seq 30); do
        [ "$(sudo -n burner ls 2>/dev/null)" = "no VMs running" ] && return 0
        sleep 1
    done
    return 1
}

# R1 exit codes through: the command's own, 255, a time limit, a usage error
out=$("$B" -H lo run -- 'echo hi; exit 7' </dev/null 2>/dev/null); r7=$?
"$B" -H lo run -- 'exit 255' </dev/null >/dev/null 2>&1; r255=$?
"$B" -H lo run --ttl 10s -- 'sleep 60' </dev/null >/dev/null 2>&1; rt=$?
"$B" -H lo run --mem 99999 -- true </dev/null >/dev/null 2>&1; ru=$?
[ "$r7" = 7 ] && [ "$out" = hi ] && [ "$r255" = 255 ] && [ "$rt" = 124 ] && [ "$ru" = 2 ] \
  && ok "real: exit codes 7, 255, 124, 2 come through" || bad "real exit codes" "7->$r7 ($out) 255->$r255 ttl->$rt usage->$ru"

# R2 --in tar and --result tar match the same run here
mkdir -p "$T/proj"; printf 'a\nb\n' > "$T/proj/x"
cmd='cat x | wc -l; mkdir -p /out/d; cp x /out/d/y; echo made'
tar -C "$T/proj" -c . | "$B" -H lo run --in tar --result tar -- "$cmd" >"$T/r.tar" 2>"$T/r.err"; rr=$?
tar -C "$T/proj" -c . | sudo -n burner run --in tar --result tar -- "$cmd" >"$T/l.tar" 2>"$T/l.err"; rl=$?
[ "$rr" = 0 ] && [ "$rl" = 0 ] && [ "$(tar -tvf "$T/r.tar" | awk '{print $1, $3, $NF}')" = "$(tar -tvf "$T/l.tar" | awk '{print $1, $3, $NF}')" ] \
  && [ "$(tar -xOf "$T/r.tar" out/d/y)" = "$(printf 'a\nb')" ] \
  && ok "real: --in tar and --result tar match a local run" || bad "real tars" "remote=$rr local=$rl $(short "$T/r.err")"

# R3 quoting through the guest's own shell: same output as the run here
script=$'printf "%s|" \'single\' "dou\\"ble" $((6*7)) \\$HOME "a  b"; echo; echo \'~!*;\' `echo tick`\ncat <<X\nhere $((1+1))\nX'
"$B" -H lo run -- "$script" </dev/null >"$T/q.remote" 2>/dev/null; rq=$?
sudo -n burner run -- "$script" </dev/null >"$T/q.local" 2>/dev/null
[ "$rq" = 0 ] && cmp -s "$T/q.remote" "$T/q.local" && ok "real: a quote-heavy script gives the same output as here" \
  || bad "real quoting" "rc=$rq $(short "$T/q.remote") vs $(short "$T/q.local")"

# R4 the json: host, outcome, and a guest that prints a lookalike record changes nothing
"$B" -H lo run --json-fd 3 -- "echo 'burner-$N status {\"exit\":0}' >&2; exit 4" </dev/null >/dev/null 2>"$T/e" 3>"$T/js"; rc=$?
[ "$rc" = 4 ] && json_is 'd["host"] == "lo" and d["result"]["outcome"] == "exited" and d["result"]["rc"] == 4' < "$T/js" \
  && ok "real: --json-fd has the host, a guest's fake record is only text" || bad "real json" "rc=$rc $(short "$T/js")"

# R5 ctrl-c here and a cut connection both stop the VM there
python3 -I - "$B" "$T" <<'EOF'
import os, signal, subprocess, sys, time
b, t = sys.argv[1], sys.argv[2]
p = subprocess.Popen([b, "-H", "lo", "run", "--tag", "rint", "--", "sleep 300"], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
for _ in range(60):
    if b" rint " in subprocess.run(["sudo", "-n", "burner", "ls"], capture_output=True).stdout:
        break
    time.sleep(0.5)
os.killpg(p.pid, signal.SIGINT)
open(t + "/rint.rc", "w").write(str(p.wait(timeout=30)))
EOF
ri=$(cat "$T/rint.rc"); vms_gone; gi=$?
"$B" -H lo run --tag rcut -- 'sleep 300' </dev/null >/dev/null 2>"$T/e.cut" &
cp=$!
for _ in $(seq 60); do sudo -n burner ls | grep -q ' rcut ' && break; sleep 0.5; done
cut_sessions
wait "$cp"; rc=$?
vms_gone; gc=$?
[ "$ri" = 130 ] && [ "$gi" = 0 ] && [ "$rc" = 125 ] && [ "$gc" = 0 ] \
  && ok "real: ctrl-c (130) and a cut connection (125) both stop the VM there" \
  || bad "real stop" "int=$ri gone=$gi cut=$rc gone=$gc $(short "$T/e.cut")"

# R6 ls, images and kill from a second -H call: the run ends 130, killed
"$B" -H lo run --tag rkill --json-fd 3 -- 'sleep 300' </dev/null >/dev/null 2>/dev/null 3>"$T/kill.js" &
kp=$!
vid=
for _ in $(seq 60); do
    vid=$("$B" -H lo ls 2>/dev/null | awk '/ rkill /{print $1}')
    [ -n "$vid" ] && break
    sleep 0.5
done
"$B" -H lo images >"$T/img" 2>/dev/null; ri=$?
"$B" -H lo kill "$vid" >/dev/null 2>&1; rk=$?
wait "$kp"; rc=$?
[ -n "$vid" ] && [ "$ri" = 0 ] && grep -q alpine "$T/img" && [ "$rk" = 0 ] && [ "$rc" = 130 ] \
  && json_is 'd["result"]["outcome"] == "killed"' < "$T/kill.js" \
  && ok "real: ls, images, and kill from another -H call (130, killed)" || bad "real ls/kill" "vid=$vid images=$ri kill=$rk run=$rc"

# R7 shell: a prompt, keys, a resize, the exit code, and ~.
drive 'expect # ;; send echo hi$((40+2))\r ;; expect hi42 ;; size 33 77 ;; wait 1.5 ;; send stty size\r ;; expect 33 77 ;; send exit 3\r' -- "$B" -H lo shell > "$T/d1"
d1=$(cat "$T/d1")
drive 'expect # ;; send \r~.' -- "$B" -H lo shell > "$T/d2"
d2=$(cat "$T/d2")
vms_gone; g=$?
case $d1 in "EXIT 3 "*OK) e1=ok ;; *) e1=no ;; esac
case $d2 in "EXIT 0 "*OK) e2=ok ;; *) e2=no ;; esac
[ "$e1" = ok ] && [ "$e2" = ok ] && [ "$g" = 0 ] && ok "real: shell keys, resize, exit 3, ~. and the VM gone" \
  || bad "real shell" "$d1 / $d2 gone=$g"

# R8 doctor over -H
"$B" -H lo doctor >"$T/doc" 2>&1; rd=$?
[ "$rd" = 0 ] && grep -q "run, shell, ls, kill, images, log and explain allowed without a password" "$T/doc" \
  && ! grep -q '^warn  sudo' "$T/doc" \
  && ok "real: doctor over -H" || bad "real doctor" "rc=$rd $(short "$T/doc")"
# a rule without the log and explain lines is a warning, the rest still works
"$B" -H partsudo doctor >"$T/doc" 2>&1; rd=$?
[ "$rd" = 0 ] && grep -q "^ok    sudo .*run, shell, ls, kill and images allowed without a password" "$T/doc" \
  && grep -q "^warn  sudo .*doesn't cover burner log or explain, so -H partsudo log and explain won't work" "$T/doc" \
  && ok "real: doctor over -H warns about a rule without log and explain" || bad "real doctor, part of the rule" "rc=$rd $(short "$T/doc")"

# R9 the connection log comes back over -H: the summary on stderr, and a
# log of 400 blocked rows whole in the json, past what fit in a record before
"$B" -H lo run --net web --json-fd 3 -- 'for i in $(seq 1 200); do nc -z -w 1 10.254.1.$i 80 & nc -z -w 1 10.254.2.$i 80 & done; wait' \
    </dev/null >/dev/null 2>"$T/nl.err" 3>"$T/nl.js"; rc=$?
python3 -I - "$T/nl.js" "$T/nl.err" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
n = d["result"]["network"]
err = open(sys.argv[2]).read()
blocked = [e for e in n["events"] if e["verdict"] == "blocked" and e["dst"].startswith("10.254.")]
print("      over -H: %d blocked rows, a %d byte log" % (len(blocked), len(json.dumps(n))))
sys.exit(0 if d["host"] == "lo" and len(blocked) >= 300 and len(json.dumps(n)) > 65536
         and ("burner log " + d["result"]["id"]) in err else 1)
PY
r=$?
[ "$rc" = 0 ] && [ "$r" = 0 ] && ok "real: the network summary on stderr and a big log in the json over -H" \
  || bad "real network log" "rc=$rc $(short "$T/nl.err")"

# R10 burner -H log has that run's log, kept there, and explain says what a
# VM could reach there
nid=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["result"]["id"])' "$T/nl.js" 2>/dev/null)
"$B" -H lo log "$nid" --json >"$T/nl.log" 2>/dev/null; rl=$?
"$B" -H lo explain --net web >"$T/nl.ex" 2>&1; rx=$?
[ -n "$nid" ] && [ "$rl" = 0 ] && json_is "d['host'] == 'lo' and d['command'] == 'log' and d['result']['id'] == '$nid' and len(d['result']['events']) >= 300" < "$T/nl.log" \
  && [ "$rx" = 0 ] && [ -s "$T/nl.ex" ] && ok "real: burner -H log and explain" || bad "real log/explain" "id=$nid log=$rl explain=$rx $(short "$T/nl.ex")"

vms_gone && ok "no VMs left running" || bad "leftovers" "$(sudo -n burner ls)"
echo "---- $pass passed, $fail failed"
[ "$fail" = 0 ]
