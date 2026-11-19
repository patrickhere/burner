#!/bin/bash
# isolation tests: what a hostile VM can and can't do to the host. run as a sudoer. prints PASS/FAIL per test.
set -u
cd /tmp || exit 1
T=$(mktemp -d /tmp/burner-test-XXXX)
trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1  ($2)"; fail=$((fail+1)); }
clean_state() {
    sleep 1
    [ -z "$(sudo ls /var/lib/burner/jail/firecracker/ 2>/dev/null)" ] && [ -z "$(sudo ls /run/burner/vms/ 2>/dev/null)" ] \
      && ! sudo ls /sys/fs/cgroup/burner/ | grep -q '^burner-'
}

# 1 exit code + live output
out=$(sudo burner run -- 'echo hi; exit 7' </dev/null 2>&1); rc=$?
[ "$rc" = 7 ] && [ "$out" = hi ] && ok "exit code and output" || bad "exit code and output" "rc=$rc out=$out"

# 2 --in tar
mkdir -p "$T/proj"; echo 'print me' > "$T/proj/a.txt"
out=$(tar -C "$T/proj" -c . | sudo burner run --in tar -- 'cat /work/a.txt' 2>&1); rc=$?
[ "$rc" = 0 ] && [ "$out" = "print me" ] && ok "--in tar" || bad "--in tar" "rc=$rc out=$out"

# 3 memory bomb: guest OOMs inside itself, firecracker survives and returns a result
out=$(sudo burner run --mem 256 -- 'awk "BEGIN{while(1) s=s sprintf(\"%1000000s\",\"x\")}"; echo after=$?' </dev/null 2>&1); rc=$?
echo "$out" | grep -qE 'after=(137|1|2)' && [ "$rc" = 0 ] && ok "memory bomb contained (guest OOM, VM survived)" \
  || bad "memory bomb" "rc=$rc out=$(echo "$out" | tail -2 | tr '\n' ' ')"

# 4 fork bomb + busy loops: the VM's cgroup stays within 1 core and the run ends
# by the TTL. a bomb that brings the guest kernel down ends it early with 125,
# which is just as contained. `wait` keeps the job going: on a fast box the shell
# could get out of f and exit 0 before the bomb takes over
s=$(date +%s)
( sudo burner run --ttl 25s --tag forkbomb -- 'for i in 1 2 3 4; do (while :; do :; done) & done; f(){ f|f& }; f; wait' </dev/null >/dev/null 2>&1; echo $? > "$T/fork.rc" ) &
sleep 4
vid=$(sudo burner ls | awk '/forkbomb/{print $1}')
u1=$(sudo awk '/usage_usec/{print $2}' "/sys/fs/cgroup/burner/$vid/cpu.stat"); sleep 4
u2=$(sudo awk '/usage_usec/{print $2}' "/sys/fs/cgroup/burner/$vid/cpu.stat")
cores=$(awk -v a="$u1" -v b="$u2" 'BEGIN{printf "%.2f", (b-a)/4000000}')
wait
e=$(date +%s); rc=$(cat "$T/fork.rc")
[ -n "$vid" ] && [ -n "$u1" ] && [ -n "$u2" ] && awk -v c="$cores" 'BEGIN{exit !(c <= 1.05)}' \
  && { [ "$rc" = 124 ] || [ "$rc" = 125 ]; } && [ $((e-s)) -le 40 ] \
  && ok "fork bomb + busy loops: VM held to ${cores} cores, ended after $((e-s))s (rc $rc)" \
  || bad "fork bomb" "rc=$rc cores=$cores secs=$((e-s))"

# 5 disk flood: scratch fills, job sees ENOSPC, host disk untouched
before=$(df --output=used -B1M / | tail -1)
out=$(sudo burner run --disk 1 -- 'dd if=/dev/zero of=/var/tmp/fill bs=1M count=3000 2>&1; echo dd_done' </dev/null 2>&1); rc=$?
after=$(df --output=used -B1M / | tail -1)
echo "$out" | grep -q dd_done && echo "$out" | grep -qiE 'no space|space left|I/O error' && [ $((after-before)) -lt 200 ] \
  && ok "disk flood capped at scratch size (host delta $((after-before))M after run)" \
  || bad "disk flood" "rc=$rc delta=$((after-before)) out=$(echo "$out" | tr '\n' ' ' | tail -c 200)"

# 6 hostile result tar written straight to the result disk
python3 -I - "$T/evil.tar" <<'EOF'
import io, sys, tarfile
t = tarfile.open(sys.argv[1], "w", format=tarfile.GNU_FORMAT)
def add(name, data=b"x", **kw):
    ti = tarfile.TarInfo(name); ti.size = len(data)
    for k, v in kw.items(): setattr(ti, k, v)
    t.addfile(ti, io.BytesIO(data) if ti.isreg() else None)
add("result/rc", b"0\n")
add("../escape.txt"); add("/etc/evil.txt"); add("out/../../up.txt")
add("out/link", type=tarfile.SYMTYPE, linkname="/etc/shadow", size=0)
add("out/hard", type=tarfile.LNKTYPE, linkname="/etc/shadow", size=0)
add("out/dev", type=tarfile.CHRTYPE, devmajor=1, devminor=3, size=0)
add("out/suid", b"#!/bin/sh\n", mode=0o4755)
add("out/fine.txt", b"ok\n")
for i in range(3): add(f"out/deep/{'x' * 200}/{i}", b"y")
ti = tarfile.TarInfo("out/nan"); ti.size = 0; ti.pax_headers = {"mtime": "nan"}; t.addfile(ti, io.BytesIO(b""))
t.close()
EOF
sudo burner run --in stdin --result tar -- 'cat > /dev/vdd; sync; reboot -f' < "$T/evil.tar" > "$T/res.tar" 2>"$T/res.err"; rc=$?
list=$(tar -tvf "$T/res.tar" 2>&1)
if echo "$list" | grep -q 'out/fine.txt' && ! echo "$list" | grep -qE 'escape|evil|up\.txt|link|hard|dev|^-rws|^c|^l|^h'; then
  ok "hostile result tar: only safe entries passed through (rc=$rc)"
else bad "hostile result tar" "rc=$rc list=$(echo "$list" | tr '\n' ';')"; fi
ls /tmp/escape.txt /escape.txt /etc/evil.txt /up.txt 2>/dev/null && bad "hostile tar wrote on host" "files exist"

# 7 garbage in the result disk
sudo burner run -- 'head -c 5000000 /dev/urandom > /dev/vdd; sync; reboot -f' </dev/null >/dev/null 2>"$T/g.err"; rc=$?
[ "$rc" = 125 ] && ok "random bytes on the result disk -> clean sandbox error" || bad "garbage result" "rc=$rc $(cat "$T/g.err")"

# 8 big output: first 64K live, the rest from the log, last 16M kept
s=$(date +%s)
bytes=$(sudo burner run --ttl 120s -- 'head -c 50000000 /dev/zero | tr "\0" "a"' </dev/null 2>"$T/big.err" | wc -c); e=$(date +%s)
[ "$bytes" = $((65536 + 16777216)) ] && grep -q 'not kept' "$T/big.err" && ok "50M output: 64K live + last 16M, notice on stderr ($((e-s))s)" \
  || bad "big output" "bytes=$bytes secs=$((e-s)) err=$(head -c 200 "$T/big.err")"

# 8b hostile direct console flood: capped at 1M, killed at TTL
sudo burner run --ttl 12s -- 'cat /dev/zero > /dev/console' </dev/null 2>/dev/null > "$T/flood.out"; rc=$?; bytes=$(wc -c < "$T/flood.out")
[ "$bytes" -le $((1 << 20)) ] && [ "$rc" = 124 ] && ok "direct console flood capped ($bytes bytes, rc $rc)" || bad "console flood" "bytes=$bytes rc=$rc"

# 8c byte-exact output: no trailing newline, CRLF, binary
out=$(sudo burner run -- 'printf abc' </dev/null | od -An -tx1 | tr -d ' \n')
[ "$out" = 616263 ] && ok "no trailing newline kept exact" || bad "no trailing newline" "$out"
out=$(sudo burner run -- 'printf "a\r\nb\n"' </dev/null | od -An -tx1 | tr -d ' \n')
[ "$out" = 610d0a620a ] && ok "CRLF kept exact" || bad "CRLF" "$out"
head -c 300000 /dev/urandom > "$T/proj/bin"
want=$(sha256sum < "$T/proj/bin" | cut -c1-64)
got=$(tar -C "$T/proj" -c bin | sudo burner run --in tar -- 'cat /work/bin' | sha256sum | cut -c1-64)
[ "$want" = "$got" ] && ok "300K binary round trip byte-exact" || bad "binary round trip" "sha differs"

# 9 ttl
s=$(date +%s); sudo burner run --ttl 15s -- 'sleep 300' </dev/null >/dev/null 2>&1; rc=$?; e=$(date +%s)
[ "$rc" = 124 ] && [ $((e-s)) -le 25 ] && ok "ttl kill at 15s (took $((e-s))s)" || bad "ttl" "rc=$rc secs=$((e-s))"

# 10 concurrency: 2 run, the 3rd waits
s=$(date +%s)
for i in 1 2 3; do ( sudo burner run --tag t$i -- 'sleep 12' </dev/null >/dev/null 2>"$T/c$i.err"; echo $? > "$T/c$i.rc" ) & sleep 0.5; done
sleep 6; running=$(sudo burner ls | grep -c '^burner-'); wait; e=$(date +%s)
grep -q 'waiting for a slot' "$T"/c*.err && [ "$running" = 2 ] && [ "$(cat "$T"/c*.rc | sort -u)" = 0 ] && [ $((e-s)) -ge 24 ] \
  && ok "concurrency: 2 ran, 3rd queued, all finished (${running} at once, $((e-s))s)" \
  || bad "concurrency" "running=$running rcs=$(cat "$T"/c*.rc | tr '\n' ' ') secs=$((e-s))"

# 10b two VMs at once: each firecracker runs as its own uid out of jail.uid_base
for i in 1 2; do ( sudo burner run --tag u$i -- 'sleep 10' </dev/null >/dev/null 2>&1 ) & done
sleep 6
uids=$(for p in $(cat /sys/fs/cgroup/burner/burner-*/cgroup.procs 2>/dev/null); do awk '/^Uid:/{print $3}' "/proc/$p/status"; done | sort -u | tr '\n' ' ')
wait
base=$(sudo burner config | awk '$1 == "uid_base" {print $3}')
[ -n "$base" ] && echo "$uids" | awk -v b="$base" '{ for (i = 1; i <= NF; i++) if ($i < b || $i >= b + 1024) exit 1; exit NF != 2 }' \
  && ok "two VMs run as two uids from the VM range ($uids)" || bad "VM uids" "uids=$uids base=$base"

# 11 total memory budget: 2 x 2G cannot run together
( sudo burner run --mem 2048 -- 'sleep 8' </dev/null >/dev/null 2>&1 ) & sleep 3
sudo burner run --mem 2048 -- 'true' </dev/null >/dev/null 2>"$T/m.err"; wait
grep -q 'waiting for a slot' "$T/m.err" && ok "3G total memory budget enforced" || bad "memory budget" "$(cat "$T/m.err")"

# 12 sudo burner kill: the killed run exits 130, whether the kill lands while the
# job runs or while the VM is still booting (the VM can die before burner's own
# check of the kill flag comes around)
( sudo burner run --tag victim -- 'sleep 300' </dev/null >/dev/null 2>"$T/k.err"; echo $? > "$T/k.rc" ) & sleep 5
vid=$(sudo burner ls | awk '/victim/{print $1}'); sudo burner kill "$vid" >/dev/null; wait
[ -n "$vid" ] && [ "$(cat "$T/k.rc")" = 130 ] && grep -q 'killed by burner kill' "$T/k.err" \
  && ok "sudo burner kill stops a running VM (rc 130)" || bad "kill" "vid=$vid rc=$(cat "$T/k.rc") err=$(tr '\n' ' ' < "$T/k.err")"
( sudo burner run --tag victim2 -- 'sleep 300' </dev/null >/dev/null 2>"$T/k2.err"; echo $? > "$T/k2.rc" ) &
vid=""
for _ in $(seq 40); do vid=$(sudo burner ls | awk '$2 == "victim2" && /running/ {print $1}'); [ -n "$vid" ] && break; sleep 0.25; done
[ -n "$vid" ] && sudo burner kill "$vid" >/dev/null; wait
[ -n "$vid" ] && [ "$(cat "$T/k2.rc")" = 130 ] && grep -q 'killed by burner kill' "$T/k2.err" && ! grep -q 'VM ended before' "$T/k2.err" \
  && ok "sudo burner kill during boot: rc 130, no console dump" || bad "kill during boot" "vid=$vid rc=$(cat "$T/k2.rc") err=$(tr '\n' ' ' < "$T/k2.err" | head -c 300)"

# 13 argument fuzzing: all must be refused with rc 2 before any VM starts
fz=0
for a in "--img ../alpine" "--img alpine/../x" "--img ALPINE" "--tag A_B" "--tag $(printf 'x%.0s' {1..40})" \
         "--cpus 99" "--cpus 0" "--mem 99999" "--mem 1" "--ttl 2h" "--ttl 1s" "--ttl 5x" "--disk 0" "--disk 50" \
         "--net lan" "--in auto" "--result zip" "--bogus 1"; do
  # shellcheck disable=SC2086
  sudo burner run $a -- true </dev/null >/dev/null 2>&1; r=$?
  [ "$r" = 2 ] || { fz=1; echo "      not refused: $a (rc=$r)"; }
done
sudo burner run -- </dev/null >/dev/null 2>&1; [ $? = 2 ] || { fz=1; echo "      empty command not refused"; }
sudo burner kill ../../etc >/dev/null 2>&1; [ $? = 2 ] || { fz=1; echo "      bad kill id not refused"; }
[ "$fz" = 0 ] && ok "argument fuzzing: all refused" || bad "argument fuzzing" "see above"

# 14 stdin cap is not tested here (512M); oversized command:
sudo burner run -- "$(head -c 70000 /dev/zero | tr '\0' a)" </dev/null >/dev/null 2>&1; [ $? = 2 ] && ok "oversized command refused" || bad "oversized command" "accepted"

# 15 argv mode keeps argument boundaries
out=$(sudo burner run -- printf '%s|' 'a b' c </dev/null)
[ "$out" = "a b|c|" ] && ok "several args are quoted as-is" || bad "argv mode" "$out"

# 16 a stdin pipe that never closes: refused once it's idle too long, no slot held
# meanwhile. a test config with a 10s limit instead of the default 60s
sudo burner config | sed 's/^stdin_idle_secs = .*/stdin_idle_secs = 10/' | sudo tee /etc/burner/tests.toml >/dev/null
s=$(date +%s)
( sleep 15 | sudo burner --config /etc/burner/tests.toml run --in stdin -- cat >/dev/null 2>"$T/idle.err"; echo $? > "$T/idle.rc" ) &
sleep 5; held=$(sudo burner ls | grep -c '^burner-'); wait; e=$(date +%s)
sudo rm -f /etc/burner/tests.toml
[ "$(cat "$T/idle.rc")" = 2 ] && [ "$held" = 0 ] && grep -q 'no input for' "$T/idle.err" \
  && ok "idle stdin refused after $((e-s))s without holding a slot" || bad "idle stdin" "rc=$(cat "$T/idle.rc") held=$held"

# 17 a reader that never reads: the VM still ends and the slot is freed
# shellcheck disable=SC2216
( sudo burner run --ttl 60s -- 'head -c 30000000 /dev/zero' | sleep 100 ) >/dev/null 2>&1 &
bg=$!
# the VM ends on its own once its output is written; poll instead of a fixed wait
for _ in $(seq 30); do held=$(sudo burner ls | grep -c '^burner-'); [ "$held" = 0 ] && break; sleep 2; done
pkill -P "$bg" 2>/dev/null; kill "$bg" 2>/dev/null; wait 2>/dev/null
[ "$held" = 0 ] && ok "stuck reader: VM done and slot freed while output waits" || bad "stuck reader" "slots held=$held"
sleep 2

# 18 live output: a line printed early shows up while the command is still running
first=""; last=""
while read -r l; do
    case "$l" in early) first=$(date +%s) ;; late) last=$(date +%s) ;; esac
done < <(sudo burner run -- 'echo early; sleep 8; echo late' </dev/null 2>/dev/null)
[ -n "$first" ] && [ -n "$last" ] && [ $((last - first)) -ge 6 ] \
  && ok "output streams live ($((last - first))s between early and late lines)" \
  || bad "live output" "early=$first late=$last"

# 19 a wrapper killed with SIGKILL: the reaper stops its VM and frees the slot
( sudo burner run --tag sigkill -- 'sleep 300' </dev/null >/dev/null 2>&1 & )
vid=""
for _ in $(seq 30); do vid=$(sudo burner ls | awk '/ sigkill /{print $1}'); [ -n "$vid" ] && break; sleep 1; done
sleep 3
sudo pkill -KILL -f '^burner run --tag sigkill'
s=$(date +%s)
for _ in $(seq 45); do sudo burner ls | grep -q ' sigkill ' || break; sleep 2; done
e=$(date +%s)
[ -n "$vid" ] && ! sudo burner ls | grep -q ' sigkill ' && ! sudo test -d "/sys/fs/cgroup/burner/$vid" \
  && ok "SIGKILLed wrapper: reaper stopped the VM and freed the slot in $((e - s))s" \
  || bad "sigkill wrapper" "vid=$vid still=$(sudo burner ls | grep -c ' sigkill ')"

# 20 something left running in the background doesn't hold the run open: the
# run ends with the job, with the job's own exit code, its output and /out
s=$(date +%s)
a=$(sudo burner run -- 'sleep 300 & echo ok' </dev/null 2>&1); ra=$?
b=$(sudo burner run -- 'setsid sleep 300 & echo ok' </dev/null 2>&1); rb=$?
sudo burner run -- 'sleep 300 & exit 7' </dev/null >/dev/null 2>&1; rc7=$?
sudo burner run --result tar -- 'sleep 300 & echo hi > /out/f' </dev/null > "$T/bg.tar" 2>/dev/null; rt=$?
e=$(date +%s)
[ "$a" = ok ] && [ "$ra" = 0 ] && [ "$b" = ok ] && [ "$rb" = 0 ] && [ "$rc7" = 7 ] && [ "$rt" = 0 ] \
  && tar -tf "$T/bg.tar" 2>/dev/null | grep -qx 'out/f' && [ $((e - s)) -le 60 ] \
  && ok "background processes don't hold a run open (4 runs in $((e - s))s)" \
  || bad "background processes" "a=$ra:$a b=$rb:$b rc7=$rc7 tar=$rt secs=$((e - s))"
s=$(date +%s); out=$(sudo burner run --ttl 20s -- 'echo before; sleep 300' </dev/null 2>/dev/null); rc=$?; e=$(date +%s)
# the job's shell prints "Terminated" after it when the watchdog stops it
[ "$rc" = 124 ] && [ "$(echo "$out" | head -n 1)" = before ] && [ $((e - s)) -le 30 ] \
  && ok "a job that really runs on still ends at the ttl with its output (rc $rc)" \
  || bad "ttl with output" "rc=$rc out=$out secs=$((e - s))"

# 21 a stopped wrapper (ctrl-z) doesn't hold its slot: a minute past the
# deadline the reaper kills it, and the pass after that frees the VM
( sudo burner run --ttl 15s --tag stopme -- 'sleep 300' </dev/null >/dev/null 2>&1 & )
vid=""
for _ in $(seq 30); do vid=$(sudo burner ls | awk '/ stopme /{print $1}'); [ -n "$vid" ] && break; sleep 1; done
sudo pkill -STOP -f '^burner run --ttl 15s --tag stopme'
s=$(date +%s)
for _ in $(seq 60); do sudo burner ls | grep -q ' stopme ' || break; sleep 5; done
e=$(date +%s)
# sudo stops itself along with its stopped child, wake it so it can exit
sudo pkill -CONT -f '^sudo burner run --ttl 15s --tag stopme'
[ -n "$vid" ] && ! sudo burner ls | grep -q ' stopme ' && ! sudo test -d "/sys/fs/cgroup/burner/$vid" \
  && ! sudo test -e "/var/lib/burner/jail/firecracker/$vid" \
  && ok "stopped wrapper: slot freed $((e - s))s after it stopped" \
  || bad "stopped wrapper" "vid=$vid still=$(sudo burner ls | grep -c ' stopme ')"

# 22 other users on the host can't read a run's input or config
printf 'secret-input\n' > "$T/in.txt"
( while :; do sudo -u nobody cat /var/lib/burner/jail/firecracker/*/root/job.tar /var/lib/burner/jail/firecracker/*/root/vm.json 2>/dev/null; done > "$T/peek" ) &
peeker=$!
for _ in 1 2 3; do tar -C "$T" -cf - in.txt | sudo burner run --in tar -- 'cat in.txt' >/dev/null 2>&1; done
sudo burner run -- 'sleep 10' </dev/null >/dev/null 2>&1 &
sleeper=$!
sleep 5
nobody_ls=$(sudo -u nobody ls /var/lib/burner/jail 2>/dev/null; echo "rc=$?")
kill "$peeker" 2>/dev/null; wait "$peeker" 2>/dev/null
wait "$sleeper"
[ ! -s "$T/peek" ] && [ "${nobody_ls##*rc=}" != 0 ] \
  && ok "job input and VM config unreadable to other users" \
  || bad "jail permissions" "peek=$(wc -c < "$T/peek") ls=$nobody_ls"

# 23 as root, helpers never come from the caller's PATH
mkdir -p "$T/evil"
printf '#!/bin/sh\ntouch %s/pwned\nexit 1\n' "$T" > "$T/evil/mkfs.ext4"
chmod 755 "$T/evil" "$T/evil/mkfs.ext4"
out=$(sudo env PATH="$T/evil:$PATH" /usr/local/bin/burner run -- 'echo fine' </dev/null 2>&1); rc=$?
[ "$rc" = 0 ] && [ "$out" = fine ] && [ ! -e "$T/pwned" ] \
  && ok "a PATH passed through sudo isn't used for helpers" \
  || bad "PATH" "rc=$rc out=$out pwned=$([ -e "$T/pwned" ] && echo yes)"

# 24 leaving a shell: back at the caller's prompt with no guest kernel line
( sleep 8; printf 'echo shell-$((6*7))\r'; sleep 2; printf 'exit\r'; sleep 8 ) \
  | script -qfec "sudo burner shell alpine" "$T/shell.out" >/dev/null 2>&1
grep -q 'shell-42' "$T/shell.out" && ! grep -q 'reboot:\|BURNER-' "$T/shell.out" \
  && ok "shell exit shows no kernel reboot line" \
  || bad "shell exit" "$(tr -d '\r' < "$T/shell.out" | tail -n 4 | tr '\n' ' ')"

if clean_state; then ok "no leftover jails, state files or cgroups"; else bad "leftovers" "$(sudo ls /var/lib/burner/jail/firecracker/ /run/burner/vms/)"; fi
echo "---- $pass passed, $fail failed"
[ "$fail" = 0 ]
