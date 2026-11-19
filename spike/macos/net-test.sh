#!/bin/sh
# boots one guest with spike-net and burner-macnet, runs JOB (a shell script)
# inside it, then checks the network process went away with the VM.
#   net-test.sh JOB [MACNET ARGS]
# needs spike-net built and signed in this dir, macnet/ built with --release,
# and SPIKE pointing at a dir with vmlinux, rootfs.ext4, scratch.ext4, result.raw
set -u
job=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
spike=${SPIKE:-$HOME/burner-spike}
macnet=${MACNET:-$here/../../macnet/target/release/burner-macnet}
work=$(mktemp -d "${TMPDIR:-/tmp}/burner-net.XXXXXX")
trap 'rm -rf "$work"' EXIT

mkdir "$work/job"
cp "$job" "$work/job/run.sh"
tar --format ustar -cf "$work/job.tar" -C "$work/job" run.sh
dd if=/dev/null of="$work/job.tar" bs=1 seek=1048576 2>/dev/null
# clones on apfs, so the spike's own disks stay as they are
cp -c "$spike/scratch.ext4" "$work/scratch.ext4"
cp -c "$spike/result.raw" "$work/result.raw"

token=nt$$
cmdline="console=hvc0 reboot=k panic=1 pci=off quiet loglevel=1 root=/dev/vda ro init=/sbin/burner-init burner.token=$token burner.proto=1 ip=172.29.217.2::172.29.217.1:255.255.255.252:burner:eth0:off burner.dns=9.9.9.9,1.1.1.1"
[ $# -gt 0 ] || set -- --mode web --resolver 9.9.9.9 --resolver 1.1.1.1 -v
"$here/spike-net" "$spike/vmlinux" "$spike/rootfs.ext4" "$work/scratch.ext4" "$work/job.tar" "$work/result.raw" pty "$cmdline" \
    "$macnet" "$@" 2> "$work/stderr" | tr -d '\r' | sed -n "/BURNER-$token-BEGIN/,/BURNER-$token-END/p"
echo "== host side"
grep -v '^\[' "$work/stderr"
pid=$(sed -n 's/^spike: burner-macnet pid //p' "$work/stderr")
sleep 0.5
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    echo "burner-macnet $pid still running after the VM exited"
    kill "$pid"
else
    echo "burner-macnet $pid exited with the VM"
fi
