#!/bin/sh
# install burner on this machine. run from a checkout after `cargo build --release`:
#   sudo ./install.sh
# downloads firecracker, the jailer and a guest kernel (pinned and checksummed),
# creates the burner and burner-parse users, installs the binary and systemd
# units, then runs burner doctor. everything is downloaded and checked before
# anything already installed is replaced. safe to run again to upgrade.
set -eu
umask 022

FC_VERSION=v1.18.0
KERNEL_BUILD=20261111-778a26c0594c-0
KERNEL_VERSION=6.1.188
ROOT=/var/lib/burner
BIN=/usr/local/bin/burner

die() { echo "install: $*" >&2; exit 1; }

# sudo ./install.sh --uninstall: everything this script put on the machine, except
# /etc/burner (your config) and the docker images tools/build-image left behind
uninstall() {
    [ "$(id -u)" = 0 ] || die "run as root (sudo ./install.sh --uninstall)"
    if [ -x "$BIN" ] && "$BIN" ls --json 2>/dev/null | grep -q '"id"'; then
        die "VMs are running (burner ls), stop them first"
    fi
    systemctl disable --now burner-reap.timer burner-net.service 2>/dev/null || true
    if [ -x "$BIN" ]; then "$BIN" net down >/dev/null 2>&1 || true; fi
    rm -f /etc/systemd/system/burner-net.service /etc/systemd/system/burner-reap.service \
        /etc/systemd/system/burner-reap.timer
    systemctl daemon-reload
    rm -rf "$ROOT" /run/burner
    rm -f "$BIN"
    for u in burner-parse burner; do
        id "$u" >/dev/null 2>&1 && userdel "$u"
    done
    echo "removed burner. left in place: /etc/burner, the ufw rule if you added one, docker images named burner-img-*"
    exit 0
}
[ "${1:-}" = --uninstall ] && uninstall

[ "$(id -u)" = 0 ] || die "run as root (sudo ./install.sh)"
[ "$(uname -s)" = Linux ] || die "burner only runs on linux"
case "$(uname -m)" in
    x86_64)
        FC_SHA=1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd
        KERNEL_SHA=f5735774e2570d9df451fc5665f3525d3baf723fa6a8a413a03591d5742b39a5 ;;
    aarch64)
        FC_SHA=2a6130ff0338901ff9d7fbd73ce046c6b1c6123889dc84a34d678aa53bd0c0c2
        KERNEL_SHA=7e7f3c7073c36e334e33e8a74ae744cea06c914f0ab9303b9e557e4106840da4 ;;
    *) die "unsupported cpu $(uname -m), firecracker needs x86_64 or aarch64" ;;
esac
ARCH=$(uname -m)

src=$(cd "$(dirname "$0")" && pwd)
bin="$src/target/release/burner"
[ -x "$bin" ] || die "no $bin, build it first: cargo build --release"
for t in curl tar sha256sum ip nft mkfs.ext4 conntrack systemctl useradd; do
    command -v "$t" >/dev/null 2>&1 || die "missing $t"
done
for f in burner-net.service burner-reap.service burner-reap.timer; do
    [ -f "$src/dist/$f" ] || die "missing dist/$f in the checkout"
done

# a service account burner can trust: exists or gets created, never root, never
# a login account someone else already uses
account() { # name
    if ! id "$1" >/dev/null 2>&1; then
        echo "creating the $1 user"
        useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$1"
    fi
    uid=$(id -u "$1")
    [ "$uid" != 0 ] || die "user $1 is root, burner needs an unprivileged account"
    max=$(awk '$1 == "SYS_UID_MAX" {print $2}' /etc/login.defs 2>/dev/null)
    [ "$uid" -le "${max:-999}" ] || die "user $1 (uid $uid) looks like a person's account, not a system one"
    case "$(getent passwd "$1" | cut -d: -f7)" in
        */nologin|*/false) ;;
        *) die "user $1 has a login shell, burner wants an account nobody logs in as" ;;
    esac
}

# dirs root writes into must not be writable by anyone else
root_only() { # path
    p=$1
    while [ -n "$p" ] && [ "$p" != / ]; do
        if [ -e "$p" ]; then
            [ "$(stat -c %u "$p")" = 0 ] || die "$p isn't owned by root"
            case "$(stat -c %A "$p")" in
                ?????w????|????????w?) die "$p is writable by others than root" ;;
            esac
        fi
        p=$(dirname "$p")
    done
}

fetch() { # url sha256 dest
    curl -fsSL --proto '=https' --retry 3 -o "$3" "$1" || die "download failed: $1"
    echo "$2  $3" | sha256sum -c --quiet - || die "checksum mismatch for $1"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. stage: download and check everything first
echo "firecracker $FC_VERSION"
fetch "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz" \
    "$FC_SHA" "$work/fc.tgz"
tar -xzf "$work/fc.tgz" -C "$work"
fc="$work/release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH"
jailer="$work/release-$FC_VERSION-$ARCH/jailer-$FC_VERSION-$ARCH"
"$fc" --version >/dev/null 2>&1 || die "the downloaded firecracker doesn't run here"
"$jailer" --version >/dev/null 2>&1 || die "the downloaded jailer doesn't run here"

echo "guest kernel $KERNEL_VERSION"
fetch "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$KERNEL_BUILD/$ARCH/vmlinux-$KERNEL_VERSION" \
    "$KERNEL_SHA" "$work/vmlinux"

"$bin" config >/dev/null 2>&1 || "$bin" --help >/dev/null 2>&1 || die "$bin doesn't run here"

account burner
account burner-parse
[ "$(id -u burner)" != "$(id -u burner-parse)" ] || die "burner and burner-parse must be different users"
getent group kvm >/dev/null && usermod -aG kvm burner

# 2. install: each file goes in under a temp name and is renamed into place
install -d -m 0755 "$ROOT" "$ROOT/fc" "$ROOT/kernel" "$ROOT/images"
for d in "$ROOT" "$ROOT/fc" "$ROOT/kernel" "$ROOT/images" /etc/burner "$(dirname "$BIN")"; do
    root_only "$d"
done
put() { # mode src dest
    install -m "$1" "$2" "$3.new"
    mv -f "$3.new" "$3"
}
# firecracker and the jailer go in a directory per release, and $ROOT/bin is a
# symlink switched with one rename: a launch never pairs two different versions
rel="$ROOT/fc/$FC_VERSION"
install -d -m 0755 "$rel"
put 0755 "$fc" "$rel/firecracker"
put 0755 "$jailer" "$rel/jailer"
if [ -d "$ROOT/bin" ] && [ ! -L "$ROOT/bin" ]; then
    mv "$ROOT/bin" "$ROOT/fc/pre-$FC_VERSION.old"   # an install from before versioned dirs
fi
ln -sfn "fc/$FC_VERSION" "$ROOT/bin.new"
mv -fT "$ROOT/bin.new" "$ROOT/bin"
put 0644 "$work/vmlinux" "$ROOT/kernel/vmlinux-$KERNEL_VERSION"
ln -sfn "vmlinux-$KERNEL_VERSION" "$ROOT/kernel/vmlinux.new"
mv -fT "$ROOT/kernel/vmlinux.new" "$ROOT/kernel/vmlinux"
put 0755 "$bin" "$BIN"

install -d -m 0755 /etc/burner
if [ -s /etc/burner/config.toml ]; then
    "$BIN" config >/dev/null || die "/etc/burner/config.toml has errors (above), fix it and run this again"
else
    "$BIN" config > /etc/burner/config.toml.new
    mv -f /etc/burner/config.toml.new /etc/burner/config.toml
fi

for f in burner-net.service burner-reap.service burner-reap.timer; do
    put 0644 "$src/dist/$f" "/etc/systemd/system/$f"
done
systemctl daemon-reload
systemctl enable burner-net.service burner-reap.timer >/dev/null
# reload, not restart: a restart runs net down first, which stops networked VMs
systemctl reload-or-restart burner-net.service || die "burner-net failed to start, see: journalctl -u burner-net"
systemctl start burner-reap.timer
# one pass now, so networked runs don't wait for the timer's first tick
"$BIN" reap || die "burner reap failed, see journalctl -t burner"

echo
"$BIN" doctor || die "burner doctor found problems, see the FAIL lines above"
echo
[ -n "$(ls "$ROOT/images" 2>/dev/null)" ] || echo "no images yet: tools/build-image alpine (needs docker)"
# a changed guest/init only reaches VMs through a rebuilt image
for img in "$ROOT"/images/*/; do
    [ -d "$img" ] || continue
    cmp -s "$src/guest/init" "$img/init" || echo "rebuild $(basename "$img") to pick up the new guest init: tools/build-image $(basename "$img")"
done
