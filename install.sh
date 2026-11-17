#!/bin/sh
# install burner on this machine. run from a checkout after `cargo build --release`:
#   sudo ./install.sh
# downloads firecracker, the jailer and a guest kernel (pinned and checksummed),
# creates the burner user, installs the binary and systemd units, then runs burner doctor.
set -eu

FC_VERSION=v1.18.0
KERNEL_BUILD=20261111-778a26c0594c-0
KERNEL_VERSION=6.1.188
ROOT=/var/lib/burner

die() { echo "install: $*" >&2; exit 1; }

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
for t in curl tar sha256sum ip nft mkfs.ext4 systemctl; do
    command -v "$t" >/dev/null 2>&1 || die "missing $t"
done

fetch() { # url sha256 dest
    curl -fsSL --retry 3 -o "$3" "$1"
    echo "$2  $3" | sha256sum -c --quiet - || die "checksum mismatch for $1"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "firecracker $FC_VERSION"
fetch "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz" \
    "$FC_SHA" "$work/fc.tgz"
tar -xzf "$work/fc.tgz" -C "$work"
install -d -m 0755 "$ROOT" "$ROOT/bin" "$ROOT/kernel" "$ROOT/images"
install -m 0755 "$work/release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH" "$ROOT/bin/firecracker"
install -m 0755 "$work/release-$FC_VERSION-$ARCH/jailer-$FC_VERSION-$ARCH" "$ROOT/bin/jailer"

echo "guest kernel $KERNEL_VERSION"
fetch "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$KERNEL_BUILD/$ARCH/vmlinux-$KERNEL_VERSION" \
    "$KERNEL_SHA" "$work/vmlinux"
install -m 0644 "$work/vmlinux" "$ROOT/kernel/vmlinux-$KERNEL_VERSION"
ln -sfn "vmlinux-$KERNEL_VERSION" "$ROOT/kernel/vmlinux"

if ! id burner >/dev/null 2>&1; then
    echo "creating the burner user"
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin burner
fi
getent group kvm >/dev/null && usermod -aG kvm burner

install -m 0755 "$bin" /usr/local/bin/burner
install -d -m 0755 /etc/burner
[ -f /etc/burner/config.toml ] || burner config > /etc/burner/config.toml
install -m 0644 "$src"/dist/burner-net.service "$src"/dist/burner-reap.service "$src"/dist/burner-reap.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now burner-net.service burner-reap.timer

echo
burner doctor || true
echo
[ -n "$(ls "$ROOT/images" 2>/dev/null)" ] || echo "no images yet: tools/build-image alpine (needs docker)"
