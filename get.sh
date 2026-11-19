#!/bin/sh
# install or upgrade burner from the latest release:
#   curl -fsSL https://raw.githubusercontent.com/patrickhere/burner/main/get.sh | sh
# downloads the release for this cpu, checks it against SHA256SUMS, installs the
# packages burner needs, runs install.sh and builds the alpine image.
#   BURNER_VERSION=v0.1.0   install that release instead of the latest
#   NO_COLOR=1              plain output
# everything runs from main() at the bottom, so a download cut off halfway
# runs nothing
set -eu

REPO=patrickhere/burner
SHARE=/usr/local/share/burner

ui() {
    TTY=""
    [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ] && TTY=1
    if [ -n "$TTY" ]; then
        B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[0m')
        F=$(printf '\033[38;5;208m') G=$(printf '\033[32m') Y=$(printf '\033[33m') E=$(printf '\033[31m')
    else
        B="" D="" R="" F="" G="" Y="" E=""
    fi
    case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
        *UTF-8* | *utf8* | *UTF8*) FRAMES="⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏" ;;
        *) FRAMES="- \\ | /" ;;
    esac
}

banner() {
    printf '\n  %s%sburner%s  %sthrowaway linux VMs on your own hardware%s\n\n' "$B" "$F" "$R" "$D" "$R"
}

ok() { printf '  %s+%s %-26s %s%s%s\n' "$G" "$R" "$1" "$D" "${2:-}" "$R"; }
warn() { printf '  %s!%s %s\n' "$Y" "$R" "$1"; }

die() {
    printf '\n  %sx%s %s\n' "$E" "$R" "$1" >&2
    shift
    for line in "$@"; do printf '    %s\n' "$line" >&2; done
    printf '\n' >&2
    exit 1
}

# run a step with a spinner, its output into the log. on failure, the end of
# the log and where to find the rest
run() {
    step=$1
    shift
    printf '\n== %s\n' "$step" >>"$LOG"
    rc=0
    if [ -n "$TTY" ]; then
        "$@" >>"$LOG" 2>&1 &
        pid=$!
        while kill -0 "$pid" 2>/dev/null; do
            # first frame shown, then rotated to the back
            frame=${FRAMES%% *}
            FRAMES="${FRAMES#* } $frame"
            printf '\r  %s%s%s %s' "$F" "$frame" "$R" "$step"
            sleep 0.1
        done
        wait "$pid" || rc=$?
        printf '\r\033[K'
    else
        "$@" >>"$LOG" 2>&1 || rc=$?
    fi
    if [ "$rc" != 0 ]; then
        printf '  %sx%s %s\n\n' "$E" "$R" "$step" >&2
        tail -n 15 "$LOG" | sed 's/^/    /' >&2
        KEEP_LOG=1
        die "that step failed, the whole log is in $LOG"
    fi
}

as_root() {
    if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

not_linux() {
    case "$(uname -s)" in
        Darwin)
            die "burner runs on linux with kvm, so on a mac it runs inside a linux VM." \
                "on an M3 or newer with macOS 15 or later:" \
                "" \
                "  brew install lima" \
                "  limactl start --name=burner --vm-type=vz --set '.nestedVirtualization=true' template:ubuntu-24.04" \
                "  limactl shell burner" \
                "" \
                "then run this installer again in there."
            ;;
        MINGW* | MSYS* | CYGWIN* | Windows*)
            die "burner runs on linux with kvm. on windows 11, run this installer inside WSL2" \
                "with nested virtualization on (/dev/kvm has to exist in there)."
            ;;
        *) die "burner runs on linux with kvm, this is $(uname -s)" ;;
    esac
}

# the tools install.sh checks for, and the package each one comes in
missing_packages() {
    for pair in ip:iproute2 nft:nftables conntrack:conntrack mkfs.ext4:e2fsprogs tar:tar; do
        command -v "${pair%%:*}" >/dev/null 2>&1 || printf '%s ' "${pair#*:}"
    done
}

install_packages() {
    # shellcheck disable=SC2086,SC2046 # one word per package
    if command -v apt-get >/dev/null 2>&1; then
        as_root env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $1
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y -q $(echo "$1" | sed 's/conntrack/conntrack-tools/')
    elif command -v pacman >/dev/null 2>&1; then
        as_root pacman -S --needed --noconfirm $(echo "$1" | sed 's/conntrack/conntrack-tools/')
    else
        return 1
    fi
}

download() {
    base="https://github.com/$REPO/releases/download/$version"
    curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz"
    curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
    (cd "$tmp" && grep " $name.tar.gz\$" SHA256SUMS | sha256sum -c -)
}

unpack() {
    # kept, so tools/build-image is there for more images later
    # explicit mode: a root umask of 077 would make it unreadable to the build step
    as_root install -d -m 0755 "$SHARE"
    as_root rm -rf "${SHARE:?}/$name"
    as_root tar -xzf "$tmp/$name.tar.gz" -C "$SHARE" --no-same-owner
    as_root ln -sfn "$name" "$SHARE/current"
}

main() {
    ui
    banner
    start=$(date +%s)
    # ip, nft and mkfs.ext4 live in sbin, which isn't on every user's PATH
    PATH="$PATH:/usr/sbin:/sbin"

    [ "$(uname -s)" = Linux ] || not_linux
    case "$(uname -m)" in
        x86_64 | aarch64) arch=$(uname -m) ;;
        *) die "burner needs an x86_64 or aarch64 cpu, this is $(uname -m)" ;;
    esac
    [ -e /dev/kvm ] || die "no /dev/kvm here." \
        "kvm is off in the bios, or this is a VM without nested virtualization."
    for t in curl sha256sum; do
        command -v "$t" >/dev/null 2>&1 || die "this installer needs $t"
    done
    if [ "$(id -u)" != 0 ]; then
        command -v sudo >/dev/null 2>&1 || die "run this as root, or install sudo"
        # asked once, up front, since the steps below hide their output
        sudo -v || die "burner installs as root, and sudo said no"
    fi
    kernel=$(uname -r)
    ok "this machine" "linux $arch, kvm, kernel ${kernel%%-*}"

    LOG=$(mktemp /tmp/burner-install-XXXXXX)
    KEEP_LOG=""
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"; [ -n "$KEEP_LOG" ] || rm -f "$LOG"' EXIT

    pkgs=$(missing_packages)
    if [ -n "$pkgs" ]; then
        command -v apt-get >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1 || command -v pacman >/dev/null 2>&1 \
            || die "install these first: $pkgs"
        run "installing packages" install_packages "$pkgs"
        ok "packages" "installed ${pkgs% }"
    else
        ok "packages" "all there"
    fi

    version=${BURNER_VERSION:-}
    if [ -z "$version" ]; then
        # releases/latest redirects to the newest tag, no api rate limit
        url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") \
            || die "couldn't reach github"
        version=${url##*/}
    fi
    case "$version" in
        v[0-9]*) ;;
        *) die "couldn't tell which release is the latest (got \"$version\")" ;;
    esac
    old=$(burner --version 2>/dev/null | awk '{print $2}') || old=""

    name="burner-$version-$arch-linux"
    run "downloading $version" download
    size=$(du -k "$tmp/$name.tar.gz" | awk '{printf "%.1f MB", $1 / 1024}')
    ok "downloaded $version" "$size, sha256 matches"

    run "unpacking" unpack
    if [ -n "$old" ] && [ "v$old" != "$version" ]; then
        label="upgraded $old -> ${version#v}"
    elif [ -n "$old" ]; then
        label="reinstalled ${version#v}"
    else
        label="installed"
    fi
    run "installing" as_root "$SHARE/$name/install.sh"
    fc=$(sed -n 's/^firecracker v\([0-9.]*\).*/\1/p' "$LOG" | tail -n 1)
    ok "$label" "firecracker ${fc:-ok}, systemd units, reaper"

    if ! as_root /usr/local/bin/burner images 2>/dev/null | grep -qx alpine \
        || grep -q 'rebuild alpine' "$LOG"; then
        run "building the alpine image" "$SHARE/$name/tools/build-image" alpine
        img=$(sed -n 's/^alpine: \([0-9.]*[KMG]\).*/\1/p' "$LOG" | tail -n 1)
        ok "alpine image" "${img:-built}"
    else
        ok "alpine image" "already there"
    fi

    # the first sentence of each doctor warning, doctor itself has the rest
    warns=$(as_root /usr/local/bin/burner doctor 2>/dev/null | sed -n 's/^warn *[a-z]* *//p')
    if [ -n "$warns" ]; then
        printf '\n'
        printf '%s\n' "$warns" | while read -r w; do
            w=${w%%. *}
            [ "${#w}" -le 90 ] || w="$(printf '%.87s' "$w")..."
            warn "$w"
        done
        printf '    %ssudo burner doctor says more%s\n' "$D" "$R"
    fi

    took=$(($(date +%s) - start))
    printf '\n  %sburner %s is ready%s %s(%ss)%s\n\n' "$B" "${version#v}" "$R" "$D" "$took" "$R"
    printf '  %stry it%s\n' "$D" "$R"
    printf "    sudo burner run -- 'uname -a; cat /etc/alpine-release'\n"
    printf '    sudo burner shell alpine\n'
    if [ -x /usr/local/bin/burner-tui ]; then printf '    burner-tui\n'; fi
    printf '\n  %smore images: %s/current/tools/build-image NAME%s\n' "$D" "$SHARE" "$R"
    printf '  %sdocs: https://github.com/%s%s\n\n' "$D" "$REPO" "$R"
}

main "$@"
