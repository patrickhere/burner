#!/bin/sh
# install or upgrade burner from the latest release:
#   curl -fsSL https://get.burnervm.dev | sh
# downloads the release for this cpu, checks it against SHA256SUMS, installs the
# packages burner needs, runs install.sh and sets up the alpine image. on a mac
# it installs burner with homebrew and runs burner setup.
#   ... | sh -s -- --allow USER   let USER run VMs through sudo, no password
#   ... | sh -s -- --debian       the debian image too, without asking
#   ... | sh -s -- --force        upgrade even with VMs running
#   ... | sh -s -- --uninstall    take burner back off. --purge: its config too
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
    # questions only need someone at a terminal, with or without color
    ASK=""
    [ -t 1 ] && ASK=1
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
    # in the background either way: on the left of || a function runs with
    # set -e off, so a step's first failure wouldn't stop it
    "$@" >>"$LOG" 2>&1 &
    pid=$!
    if [ -n "$TTY" ]; then
        while kill -0 "$pid" 2>/dev/null; do
            # first frame shown, then rotated to the back
            frame=${FRAMES%% *}
            FRAMES="${FRAMES#* } $frame"
            printf '\r  %s%s%s %s' "$F" "$frame" "$R" "$step"
            sleep 0.1
        done
    fi
    wait "$pid" || rc=$?
    [ -z "$TTY" ] || printf '\r\033[K'
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

# the same where nothing may ask for a password, on the way out
as_root_n() {
    if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi
}

# a question on the terminal, even with this script on stdin. nothing when
# there's no terminal to ask on
ask() { # prompt
    [ -n "$ASK" ] && (: </dev/tty) 2>/dev/null || return 1
    printf '  %s?%s %s ' "$F" "$R" "$1" >/dev/tty
    read -r answer </dev/tty || return 1
}

yes_to() { # prompt
    ask "$1 [y/N]" || return 1
    case "$answer" in y | Y | yes) return 0 ;; *) return 1 ;; esac
}

# sudo asked once, up front, since the steps hide their output
need_root() {
    if [ "$(id -u)" != 0 ]; then
        command -v sudo >/dev/null 2>&1 || die "run this as root, or install sudo"
        sudo -v || die "burner installs as root, and sudo said no"
    fi
}

not_linux() {
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN* | Windows*)
            die "burner runs on linux with kvm. on windows 11, run this installer inside WSL2" \
                "with nested virtualization on (/dev/kvm has to exist in there)."
            ;;
        *) die "burner runs on linux with kvm, this is $(uname -s)" ;;
    esac
}

# on a mac burner runs VMs itself on hypervisor.framework through libkrun.
# homebrew builds it, signs it and pulls in libkrun and e2fsprogs
mac() {
    [ "$(uname -m)" = arm64 ] || die "burner needs an apple silicon mac, intel macs aren't supported"
    v=$(sw_vers -productVersion)
    [ "${v%%.*}" -ge 15 ] || die "burner needs macOS 15 or later, this is $v"
    chip=$(sysctl -n machdep.cpu.brand_string)
    ok "this machine" "macOS $v, $chip"
    command -v brew >/dev/null 2>&1 || die "on a mac burner installs through homebrew, and it isn't here." \
        "get it from https://brew.sh, then run this again."

    LOG=$(mktemp /tmp/burner-install-XXXXXX)
    KEEP_LOG=""
    trap '[ -n "$KEEP_LOG" ] || rm -f "$LOG"' EXIT
    if [ -n "$uninstall" ]; then
        mac_uninstall
        return
    fi
    [ -z "$allow" ] || warn "--allow is for linux, on a mac VMs run as you without sudo"
    if brew list --formula burner >/dev/null 2>&1; then
        run "upgrading with homebrew" brew upgrade burnervm/tap/burner
        ok "homebrew" "burnervm/tap/burner, up to date"
    else
        run "installing with homebrew" brew install burnervm/tap/burner
        ok "homebrew" "burnervm/tap/burner, with libkrun"
    fi
    run "installing the guest kernel and alpine image" burner setup
    version=$(burner --version 2>/dev/null | awk '{print $2}')
    ok "burner" "native, ${version:-installed}"
    # an upgrade brings the debian image along when it's there
    if burner images 2>/dev/null | grep -qx debian; then
        run "updating the debian image" burner setup debian
        ok "debian image" "updated"
    elif [ -n "$debian" ] || yes_to "the debian image too, for install scripts that expect debian?"; then
        run "fetching the debian image" burner setup debian
        ok "debian image" "installed"
    fi
    if command -v limactl >/dev/null 2>&1 && limactl list -q 2>/dev/null | grep -qx burnervm; then
        printf '  %sthe lima VM from burner 0.1.x is still there: limactl delete burnervm%s\n' "$D" "$R"
    fi

    took=$(($(date +%s) - start))
    printf '\n  %sburner %s is ready%s %s(%ss)%s\n\n' "$B" "${version:-}" "$R" "$D" "$took" "$R"
    printf '  %stry it%s\n' "$D" "$R"
    printf "    burner run -- 'uname -a; cat /etc/alpine-release'\n"
    printf '    burner shell alpine\n'
    printf '    burner doctor\n'
    printf '\n  %sdocs: https://github.com/%s%s\n\n' "$D" "$REPO" "$R"
}

# burner setup --remove, then homebrew takes burner off. --purge: the config
# and the run log too
mac_uninstall() {
    support="$HOME/Library/Application Support/burner"
    if command -v burner >/dev/null 2>&1 && burner setup --help 2>/dev/null | grep -q -- --remove; then
        run "removing the kernel and images" burner setup --remove
        ok "kernel and images" "removed"
    fi
    if brew list --formula burner >/dev/null 2>&1; then
        run "uninstalling with homebrew" brew uninstall burnervm/tap/burner
        ok "homebrew" "burner uninstalled"
    fi
    if [ -n "$purge" ]; then
        rm -rf "$support"
        ok "$support" "removed, config, run log and any other images too"
    elif [ -e "$support" ]; then
        printf '\n  %sleft: %s, --purge removes it%s\n' "$D" "$support" "$R"
    fi
    printf '\n  %sburner is off this mac%s\n\n' "$B" "$R"
}

# install.sh --uninstall from the release installed here, then this
# script's own copies. --purge: /etc/burner and the sudo rule too
linux_uninstall() {
    [ -x "$SHARE/current/install.sh" ] || die "there's no $SHARE/current/install.sh, so burner wasn't installed by this script." \
        "run sudo ./install.sh --uninstall from the release you installed by hand."
    roots_alone "$SHARE/current/install.sh" || die "$SHARE/current/install.sh isn't root's alone, so it won't run it as root"
    # an install.sh before 0.3.1 doesn't know --purge, that part is done here then
    how=--uninstall
    if [ -n "$purge" ] && grep -q -- '--purge)' "$SHARE/current/install.sh"; then how=--purge; fi
    run "removing burner" as_root "$SHARE/current/install.sh" "$how"
    ok "burner" "removed, with /var/lib/burner (its images and run log)"
    as_root rm -rf "$SHARE"
    ok "$SHARE" "removed"
    left=$(sed -n 's/^removed burner.* left in place: //p' "$LOG" | tail -n 1)
    if [ -n "$purge" ] && [ "$how" = --uninstall ]; then
        as_root rm -rf /etc/burner
        as_root rm -f /etc/sudoers.d/burner /etc/sudoers.d/burner.new /etc/sudoers.d/burner.old
        left="the ufw rule if you added one, docker images named burner-img-*"
    fi
    [ -n "$purge" ] && ok "config and sudo rule" "removed"
    [ -z "$left" ] || printf '\n  %sleft: %s%s\n' "$D" "$left" "$R"
    printf '\n  %sburner is off this machine%s\n\n' "$B" "$R"
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

# as root into root's own temp dir: what's checked is what root unpacks and
# runs, nobody else can swap it in between
download() {
    base="https://github.com/$REPO/releases/download/$version"
    as_root curl -fsSL -o "$tmp/$name.tar.gz" "$base/$name.tar.gz"
    as_root curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
    # shellcheck disable=SC2016 # the inner sh expands them
    as_root sh -c 'cd "$1" && grep " $2.tar.gz\$" SHA256SUMS | sha256sum -c -' sh "$tmp" "$name"
}

# root runs install.sh from $SHARE: nobody else may be able to write a path
# there or any dir above it, as written or where it leads
roots_alone() { # path
    for p in "$1" "$(readlink -f "$1")"; do
        while [ -n "$p" ] && [ "$p" != / ]; do
            [ "$(stat -c %u "$p")" = 0 ] || { echo "$p isn't owned by root" >&2; return 1; }
            # a symlink's own mode means nothing, its owner and its dir do
            [ -L "$p" ] || case "$(stat -c %A "$p")" in
                ?????w???? | ????????w?) echo "$p is writable by others than root" >&2; return 1 ;;
            esac
            p=$(dirname "$p")
        done
    done
}

# into $SHARE/.new, so the release that's there stays whole until this one
# is installed
unpack() {
    # kept, so tools/build-image is there for more images later
    # explicit mode: a root umask of 077 would make it unreadable to the build step
    as_root install -d -m 0755 "$SHARE"
    roots_alone "$SHARE" || return 1
    as_root rm -rf "$SHARE/.new"
    as_root install -d -m 0755 "$SHARE/.new"
    as_root tar -xzf "$tmp/$name.tar.gz" -C "$SHARE/.new" --no-same-owner
    # install.sh keeps it for burner setup, which checks the images against it
    as_root install -m 0644 "$tmp/SHA256SUMS" "$SHARE/.new/$name/SHA256SUMS"
}

# a run killed between switch's two moves left the release current points
# at in .old: back it goes
recover_share() {
    [ -d "$SHARE/.old" ] || return 0
    roots_alone "$SHARE/.old" || die "$SHARE isn't root's alone, so this won't touch it"
    cur=$(readlink "$SHARE/current" 2>/dev/null) || return 0
    [ -e "$SHARE/$cur" ] || as_root mv -T "$SHARE/.old" "$SHARE/$cur"
}

# once it's installed: current is this release, previous the one before, and
# any older one goes. sudo $SHARE/previous/install.sh goes back to it
switch() {
    as_root rm -rf "$SHARE/.old"
    if [ -e "$SHARE/$name" ] && as_root diff -r "$SHARE/$name" "$SHARE/.new/$name" >/dev/null 2>&1; then
        # a reinstall of the same files: the copy that's there stays
        :
    elif [ -e "$SHARE/$name" ] && as_root mv --exchange -T "$SHARE/.new/$name" "$SHARE/$name" 2>/dev/null; then
        # one step where mv can (coreutils 9.5 and later)
        :
    else
        if [ -e "$SHARE/$name" ]; then as_root mv -T "$SHARE/$name" "$SHARE/.old"; fi
        as_root mv -T "$SHARE/.new/$name" "$SHARE/$name"
    fi
    as_root rm -rf "$SHARE/.new" "$SHARE/.old"
    was=$(readlink "$SHARE/current" 2>/dev/null) || was=""
    if [ -n "$was" ] && [ "$was" != "$name" ] && [ -d "$SHARE/$was" ]; then
        as_root ln -sfn "$was" "$SHARE/previous.new"
        as_root mv -fT "$SHARE/previous.new" "$SHARE/previous"
    fi
    as_root ln -sfn "$name" "$SHARE/current.new"
    as_root mv -fT "$SHARE/current.new" "$SHARE/current"
    keep=$(readlink "$SHARE/previous" 2>/dev/null) || keep=""
    for d in "$SHARE"/burner-v*-linux; do
        [ -d "$d" ] || continue
        case "${d##*/}" in
            "$name" | "$keep") ;;
            *) as_root rm -rf "$d" ;;
        esac
    done
}

# whether this release has an image for this cpu and a burner setup that
# fetches it (linux setup is new in 0.3.1)
in_release() { # image
    as_root grep -q "  $1-$arch\.ext4\.gz\$" "$tmp/SHA256SUMS" \
        && as_root /usr/local/bin/burner setup --help >/dev/null 2>&1
}

# an image from the release when it has one, else built here
image() { # name
    if in_release "$1"; then
        run "fetching the $1 image" as_root /usr/local/bin/burner setup "$1"
    else
        run "building the $1 image" "$SHARE/current/tools/build-image" "$1"
    fi
    size=$(as_root du -h "/var/lib/burner/images/$1/rootfs.ext4" 2>/dev/null | cut -f1)
    ok "$1 image" "${size:-installed}"
}

main() {
    allow="" debian="" force="" uninstall="" purge=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --allow)
                [ $# -ge 2 ] || { ui; die "--allow takes a user name"; }
                allow="$allow $2"
                shift
                ;;
            --debian) debian=1 ;;
            --force) force=1 ;;
            --uninstall) uninstall=1 ;;
            --purge) uninstall=1 purge=1 ;;
            *) ui; die "unknown option $1" "it takes --allow USER, --debian, --force, --uninstall and --purge" ;;
        esac
        shift
    done
    ui
    banner
    start=$(date +%s)
    # ip, nft and mkfs.ext4 live in sbin, which isn't on every user's PATH
    PATH="$PATH:/usr/sbin:/sbin"

    if [ "$(uname -s)" = Darwin ]; then
        mac
        return
    fi
    [ "$(uname -s)" = Linux ] || not_linux
    if [ -n "$uninstall" ]; then
        need_root
        recover_share
        LOG=$(mktemp /tmp/burner-install-XXXXXX)
        KEEP_LOG=""
        trap '[ -n "$KEEP_LOG" ] || rm -f "$LOG"' EXIT
        linux_uninstall
        return
    fi
    case "$(uname -m)" in
        x86_64 | aarch64) arch=$(uname -m) ;;
        *) die "burner needs an x86_64 or aarch64 cpu, this is $(uname -m)" ;;
    esac
    [ -e /dev/kvm ] || die "no /dev/kvm here." \
        "kvm is off in the bios, or this is a VM without nested virtualization."
    for t in curl sha256sum; do
        command -v "$t" >/dev/null 2>&1 || die "this installer needs $t"
    done
    need_root
    recover_share
    kernel=$(uname -r)
    ok "this machine" "linux $arch, kvm, kernel ${kernel%%-*}"

    LOG=$(mktemp /tmp/burner-install-XXXXXX)
    KEEP_LOG=""
    tmp=$(as_root mktemp -d /tmp/burner-get-XXXXXX)
    trap 'as_root_n rm -rf "$tmp"; [ -n "$KEEP_LOG" ] || rm -f "$LOG"' EXIT
    # an upgrade stops for running VMs before downloading anything. install.sh
    # checks again. without SUDO_UID, ls lists every user's VMs
    if [ -z "$force" ] && [ -x /usr/local/bin/burner ] \
        && as_root env SUDO_UID='' /usr/local/bin/burner ls --json 2>/dev/null | grep -q '"id"'; then
        die "VMs are running (sudo burner ls), stop them first." \
            "or upgrade anyway: curl -fsSL https://get.burnervm.dev | sh -s -- --force"
    fi
    # the sudo rule's user, asked now so the steps below run unattended
    if [ -z "$allow" ] && ! as_root test -e /etc/sudoers.d/burner && command -v visudo >/dev/null 2>&1; then
        who=${SUDO_USER:-$(id -un)}
        if [ "$who" != root ]; then
            if yes_to "let $who run VMs through sudo with no password (dist/sudoers.example has what it allows)?"; then
                allow=" $who"
            fi
        elif ask "a user to let run VMs through sudo with no password (enter for none):" && [ -n "$answer" ]; then
            allow=" $answer"
        fi
    fi

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
    size=$(as_root du -k "$tmp/$name.tar.gz" | awk '{printf "%.1f MB", $1 / 1024}')
    ok "downloaded $version" "$size, sha256 matches"

    run "unpacking" unpack
    if [ -n "$old" ] && [ "v$old" != "$version" ]; then
        label="upgraded $old -> ${version#v}"
    elif [ -n "$old" ]; then
        label="reinstalled ${version#v}"
    else
        label="installed"
    fi
    opts=""
    for u in $allow; do opts="$opts --allow $u"; done
    [ -z "$force" ] || opts="$opts --force"
    # a version change marks the images for a refresh before anything is
    # installed, and they stay marked until it went through
    [ "v$old" = "$version" ] || as_root touch "$SHARE/.refresh-images"
    # shellcheck disable=SC2086 # one word per option
    run "installing" as_root "$SHARE/.new/$name/install.sh" $opts
    fc=$(sed -n 's/^firecracker v\([0-9.]*\).*/\1/p' "$LOG" | tail -n 1)
    ok "$label" "firecracker ${fc:-ok}, systemd units, reaper"
    run "keeping $version and the release before it" switch
    rule=$(sed -n 's/^sudo rule: \(.*\) can run burner VMs.*/\1/p' "$LOG" | tail -n 1)
    [ -z "$rule" ] || ok "sudo rule" "$rule, /etc/sudoers.d/burner"

    # a new release brings its images along: more than the guest init can
    # change between them (bash in alpine, debian's disk in 0.3.1)
    # marked (above) until they're through, so a run that stops before then
    # (a failed fetch, ctrl-c) leaves the next one, already on this release,
    # to bring them along
    # with --force and VMs still running, setup won't swap images under them.
    # they stay marked, so running this again once they've stopped does it
    busy=""
    if [ -n "$force" ] && as_root env SUDO_UID='' /usr/local/bin/burner ls --json 2>/dev/null | grep -q '"id"'; then
        busy=1
        warn "VMs are running, so the images stay as they are. once they've stopped, run this again"
    fi
    if [ -z "$busy" ]; then
        upgraded=""
        [ -e "$SHARE/.refresh-images" ] && upgraded=1
        if ! as_root /usr/local/bin/burner images 2>/dev/null | grep -qx alpine \
            || grep -q 'rebuild alpine' "$LOG" || { [ -n "$upgraded" ] && in_release alpine; }; then
            image alpine
        else
            ok "alpine image" "already there"
        fi
        # an upgrade brings the debian image along when it's there. a new one only
        # when you ask: it's ~100M, and built here it needs mmdebstrap
        have_debian=""
        as_root /usr/local/bin/burner images 2>/dev/null | grep -qx debian && have_debian=1
        if [ -n "$have_debian" ] && { grep -q 'rebuild debian' "$LOG" || [ -n "$upgraded" ]; }; then
            if in_release debian; then
                image debian
            elif grep -q 'rebuild debian' "$LOG"; then
                warn "the debian image needs a rebuild for the new guest init: $SHARE/current/tools/build-image debian"
            fi
        elif [ -z "$have_debian" ]; then
            if [ -n "$debian" ] || { in_release debian && yes_to "the debian image too, for install scripts that expect debian?"; }; then
                image debian
            fi
        fi

        as_root rm -f "$SHARE/.refresh-images"
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
    printf '\n'
    if ! as_root /usr/local/bin/burner images 2>/dev/null | grep -qx debian; then
        if in_release debian; then
            printf '  %sdebian 13: sudo burner setup debian%s\n' "$D" "$R"
        else
            printf '  %sdebian 13: %s/current/tools/build-image debian (needs mmdebstrap)%s\n' "$D" "$SHARE" "$R"
        fi
    fi
    [ -n "$rule" ] || printf '  %sother users: sudo %s/current/install.sh --allow USER%s\n' "$D" "$SHARE" "$R"
    printf '  %smore images: %s/current/tools/build-image NAME%s\n' "$D" "$SHARE" "$R"
    printf '  %sdocs: https://github.com/%s%s\n\n' "$D" "$REPO" "$R"
}

main "$@"
