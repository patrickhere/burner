# shellcheck shell=sh
# burner -H runs this on the far end as: sh -c THIS burner-remote NONCE BURNER MODE ARG...
# NONCE marks the lines meant for the caller, BURNER is the path of burner there or
# empty for the usual one, MODE is auto (sudo on linux unless root), user (never
# sudo) or doctor (auto, and say what the sudo rule allows). what it finds goes
# to stderr as marked lines, then burner runs with ARG.
# no single quotes and no backslashes in here: it travels inside single quotes
n=$1
b=$2
m=$3
shift 3
# burner here runs here: a BURNER_HOST from a profile must not send it on
unset BURNER_HOST
os=$(uname -s)
if [ -z "$b" ]; then
    case $os in
        Darwin) b=/opt/homebrew/bin/burner ;;
        *) b=/usr/local/bin/burner ;;
    esac
fi
if [ ! -x "$b" ]; then
    echo "burner-$n nobin $b" >&2
    exit 125
fi
v=$("$b" --version 2>/dev/null | head -n 1)
u=$(id -u)
s=sudo
if [ "$os" = Darwin ] || [ "$u" = 0 ] || [ "$m" = user ]; then
    s=direct
fi
echo "burner-$n wrap $os $u $s $v" >&2
# whether sudo runs exactly this burner command line without a password,
# without running it
may() {
    if sudo -n -l "$b" "$@" >/dev/null 2>&1; then
        echo yes
    else
        echo no
    fi
}
if [ "$m" = doctor ] && [ "$s" = sudo ]; then
    echo "burner-$n sudo run $(may run --remote "1:$n" -- true)" >&2
    echo "burner-$n sudo shell $(may shell --remote "1:$n")" >&2
    echo "burner-$n sudo ls $(may ls)" >&2
    echo "burner-$n sudo kill $(may kill burner-000000000000)" >&2
    echo "burner-$n sudo images $(may images)" >&2
    echo "burner-$n sudo log $(may log)" >&2
    echo "burner-$n sudo explain $(may explain)" >&2
    echo "burner-$n sudo doctor $(may "$@")" >&2
    if [ "$(may "$@")" = no ]; then
        s=direct
    fi
fi
if [ "$s" = sudo ]; then
    if [ "$(may "$@")" = no ]; then
        echo "burner-$n nosudo" >&2
        exit 125
    fi
    exec sudo -n "$b" "$@"
fi
exec "$b" "$@"
