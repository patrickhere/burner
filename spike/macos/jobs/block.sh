# run with --block 140.82.112.0/20 (github): github refused, the rest still works
t() {
    echo "\$ $*"
    "$@" > /tmp/out 2>&1
    rc=$?
    head -3 /tmp/out
    echo "-> rc=$rc"
}
t curl -sI -m 5 https://github.com
t curl -sI -m 5 https://example.com
