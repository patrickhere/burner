# burner

[![ci](https://github.com/patrickhere/burner/actions/workflows/ci.yml/badge.svg)](https://github.com/patrickhere/burner/actions/workflows/ci.yml) [![vm suites](https://github.com/patrickhere/burner/actions/workflows/vm-suites.yml/badge.svg)](https://github.com/patrickhere/burner/actions/workflows/vm-suites.yml)

throwaway linux VMs on your own hardware. you ask for a VM, get a root shell or run a command in it, and it's deleted when you're done. each one is a firecracker microVM with its own kernel, and it can reach the internet but not your LAN.

it started as a sandbox on my homelab for running code i don't trust (install scripts, other people's repos, things agents want to run) away from the box that has my keys on it. this is the rebuild in rust so other people can install it. the homelab version stays private, so the history here starts with the rebuild.

status: early. one maintainer, tested on ubuntu 26.04, ubuntu 24.04 (github's runners) and debian 13 on x86_64, and ubuntu 24.04 on aarch64 (in a VM on an apple silicon mac). nobody has audited it.

```
sudo burner shell                          # root shell in a fresh VM, gone when you exit
sudo burner run -- 'uname -a; exit 3'      # run one thing, get its output and exit code back
```

## what it does

- `burner shell [image]` -> a login shell on the VM's console, your terminal size passed in. 60 min by default. `~.` after enter leaves and stops the VM, like ssh
- `burner run -- cmd` -> boots a VM (~2-3s), runs `cmd` in `sh`, streams the first 64K of output live and prints the rest when it ends (the serial console is slow), returns its exit code, deletes the VM
- `--in tar` unpacks a tar from stdin into `/work`, `--in stdin` feeds stdin to the command, `--result tar` hands back whatever the command put in `/out`
- `--net none|web|open` -> no network, http/https plus dns and ping only, or any port but mail. the LAN, the host and other VMs are always blocked
- `burner ls`, `burner kill ID`, `burner images`, `burner doctor`

```
git archive HEAD | sudo burner run --net web --in tar -- 'apk add -q nodejs npm && npm ci && npm test'
tar -c file.zip | sudo burner run --in tar --result tar -- 'unzip -q file.zip -d /out' > res.tar
```

exit codes and the rest of what a wrapper needs are under [from scripts and agents](#from-scripts-and-agents).

the image is plain alpine with git and curl, so the first example installs node itself. build your own with a Dockerfile in `images/NAME/` and `tools/build-image NAME`.

defaults, and the most a run can ask for (`[limits]` in `/etc/burner/config.toml`). an image's `defaults.toml` can change the defaults:

| | default | most |
|---|---|---|
| cpus | 1 | 2 |
| memory | 512M | 3072M per VM, 3072M for all VMs together |
| scratch disk | 2G | 8G |
| time | 10 min for run, 60 min for shell | 30 min for run, 60 for shell |
| network | none for run, web for shell | web, `open` only if you set `net = "open"` |
| VMs at once | | 2, the rest wait |
| bandwidth | 2.5 MB/s each way per VM (`net.rate`), so big installs are slow | |

## how it works

```
burner ──jailer──> firecracker VM ──tap──> nft ──nat──> internet
                        │                   │
                        │                   └──x──> LAN, the host, other VMs
                        └── read-only image, scratch disk, job tar in, result tar out
```

- every VM runs under firecracker's jailer as its own uid and gid, in its own cgroup with cpu, memory and pid caps. the ids come from `jail.uid_base` in the config (1900000000 up, no account behind them), so a guest that breaks out into firecracker can't open another VM's disks or signal its process. a uid stays taken until its VM is cleaned up, and `burner doctor` fails if an account, a group or a `/etc/subuid` range already uses one
- the image is mounted read-only with an overlay on a throwaway scratch disk. the command goes in as a raw tar on its own disk
- results come back as a raw tar the guest writes to another disk. the host never mounts anything the guest wrote: the tar is read by a separate burner process running as its own user, `burner-parse`, with hard rlimits, and only regular files and directories get through
- each VM gets a tap and its own /30. one nft table only lets those taps out the uplink, minus private ranges and the host's own addresses. bandwidth and disk io are capped per VM
- the time limit is enforced by burner and backed up by a reaper timer, and a VM's slot is only freed once its cgroup is empty

nothing from the host goes into a VM unless you pipe it in. `--net web` means anything that goes in can leave, so don't pipe in secrets.

where to start reading the code:

- `burner/src/run/mod.rs`, the lock order comment at the top. read it before touching anything that takes a lock
- `burner/src/run/launch.rs`, one run from waiting for a slot to teardown
- `burner/src/net.rs`, `ruleset()` is the whole nft table: what a tap can and can't reach
- `burner/src/result.rs`, the parser for the result tar, run as `burner-parse`
- `guest/init`, pid 1 inside the VM: unpacks the job, runs it, writes the result disk
- `burner-tui/`, the terminal UI, which only ever runs the burner binary

## what it protects against

i run it on a box that's only reachable over a VPN. yours might sit on a home LAN or have a public IP. burner assumes the code in the VM is hostile and the host could be any of those.

- burner has no daemon and listens on no port. it's a command you run as root. if you put it behind a web app, a bot or a shared ssh account, everyone who can reach that can boot VMs, and the limits in `/etc/burner/config.toml` (`max_vms`, memory, disk, time, and `net` for the most network a run may ask for) are the only thing between them and your host. as root, burner only reads a config that root owns in a directory only root can write, and through sudo only one in `/etc/burner`, so a sudo rule for burner can't be used to load some other root-owned file. its state dir and locks are root-only, so other users can't sit on a lock and stall it
- a VM can't reach the host on any address, its LAN, other VMs, or anything behind a route that isn't the default one (VPNs, docker networks, tailnets). VM traffic has its own routing table with only the uplink's default route in it, so a VPN that comes up later never applies to VMs. on top of that, a blocked list built from the host's own routes and addresses is refreshed every 30s, and if that refresh fails VMs lose their network instead of keeping a stale filter
- guest packets are checked before conntrack: wrong source address, fragments and floods are dropped at the tap. connections a VM leaves behind are cleared before its slot is reused
- no ipv6 in VMs at all
- on a host with a public IP, VM traffic leaves from that IP. whatever a VM does on the internet looks like you did it. `run` has no network unless you ask, `--net open` is off unless you set it in the config and still blocks mail ports, and every VM is rate limited, but that's damage control
- on a home network behind NAT, your router's public address is just "the internet" to burner, and from the inside it often answers with the router's own admin page or ssh, or loops back into your port forwards. set `net.block_public_ip = true` and burner looks that address up every 10 min (from icanhazip.com, ipify.org as a fallback) and blocks it, or put it in `net.block` yourself. `burner doctor` warns when the host looks NATed and nothing public is blocked
- nothing on the LAN or the internet can open a connection into a VM, only replies to what the VM started get back in
- everything the guest sends back is treated as hostile: console output going to a terminal is escaped (piped somewhere else, it's the guest's bytes as they are), the shell goes through a filter that strips terminal tricks (window titles, clipboard writes, escape replies), and the result tar is parsed by a separate unprivileged user with hard limits
- a VM that hangs, a wrapper that gets killed, a full disk or a crash mid-run all end with the VM stopped and its slot freed by the reaper

what it doesn't cover: a bug in firecracker or kvm itself (keep the host kernel and burner's pinned firecracker updated), side channels between VMs on the same cpu, and anything you pipe in yourself.

## install

linux on x86_64 or aarch64 with kvm and cgroup v2. one line does it all: it downloads the latest release, checks it against `SHA256SUMS`, installs the packages it needs (apt, dnf or pacman), runs `install.sh` and builds the alpine image:

```
curl -fsSL https://get.burnervm.dev | sh
```

run it again later to upgrade. to do the same by hand, grab the tarball for your cpu (x86_64 or aarch64) and `SHA256SUMS` from the [latest release](https://github.com/patrickhere/burner/releases/latest), then:

```
sudo apt install nftables conntrack e2fsprogs iproute2 curl   # debian/ubuntu
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf burner-v*-$(uname -m)-linux.tar.gz
cd burner-v*-$(uname -m)-linux
sudo ./install.sh                # firecracker, jailer, guest kernel (pinned + checksummed), a user, units
tools/build-image alpine         # an image to boot, uses sudo, no docker
sudo burner doctor
```

releases after 0.1.0 come with build provenance, so you can also check a tarball was built by this repo's release workflow: `gh attestation verify burner-v*-x86_64-linux.tar.gz -R patrickhere/burner`.

on a mac, burner runs inside a linux VM. apple's virtualization passes kvm through to the VM on an M3 or newer with macOS 15 or later, and the homebrew tap sets that up with [lima](https://lima-vm.io). the same `curl ... | sh` line does it for you when it sees a mac, or by hand:

```
brew install burnervm/tap/burner
burner setup                     # makes the VM and installs burner in it, once
burner run -- 'uname -a'         # every burner command runs in the VM, no sudo needed
```

on an M1 or M2 there's no kvm inside the VM, so no burner. on windows 11, WSL2 with nested virtualization should work like a linux box (`/dev/kvm` has to exist inside it), but it hasn't been tried yet.

or from source, with rust 1.88 or newer: `cargo build --release` in a checkout, then the same `sudo ./install.sh` and on.

an image is `images/NAME/packages`, one alpine package per line. `tools/build-image NAME` takes the alpine minirootfs (pinned + checksummed), installs those packages into it with apk in a chroot and writes `/var/lib/burner/images/NAME/rootfs.ext4`. it builds for the host's arch only. an `images/NAME/Dockerfile` with no packages file next to it still gets built the old way, through docker.

if ufw is on, `burner doctor` prints the one route rule it needs. settings live in `/etc/burner/config.toml`, which starts out empty: put only what you change there. `burner config` shows every setting with the defaults filled in.

## letting other users run VMs

anyone who can run `sudo burner` with any arguments can also take the VM network down or reap. to let someone run VMs and nothing else, use `dist/sudoers.example`: it allows `run`, `shell`, `ls`, `kill` and `images`. through sudo, `--config` only takes files in `/etc/burner`, `burner kill` only stops VMs that caller started, and `[limits]` in the config apply to everyone.

## from scripts and agents

- exit codes: the command's own, 124 when it hit the time limit, 125 when the sandbox itself failed, 2 for bad arguments, 130 when interrupted (ctrl-c, SIGTERM, SIGHUP) or killed with `burner kill`
- `--status-fd N` writes one JSON line when the run ends, so a command that exits 124 itself isn't mistaken for a timeout. it has `outcome`, `rc` (the command's exit code, only when outcome is `exited`), `exit` (what burner exits with), `id` and `secs`. outcome is one of `exited`, `timeout`, `killed`, `interrupted`, `busy`, `sandbox_error` or `usage`. sudo closes fds above 2, so through sudo use `--status-fd 2` and read the last line of stderr
- when every slot is taken (`max_vms`, or the memory total), a run waits for one, says `burner: waiting for a slot` on stderr, and gives up with 125 after 10 min. `--no-wait` fails right away instead, with 125 and outcome `busy`
- `sudo burner ls --json` prints `{"vms": [...], "max_vms", "total_mem", "used_mem"}`. each VM has `id`, `tag`, `img`, `vcpus`, `mem`, `disk`, `net`, `status` (`preparing`, `running` or `cleanup-failed`), `owner`, `age`, `ttl` and `ttl_left`. `--tag` on a run makes yours easy to find
- anything the command leaves running in the background (a server started with `&`, a daemon, even one that called setsid) is killed when the command exits, and the run ends there. if the tests need a server, start it and stop it inside the same command

a wrapper that tells a failing test from a timeout or a busy box:

```sh
#!/bin/sh
log=$(mktemp)
git archive HEAD | sudo burner run --net web --in tar --tag tests --status-fd 2 -- 'sh ./test.sh' 2>"$log"
code=$?
outcome=$(tail -n 1 "$log" | grep -o '"outcome":"[a-z_]*"' | cut -d'"' -f4)
case $outcome in
    exited) echo "tests exited $code" ;;
    timeout) echo "tests hit the time limit" ;;
    *) echo "no result ($outcome), see $log" >&2 ;;
esac
exit "$code"
```

## tui

`burner-tui` is a small terminal UI on top of the same commands. pick an image, network, cpus, memory and time limit, see the exact `sudo burner ...` line it'll run, and enter starts the shell or run in your terminal and comes back when it ends. tab shows the running VMs, refreshed every 2s, and `k` kills one after asking.

it only ever runs `burner` (or `$BURNER`), through sudo when you're not root, so the sudoers rule above covers it. release tarballs have it next to burner, `cargo build --release` builds it too, and `install.sh` puts it in `/usr/local/bin`.

## why not docker, gvisor or a hosted sandbox

- docker and podman containers share the host's kernel. one kernel bug or one careless mount and the code is on your box. every burner VM has its own kernel behind kvm
- gvisor puts its own kernel in front of the host's, in software. it's good, but some programs don't run under it, and it's still your kernel underneath. burner leans on hardware virtualization instead
- hosted sandboxes (e2b, modal and friends) run your code on someone else's machines with your inputs. burner runs on yours, with no account and nothing leaving except what the VM sends
- firecracker on its own is a VM monitor, not a tool. burner is the part around it: networking that can't reach your LAN, cleanup when things die, results back without trusting the guest

## when something breaks

- `sudo burner doctor` first. it checks kvm, the tools, the network setup, the reaper and the install, and says what to fix
- burner logs to syslog under the `burner` tag: `journalctl -t burner`. every run logs a start and an end line with its id, and the reaper says what it cleaned up
- the network: `systemctl status burner-net`, and `sudo burner net show` for the rules. a VM with no internet on a docker host is usually docker's FORWARD drop policy, doctor prints the two lines that fix it
- `cleanup-failed` in `burner ls` means a VM stopped but something of it (its cgroup, tap or jail dir) couldn't be removed yet. the reaper retries every 30s and the slot stays taken until it's gone
- `sudo ./install.sh --uninstall` takes it all back off, except `/etc/burner`

## tests

`tests/isolation.sh` (memory and fork bombs, disk and console floods, a hostile result tar, time limits, slots, argument fuzzing) and `tests/network.sh` (what a VM can and can't reach, with targets found on the host it runs on). both need a box with burner installed and an alpine image, and run as root through sudo.

both VM suites run on github's kvm runners on every push to main, and on a dedicated box with a LAN and vpns.

## license

MIT or Apache-2.0, your pick. see `LICENSE-MIT` and `LICENSE-APACHE`. security reports: `SECURITY.md`.
