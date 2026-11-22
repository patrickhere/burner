<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/svg/lockup-on-dark.svg">
    <img alt="burner" src="brand/svg/lockup-on-light.svg" width="300">
  </picture>
</p>

[![ci](https://github.com/patrickhere/burner/actions/workflows/ci.yml/badge.svg)](https://github.com/patrickhere/burner/actions/workflows/ci.yml) [![vm suites](https://github.com/patrickhere/burner/actions/workflows/vm-suites.yml/badge.svg)](https://github.com/patrickhere/burner/actions/workflows/vm-suites.yml) [![crates.io](https://img.shields.io/crates/v/burnervm)](https://crates.io/crates/burnervm) [![site](https://img.shields.io/badge/site-burnervm.dev-fa794a)](https://burnervm.dev) [![x](https://img.shields.io/badge/x-%40burnervm-black?logo=x)](https://x.com/burnervm) [![bluesky](https://img.shields.io/badge/bluesky-%40burnervm.dev-0285FF?logo=bluesky&logoColor=white)](https://bsky.app/profile/burnervm.dev)

throwaway linux VMs on your own hardware. you ask for a VM, get a root shell or run a command in it, and it's deleted when you're done. each one is a firecracker microVM with its own kernel, and it can reach the internet but not your LAN.

it started as a sandbox on my homelab for running code i don't trust (install scripts, other people's repos, things agents want to run) away from the box that has my keys on it. this is the rebuild in rust so other people can install it. the homelab version stays private, so the history here starts with the rebuild.

status: early, with one maintainer. it's tested on ubuntu 24.04 and 26.04 and debian 13 on x86_64, and on arm in a linux VM on a mac. it hasn't had an outside security review yet, so read [what it protects against](#what-it-protects-against) before trusting it with anything that matters.

```
sudo burner shell                          # root shell in a fresh VM, gone when you exit
sudo burner run -- 'uname -a; exit 3'      # run one thing, get its output and exit code back
```

![burner running commands in fresh VMs: a kernel and alpine version, an exit code coming back, https working, and the LAN blocked](docs/media/demo.gif)

## install

```
curl -fsSL https://get.burnervm.dev | sh
```

![the installer on a fresh aarch64 machine: packages, a checksummed download, firecracker and the units, the alpine image, then a first VM](docs/media/install.gif)

that's linux with kvm (x86_64 or arm), or any apple silicon mac (M1 and newer, macOS 15 or later), where it installs burner through homebrew and runs VMs natively. run it again later to upgrade. [install details](#install-details) has what it does step by step, the manual way, macs, building from source and making more images.

## what it does

- `burner shell [image]` -> a login shell on the VM's console, your terminal size passed in. 60 min by default. exits with the shell's exit code, 125 if the VM crashed under it. `~.` after enter leaves and stops the VM, like ssh. in a bracketed paste it's pasted text, until the paste ends or a second goes by with nothing more of it. `sudo burner kill ID` from another terminal always ends a session, mid-paste too
- `burner run -- cmd` -> boots a VM (~2-3s), runs `cmd` in `sh`, streams the first 64K of output live and prints the rest when it ends (the serial console is slow), returns its exit code, deletes the VM
- `--in tar` unpacks a tar from stdin into `/work`, `--in stdin` feeds stdin to the command, `--result tar` hands back whatever the command put in `/out`
- `--net none|web|open` -> no network, http/https plus dns and ping only, or any port but mail. the LAN, the host and other VMs are always blocked
- after a run with a network, a few lines on stderr say what it tried: connections out, what was blocked and why, dns lookups. `burner log` has every connection of the last 32 runs, see [what a VM tried](#what-a-vm-tried)
- `burner explain` says what a VM could reach on this host and why the rest is blocked, `burner doctor --probe` boots a VM that tries it for real
- `burner ls`, `burner kill ID`, `burner images`, `burner doctor`, `burner log`, `burner explain`, `burner version`. `--json` on any of them gives one JSON document instead ([docs/json.md](docs/json.md))

```
git archive HEAD | sudo burner run --net web --in tar -- 'apk add -q nodejs npm && npm ci && npm test'
tar -c file.zip | sudo burner run --in tar --result tar -- 'unzip -q file.zip -d /out' > res.tar
```

exit codes and the rest of what a wrapper needs are under [from scripts and agents](#from-scripts-and-agents).

the image is plain alpine with git and curl, so the first example installs node itself. there's a debian 13 image too, `--img debian` or `burner shell debian`, for install scripts and `apt install` steps that expect debian. it has python3, curl, sudo and gpg but no git (`apt-get install -y git` with `--net web`). build your own with a package list in `images/NAME/packages` and `tools/build-image NAME`, see [install details](#install-details).

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
sudo burner run --net web --in tar --result tar -- cmd
  │
  │  jailer: its own uid, its own cgroup (cpu, memory, pids)
  v
┌────────────────────────────┐    tap, its own /30
│ firecracker microVM        │───────────────────> nft ──nat──> internet
│   its own kernel           │                      │
│   read-only image          │                      └──x──> the host, your LAN,
│   throwaway scratch disk   │                              other VMs, VPNs
└──────┬──────────────┬──────┘
       ^              │
       │ job tar      │ result tar
       │ (raw disk)   v (raw disk, never mounted on the host)
     stdin       burner-parse ──> /out, rc and log as a tar on stdout
                 (its own user, hard limits, only files and dirs)
```

- every VM runs under firecracker's jailer as its own uid and gid, in its own cgroup with cpu, memory and pid caps. the ids come from `jail.uid_base` in the config (1900000000 up, no account behind them), so a guest that breaks out into firecracker can't open another VM's disks or signal its process. a uid stays taken until its VM is cleaned up, and `burner doctor` fails if an account, a group or a `/etc/subuid` range already uses one
- the image is mounted read-only with an overlay on a throwaway scratch disk. the command goes in as a raw tar on its own disk
- results come back as a raw tar the guest writes to another disk. the host never mounts anything the guest wrote: the tar is read by a separate burner process running as its own user, `burner-parse`, with hard rlimits, and only regular files and directories get through
- each VM gets a tap and its own /30. one nft table only lets those taps out the uplink, minus private ranges and the host's own addresses. bandwidth and disk io are capped per VM
- the same table logs every new connection a VM tries, before and after the filter decides, to an nflog group of the VM's own. a reader running as `burner-parse` turns that into the run's connection log. the log rules only log and count, they never decide what happens to a packet
- the time limit is enforced by burner and backed up by a reaper timer, and a VM's slot is only freed once its cgroup is empty

nothing from the host goes into a VM unless you pipe it in. `--net web` means anything that goes in can leave, so don't pipe in secrets.

where to start reading the code:

- `burner/src/run/mod.rs`, the lock order comment at the top. read it before touching anything that takes a lock
- `burner/src/run/launch.rs`, one run from waiting for a slot to teardown
- `burner/src/net.rs`, `ruleset()` is the whole nft table: what a tap can and can't reach
- `burner/src/result.rs`, the parser for the result tar, run as `burner-parse`
- `burner/src/netlog.rs` and `nflog.rs`, the connection log: what its producers write, how it's folded, the reader. `netmodel.rs` is the policy as a function, for explain, the log's reasons and the probe
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

one thing the shell filter takes on trust: that your terminal decodes utf-8. burner can't ask the terminal, so it goes by the locale (`LC_ALL`, `LC_CTYPE`, `LANG`) and takes utf-8 when none is set. on a terminal that decodes latin-1 or another 8-bit charset and acts on C1 controls (xterm without utf-8, luit, screen with `c1 on`), part of a utf-8 char can be a control like CSI. if that's yours, pass the locale through sudo, `sudo env LC_ALL=en_US.ISO-8859-1 burner shell`, and non-ascii from the guest shows as `?`.

on a mac (see [install details](#install-details)) it's weaker than on linux, and here's how:

- each VM is libkrun on apple's hypervisor.framework. those two and the macOS kernel are the security boundary, where on linux it's firecracker, the jailer and kvm
- the VMM runs as you. there's no uid per VM, no jailer and no chroot, so a guest that breaks out of libkrun can do anything you can, including reading other VMs' disks. the guest gets the cpus and memory you asked for, but nothing caps the VMM's own overhead the way a cgroup does on linux, and disk io isn't capped
- there's no packet filter, and `burner net` has nothing to set up (it exits 2). each VM's network is its own `burner macnet` process, a tcp/ip stack in user space (smoltcp) that only opens the connections the policy allows: the same blocks for the LAN, the host, other VMs and anything off the default route, no mail ports in open mode, `net.block_public_ip` and `net.rate`. it runs under a seatbelt sandbox that allows outbound sockets and route lookups and nothing else, so a bug in it can't read your files or start anything. it can still connect anywhere the mac can, though: the policy runs in that same process, so a guest that took macnet over could reach loopback services, your LAN and VPN routes, the things the policy is there to keep out
- no ping and no udp but dns yet, in any mode
- the connection log is macnet's own record of what it decided, written to a pipe burner run reads. it has the bytes each connection carried (linux leaves those null), and shows ping and other udp as blocked. a log macnet couldn't write in time is marked incomplete, and the VM keeps its network
- `doctor --probe` has no witness counters on a mac: what the host saw is macnet's log, plus a canary listening on the mac's loopback. the probe VM sends 127.0.0.1 out its network, and a connection that ever reached the canary would be a leak
- the result tar is still parsed in a separate process with rlimits, but as you, under a seatbelt profile that allows it nothing past the files it's handed, and without a memory cap (macOS won't set one)
- there's no reaper timer. the VMM stops itself when burner exits or its time is up, and the next `burner run` or `burner ls` cleans up what's left

## what a VM tried

every run and shell with a network ends with a summary on stderr, after the command's output and before the `--json-fd` line:

```
burner: net web: 6 connections out, 2 blocked (5 attempts), 4 dns lookups (burner log burner-3fa1c2b7d10e for all of it)
burner:   blocked  tcp 192.168.1.1:22          your lan (192.168.1.0/24 on eth0)   x3
burner:   blocked  tcp 169.254.169.254:80      cloud metadata and link-local (169.254.0.0/16)   x2
```

it's recorded on the host, not asked of the guest: on linux the nft table logs every new connection a VM tries, before and after the filter decides, and a reader running as `burner-parse` (hard limits, a seccomp list, no files) turns that into rows. on a mac macnet writes down each decision it makes. either way nothing the guest prints can add, change or hide a row.

- `--log summary` is the default, `--log full` prints every row, `--log none` nothing. stdout is never touched, so `--result tar` still works. scripts that read a run's stderr whole want `--log none`, or `--json-fd`, where the log is `result.network`
- `sudo burner log` prints your last run's log, `sudo burner log ID` a given one, `--json` all of it. the last 32 runs are kept, 1 MiB each, in the state dir, so on linux they're gone after a reboot. through sudo you only see your own runs
- a row is a destination and what happened to it: allowed and answered, refused or no answer, or blocked and why (this host, a lan or a route, a special range, net.block, your public address, another VM, a port or protocol the mode doesn't open, mail, a dns server that isn't one of net.resolvers, a rate limit). dns rows have the name and type asked and the answers
- allowed connections are always listed. blocked attempts past 100 a second are counted, not listed, and the summary says how many. a log that may be missing something (the kernel dropped messages, counters that couldn't be read) says `incomplete`. an attempt is only called blocked when the slot's counters show the log got every message the filter sent: when one went missing, an attempt with nothing after it is `unknown`, not blocked
- if the reader dies while the VM runs (a parser bug the guest found), the VM is stopped and the run exits 125, so nothing goes unrecorded
- the log can't see inside connections: a VM that tunnels everything through one https connection, a vpn or dns over https shows up as that one connection. names come from the dns the guest asked, and a server the guest controls can point any name at any address, so the address and the verdict are the facts, the names are what it resolved
- dns rebinding gets nowhere: the filter goes by address when the VM connects, so a name that resolves to your gateway, the host or cloud metadata is blocked like the address. there's no ipv6 in a VM, and taps drop ipv6 before anything else sees it

`sudo burner explain` says what a VM with `--net web` (or `--net open`) could reach on this host, and what it can't and why: this host's addresses, the lan, other routes, the tailnet, cloud metadata, other VMs, net.block and your public address. as root it checks the loaded filter against this config and exits 1 if it's missing or stale. `--rules` adds the firewall rules, on a mac macnet's checks in the order it makes them.

`sudo burner doctor --probe` boots a VM per mode (web, and open when the config allows it) that tries all of that for real: the gateway, the host, each lan and route, the tailnet, metadata, another VM's address, dns to a server that isn't a resolver, a name that resolves to this host, ipv6, and burnervm.dev on 443 (allowed), 22 and 25. the host decides each row from its own log, and on linux also from counters placed after burner's filter that count anything that got past it. exit 0 is all as expected, 1 is something wasn't, 125 the VM couldn't run. `--target IP:PORT` adds your own, `--internet HOST` tries another host. the only packets that leave the machine are the dns lookup and the connections to that host.

## install details

burner needs linux on x86_64 or aarch64 with kvm and cgroup v2. the one-liner from [install](#install) downloads the latest release, checks it against `SHA256SUMS`, installs the packages it needs (apt, dnf or pacman), runs `install.sh` and builds the alpine image.

piping a script to `sh` means trusting it, so read it first if you'd rather: `curl -fsSL https://get.burnervm.dev | less`, or it's `get.sh` in this repo. to do the same by hand, grab the tarball for your cpu (x86_64 or aarch64) and `SHA256SUMS` from the [latest release](https://github.com/patrickhere/burner/releases/latest), then:

```
sudo apt install nftables conntrack e2fsprogs iproute2 curl   # debian/ubuntu
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf burner-v*-$(uname -m)-linux.tar.gz
cd burner-v*-$(uname -m)-linux
sudo ./install.sh                # firecracker, jailer, guest kernel (pinned + checksummed), a user, units
tools/build-image alpine         # an image to boot, uses sudo, no docker
tools/build-image debian         # if you want debian too, needs mmdebstrap
sudo burner doctor
```

releases after 0.1.0 come with build provenance, so you can also check a tarball was built by this repo's release workflow: `gh attestation verify burner-v*-x86_64-linux.tar.gz -R patrickhere/burner`. the same goes for the mac build homebrew installs, `burner-v*-aarch64-macos.tar.gz`, from 0.2.1 on.

on a mac, burner runs VMs itself with [libkrun](https://github.com/containers/libkrun) on hypervisor.framework, no linux VM in between. that works on any apple silicon mac, M1 and newer, with macOS 15 or later. intel macs aren't supported. the same `curl ... | sh` line does it for you when it sees a mac, or by hand with homebrew, which installs burner as the release workflow built it, signs it for hypervisor.framework and pulls in libkrun and e2fsprogs. no rust needed:

```
brew install burnervm/tap/burner
burner setup                     # the guest kernel and alpine image homebrew fetched with it
burner setup debian              # if you want debian too, fetched from the release
burner doctor
burner run -- 'uname -m'         # no sudo, VMs run as you
```

0.1.x on a mac ran burner inside a lima VM. upgrading to the native formula leaves that VM behind: `limactl delete burnervm` removes it, and `brew uninstall lima` if nothing else uses lima. on windows 11, WSL2 with nested virtualization should work like a linux box (`/dev/kvm` has to exist inside it), but it hasn't been tried yet.

the formula pins the kernel and the image by sha256 in the tap, which isn't the place the files come from, so `burner setup` installs what brew already checked. `burner setup --version v0.2.0` fetches them from a github release instead: the kernel still has to match the sha256 built into burner (the one `install.sh` pins), but the image is only checked against that release's own `SHA256SUMS`. `--from DIR` takes both from anywhere you point it at and skips the kernel pin. the formula doesn't download the debian image, so a plain `brew install` stays small, but it pins it all the same: `burner setup debian` fetches it from burner's own release and checks it against the release's `SHA256SUMS` and the formula's sha256.

the config, kernel and images live in `~/Library/Application Support/burner`, run state in your per-user temp dir. `--net` works as on linux minus ping and non-dns udp, and the [threat model](#what-it-protects-against) is weaker, see the end of that section. `burner-tui` doesn't know about the mac yet.

or from source, with rust 1.88 or newer: `cargo build --release` in a checkout, then the same `sudo ./install.sh` and on. the crates are on crates.io as `burnervm` and `burnervm-tui` (the commands are still `burner` and `burner-tui`), but `cargo install` alone isn't enough: burner also needs the firecracker, jailer, guest kernel and units that `install.sh` sets up.

an image is `images/NAME/packages`, one alpine package per line. `tools/build-image NAME` takes the alpine minirootfs (pinned + checksummed), installs those packages into it with apk in a chroot and writes `/var/lib/burner/images/NAME/rootfs.ext4`. it builds for the host's arch only. an `images/NAME/Dockerfile` with no packages file next to it still gets built the old way, through docker.

an image with an `images/NAME/base` file is debian instead, like `images/debian`. `base` names the suite and a snapshot.debian.org timestamp (`debian trixie 20261121T000000Z`), and `tools/build-image NAME` builds it with mmdebstrap from that snapshot: debian's Essential set and apt, plus one debian package per line from `packages`. it needs mmdebstrap on the host, `sudo apt install mmdebstrap` on debian and ubuntu or `sudo dnf install mmdebstrap` on fedora. apt checks the snapshot against the keys in `keys.asc` only, and the build fails unless every package and version matches `lock-x86_64` or `lock-aarch64`, so a debian image built anywhere from the same base has the same packages in it. the snapshot moves once per burner release: after bumping `base`, `BURNER_RELOCK=1 tools/build-image NAME` writes the lock for that arch. in a VM, apt uses debian's own mirrors and gets today's packages.

a few things work differently on debian. commands run under the image's `/bin/sh`, which is dash there and busybox ash on alpine, so use `bash -c '...'` when you need bash. an `--in tar` with `../` in a name fails with 125 and `input_error`, since GNU tar refuses it where busybox drops the `../`. what apt installs goes on the scratch disk, so give big installs `--disk 4` or more.

if ufw is on, `burner doctor` prints the one route rule it needs. settings live in `/etc/burner/config.toml`, which starts out empty: put only what you change there. `burner config` shows every setting with the defaults filled in.

## letting other users run VMs

anyone who can run `sudo burner` with any arguments can also take the VM network down or reap. to let someone run VMs and nothing else, use `dist/sudoers.example`: it allows `run`, `shell`, `ls`, `kill` and `images`. through sudo, `--config` only takes files in `/etc/burner`, `burner kill` only stops VMs that caller started, and `[limits]` in the config apply to everyone.

## remote hosts

`burner -H HOST` runs any of `run`, `shell`, `ls`, `log`, `kill`, `images`, `explain`, `config`, `doctor` and `version` on another machine over ssh, with your own keys, agent and `~/.ssh/config`. nothing listens anywhere and nothing new runs as root: the laptop only starts `ssh`, as you, and burner on the far end runs as it would there by hand.

```
burner -H mini shell
burner -H vps run --net web -- 'curl -sI https://example.com'
git archive HEAD | burner -H gaming run --in tar -- 'npm ci && npm test'
```

hosts go in `~/.config/burner/hosts.toml` (`$XDG_CONFIG_HOME/burner/hosts.toml`, on a mac too):

```toml
[hosts.mini]
addrs = ["10.1.0.81", "mini.tail1234.ts.net"]   # tried in this order

[hosts.gaming]
addrs = ["10.1.10.139", "gaming.tail1234.ts.net"]
user = "patrick"              # else your ssh config, else your login name
port = 22                     # else your ssh config
connect_timeout = "2s"        # per address, 1s to 30s, default 3s
burner = "/usr/local/bin/burner"   # where it is there, if not the usual place
```

- an address is an ip, a dns name or a `Host` from your ssh config, so `ProxyJump` and the rest apply. a host's addresses are all tried at once, and the first one in the list that answers wins: once any has, the ones before it get 300ms more. at home the LAN address wins, away the tailnet one does, and nothing is remembered between runs. one behind a ProxyJump can't be tried that way, it's used when everything before it failed
- a `-H` name that isn't in hosts.toml is used as an ssh destination (`user@` too), so `burner -H vps ls` works with only `Host vps` in your ssh config. `BURNER_HOST=mini` does the same as `-H mini` for every command in that shell, and `-H local` means this machine whatever it says
- there's no place for a password or a key in the file, auth is ssh's. burner won't use the file if anyone but you (or root) could have written it or a directory above it
- every connection goes out with agent, X11 and port forwarding off, ssh's own `~` escape off, and host keys checked strictly: a host ssh doesn't know yet, or one whose key changed, is refused and never added to known_hosts. a changed key on the first address stops there, it doesn't quietly move on to the next one. `ssh HOST` once to check and add a new host's key
- on linux the far end runs burner through `sudo -n`, so the user you ssh in as needs the rule in `dist/sudoers.example`. a password prompt never comes up, `burner -H HOST doctor` says what the rule allows. ssh'd in as root it runs without sudo, and on a mac it runs as you. a mac host only needs Remote Login on, and works with nobody logged in at its screen
- `burner -H HOST doctor` checks the way there (each address, ssh, burner's version on both ends, the sudo rule) and then shows that host's own doctor. `burner hosts` lists the file, `--check` tries every address
- a run's connection log stays on the host it ran on: the summary comes back on stderr like the rest, `--log` and `--json-fd` work as they do here, and `burner -H HOST log ID` shows the whole log. `log` and `explain` need the sudo rule's lines for them there
- `burner -H` refuses to run as root or through sudo: root has other keys and another known_hosts. `net`, `reap`, `setup` and `doctor --probe` don't go over -H, they're for the machine itself

a result over `-H` is only as trustworthy as the host it ran on. that host runs the VM and the burner that reports on it, so a compromised one can make up the output, the exit code, the json and the result tar, and burner here has no way to check them against what really happened. what burner does guarantee is that a hostile host can't reach past its own results into your machine:

- the far end's output is escaped on your terminal like a local run's, and a shell's goes through the same terminal filter: no title, clipboard or query escapes reach your terminal, and it's reset at the end from what was really written to it
- `~.` in a shell is read here and ends the session without asking the far end, and ctrl-c in a run stops ssh here. either way burner there sees ssh go and stops the VM
- a `--result tar` is parsed again here by the same limited parser a guest's tar gets, so only regular files and directories with clean names reach your `tar -x`
- the exit code comes from a line marked with a nonce that only burner there knows, so the VM can't forge it (the host can). the line has to be schema 1 json whose exit code goes with its outcome, or the run is 125 `remote_error`. a host that doesn't answer, a burner there that doesn't start, and a connection that goes in the middle all end in 125, outcome `unreachable`, `remote_error` or `lost` in `--json-fd`. ssh's own 255 never comes out as burner's: a command that really exits 255 does
- your flags and host keys: what goes over is rebuilt from parsed arguments so nothing becomes a flag there, forwarding is always off, and a host key is never accepted or written
- a different burner version on the far end is fine as long as it takes the arguments, `doctor` warns. one that doesn't is refused with a message saying which one to update

things to know:

- the command line shows up in the far end's process list and in its sudo log, like it would if you typed it there. secrets go in through `--in`, never on the command line
- a laptop that sleeps in the middle of a shell gets `lost` after about a minute (burner sets `ServerAliveInterval` when your ssh config doesn't). the far end only notices when its TCP does, which can take hours, and until then the VM runs to its time limit. `ClientAliveInterval 30` in the host's `sshd_config` makes that a minute too
- every `burner -H` call is a new ssh connection. burner-tui refreshes a remote list every 5s; to make that close to free, share connections in `~/.ssh/config`:

  ```
  Host mini vps gaming
      ControlMaster auto
      ControlPath ~/.ssh/cm-%C
      ControlPersist 60s
  ```

- `BURNER_SSH` runs another ssh program, and `BURNER_BATCH=1` adds `BatchMode=yes` so ssh never asks for anything (burner-tui sets it for its background calls)

## from scripts and agents

- exit codes, the same for every command:

  | code | meaning |
  |---|---|
  | 0 | success. for run and shell: the command exited 0, the shell was left with `~.`, or the shell's VM was powered off |
  | 1 | the command didn't do its job: doctor found a FAIL or doctor --probe something not as expected, explain found the filter missing or stale, log has no such run, kill was refused or the VM is still stopping, net up failed, the config didn't load. never from run or shell |
  | 2 | usage: bad flags or arguments, needs root (or must not be root), no terminal for shell, not on this OS. nothing was started |
  | 124 | run and shell: the time limit stopped it |
  | 125 | run and shell: no result. the sandbox or the VM failed, no free slot, the config or an image's defaults didn't load, the input didn't unpack, the command powered off or rebooted the VM, the result tar wasn't delivered, the network log's reader stopped. doctor --probe: its VM couldn't run. any command over `-H`: the host didn't answer, burner there didn't start, or the connection went |
  | 130 | a signal (ctrl-c, SIGTERM, SIGHUP) stopped burner, or burner kill stopped the VM |
  | other | run and shell: the command's own exit code |

  a command can exit 2, 124, 125 or 130 itself, so for run use `--json-fd` to tell them apart
- `--json` on any command prints one JSON document instead of text, schema in [docs/json.md](docs/json.md): `exit`, `ok`, the command's `result`, and burner's own lines as `errors` and `warnings`. `burner run --json` puts only that on stdout and the command's output on stderr. `--json-fd N` on run and shell writes it to fd N and leaves stdout and stderr alone, so a command that exits 124 itself isn't mistaken for a timeout: `result.outcome` says which. sudo closes fds above 2, so through sudo use `--json-fd 2` and read the last line of stderr
- `--status-fd N` is the older one-line form, kept as it was. it has `outcome`, `rc` (the command's exit code, only when outcome is `exited`), `exit` (what burner exits with), `id` and `secs`. outcome is one of `exited`, `timeout`, `killed`, `interrupted`, `busy`, `sandbox_error`, `input_error` (an `--in tar` that didn't unpack in the VM, so the command never ran), `poweroff` (the command powered off or halted the VM before it exited), `reboot` (the same with a reboot) or `usage`. an image built with an older guest init still reports an input that didn't unpack as `exited` with rc 125, and gets no `poweroff` or `reboot`
- when every slot is taken (`max_vms`, or the memory total), a run waits for one, says `burner: waiting for a slot` on stderr, and gives up after 10 min. `--no-wait` fails right away instead. both end with 125 and outcome `busy`
- `sudo burner ls --json` prints the envelope with `result` holding `vms`, `max_vms`, `total_mem_mib` and `used_mem_mib`. each VM has `id`, `tag` (null without one), `img`, `vcpus`, `mem_mib`, `disk_gib`, `net`, `status` (`preparing`, `running` or `cleanup-failed`), `owner`, `started_unix`, `age_secs`, `ttl_secs` and `ttl_left_secs`. before 0.3 that object was the whole output, with `mem`, `disk`, `age`, `ttl` and `ttl_left` and the totals without `_mib`; burner-tui reads both. `--tag` on a run makes yours easy to find
- anything the command leaves running in the background (a server started with `&`, a daemon, even one that called setsid) is killed when the command exits, and the run ends there. if the tests need a server, start it and stop it inside the same command

a wrapper that tells a failing test from a timeout or a busy box:

```sh
#!/bin/sh
log=$(mktemp)
git archive HEAD | sudo burner run --net web --in tar --tag tests --json-fd 2 -- 'sh ./test.sh' 2>"$log"
code=$?
outcome=$(tail -n 1 "$log" | jq -r .result.outcome)
case $outcome in
    exited) echo "tests exited $code" ;;
    timeout) echo "tests hit the time limit" ;;
    *) echo "no result ($outcome), see $log" >&2 ;;
esac
exit "$code"
```

## tui

`burner-tui` is a small terminal UI on top of the same commands. pick an image, network, cpus, memory and time limit, see the exact `sudo burner ...` line it'll run, and enter starts the shell or run in your terminal and comes back when it ends. tab shows the running VMs, refreshed every 2s, and `k` kills one after asking.

`burner-tui -H mini` (or `BURNER_HOST`) drives a remote host the same way, with `burner -H` and never through sudo. `h` goes to the next host: local, then the ones in hosts.toml.

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

`tests/isolation.sh` (memory and fork bombs, disk and console floods, a hostile result tar, time limits, slots, argument fuzzing) and `tests/network.sh` (what a VM can and can't reach, with targets found on the host it runs on, by address and by a name pointing at them, ipv6, and the connection log: that it has every blocked target, can't be forged, survives hostile dns and floods, and stops the VM when its reader dies). both boot the alpine image, or the one in `BURNER_TEST_IMG` (`sudo env BURNER_TEST_IMG=debian bash tests/isolation.sh`), need a box with burner installed and that image built, and run as root through sudo.

`tests/remote.sh` tests `burner -H` over ssh to a private sshd on localhost, all of it in a temp dir. `--fake-only` puts a stand-in burner on the far end (hostile records, escapes, tars, a shell that hangs) and runs anywhere, a mac included; without it the real burner runs there too, booting alpine. run it as yourself, not root.

both VM suites run on github's kvm runners on every push to main, once on alpine and once on debian, and on a dedicated box with a LAN and vpns.

## license

MIT or Apache-2.0, your pick. see `LICENSE-MIT` and `LICENSE-APACHE`. security reports: `SECURITY.md`.

the logo and the rest of `brand/` are cc-by-4.0, and the name and the `>]` mark come with a short trademark note. both are in `brand/README.md`.
