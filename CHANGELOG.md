# changelog

## 0.3.1

- the run log: every run and shell is kept, with a network or without, and survives a reboot. a record has the command (escaped, cut at 300 characters), image, net, tag, exit, owner, when it ran and the run's whole `--json` result, the connection log included. on linux it's in `/var/lib/burner/logs`, root-only, on a mac in `~/Library/Application Support/burner/logs`
- `burner log --list` shows them newest first: id, when, host, image, net, tag, exit, the out and blocked counts and the start of the command. `--from HOST`, `--limit N` and `--json`. `burner log ID` opens with one line saying when, where, which image, the exit and the command, and `burner log ID --json` adds the record as `run` next to every 0.3.0 field
- each user keeps their newest 200 runs, none older than 30 days: `keep_runs` and `keep_days` under `[log]`. pruned when a run is kept and by the reaper
- `-H` runs and shells are kept here too, with the far end's name in the host column and the summary saying `kept here too, burner log ID`. on a mac they go in the same store, on linux in your own `~/.local/state/burner/logs`, written as you. what the far end sent is read leniently, size-capped and escaped
- through sudo, `burner log` shows the caller's runs only. on linux, `burner log` without sudo shows your `-H` copies and says how to see this machine's runs
- the summary says where a run went: `reached: github.com, objects.githubusercontent.com, +3 more`, every name the VM looked up for an address it connected to, in the order it did
- a run without `--net` whose command fails ends with `burner: this run had no network (--net web for http and https)`, and a `no_net` warning in the json
- `burner: burner-xxxx started` on stderr when it's a terminal, once the run has a slot, so you can `burner kill` it from another one
- `burner ls` has a header row, a blank tag when there's none and ages like `4m12s`. through sudo it shows only the caller's VMs, root through sudo included. on linux `ls` and `kill` without root say they need it, like `log`
- `burner kill --tag T` and `burner kill --mine` stop your VMs in one go. `--wait 30s` on run and shell says how long to queue for a slot (10m by default), `--no-wait` fails right away as before
- `--mem 512M` and `--disk 4G` on run and shell, plain numbers still mean MiB and GiB. `burner shell --img debian`
- `--json-mark NONCE` on run and shell writes the json as one `burner-NONCE status {...}` line, so nothing the guest prints can pass for it
- the log reader has a watchdog on linux: every 3s it reads the slot's counters, and a reader that stops passing messages on for 5s while some are owed stops the VM with 125, the same as a reader that died. so does one that overflowed with messages still owed
- an image built with another guest init warns on runs too, not just in doctor, and says how to fix it. a missing image says the full path to `tools/build-image` when get.sh put it there
- `sudo burner setup [alpine] [debian]` on linux: this release's images from github, checked against the `SHA256SUMS` get.sh verified at install and `install.sh` keeps in `/var/lib/burner` (from a crates.io or source install, against the release's own, and it says so). get.sh uses it and offers debian at the end. the release has an alpine image for x86_64 now too
- alpine has bash, about 1M, so `curl -fsSL URL | sudo burner run --net web --in stdin -- bash` works there too. debian gets a 4G scratch disk by default, apt needs the room
- `burner setup --remove` on a mac takes off the kernel and the images and says what's left (your config, the run log)
- `install.sh` stops when VMs are running unless `--force`, and `--uninstall` and `--purge` take burner off. get.sh keeps the release before as `/usr/local/share/burner/previous`, brings your alpine and debian images to the new release on an upgrade, and `curl -fsSL https://get.burnervm.dev | sh -s -- --uninstall` (or `--purge`) undoes it, on a mac too
- `sudo ./install.sh --allow alice` writes the sudo rule to `/etc/sudoers.d/burner` and checks it with visudo, and get.sh asks who. the rule now lets `doctor` and `doctor --json` through, and `explain` and `explain --json` but not `--rules`: through sudo `explain --rules` is refused for anyone but root
- `burner completions bash|zsh|fish|elvish|powershell` and a man page per command (`man burner-run`). install.sh and the homebrew formula put them in place
- burner-tui doesn't use sudo on a mac, where burner runs VMs as you
- `burner doctor` on a mac: the uplink and router, a warning when the mac is behind NAT and nothing public is blocked, and one line when a full-tunnel VPN is up (VMs can't reach anything while it is). on both: a FAIL when a `net.resolvers` entry is in a range VMs can't reach, a warning when it's behind a full tunnel, and whether each resolver answers from here
- on linux, `burner explain` and doctor say what a VPN means for VMs: a full tunnel's `0.0.0.0/1` routes block them, and one with a routing table of its own (wg-quick, a tailscale exit node) doesn't apply to them, so their traffic leaves outside it. the reaper reloads the filter within 30s when a VPN takes over the default route, so VMs follow it instead of losing their network
- `burner doctor` names the cpu when there's no `/dev/kvm` and fails inside a container
- the "run it there" hints for `-H` follow the far end's OS: `ssh mini burner setup debian` for a mac, with `sudo` for linux. `-H HOST doctor` with a sudo rule from before 0.3.1 says to run `install.sh --allow USER` there, and so does a `-H` run that hits a password prompt
- the readme: trying an install script in a VM, and a section on networks that aren't a home LAN (VPNs, pi-hole, NAT)
- the release builds with rust 1.98.1, pinned in `rust-toolchain.toml`, and ci checks debian's `keys.asc` against a pinned fingerprint list

things to know:

- the guest protocol didn't change, so 0.3.0 images keep working. 0.3.0's alpine has no bash: `burner setup` on a mac, or `sudo burner setup alpine` on linux, gets this release's
- the run log starts with 0.3.1. 0.3.0's connection logs in the state dir aren't carried over, and the reaper clears them
- the record keeps the command line, as `ps` and the sudo log already do. keep secrets off it
- scripts that compare a failed run's stderr exactly get one more line when they didn't pass `--net`. pass `--net none`, or read `--json-fd`
- through sudo `ls`, `kill` and `log` only see that user's VMs and runs. root itself, without sudo, sees everyone's
- the sudo rule changed. upgrades through get.sh keep it in step for the users in it; a rule written by hand stays as it was until `install.sh --allow`, and `burner -H HOST doctor` says when it's an old one
- `-H` copies follow this machine's `[log]` settings, since `--config` goes to the far end
- a full-tunnel VPN still blocks every VM while it's up, on a mac and on linux. that's on purpose: sending VM traffic through it would put it on the network behind the VPN
- give an image of your own a name of its own: `burner setup` and upgrades replace `alpine` and `debian`
- on a mac, run `burner setup` again after `brew upgrade burner`, the formula says so too

## 0.3.0

- `--json` on every command: one JSON document with the same envelope everywhere (`exit`, `ok`, the command's `result`, burner's own lines as `errors` and `warnings`), schema in docs/json.md. `burner run --json` puts only that on stdout and the command's output on stderr. `--json-fd N` on run and shell writes it to fd N and leaves stdout and stderr alone, through sudo `--json-fd 2`. `--status-fd` stays byte for byte what it was
- one table of exit codes for every command, in the README and in `--help` for run and shell. a run's json says how it went: the outcome, the VM's settings, time queued, booting and in the command, the output and the result tar
- `burner ls --json` moves under `result` and sizes and times get their units (`mem_mib`, `age_secs`, `started_unix`). burner-tui reads both shapes
- `burner version`, with `--json`: version, backend, json schema and guest protocol, no config needed
- a `--json-fd`, `--status-fd` or `--json` stdout that isn't open for writing is a usage error before anything starts, not a json lost at the end
- the connection log: every connection a VM tried, allowed or blocked and why, and the dns it asked, recorded on the host. on linux nft logs each new connection to a reader running as `burner-parse` with hard limits and a syscall allowlist, on a mac macnet writes down each decision. nothing the guest prints can add, change or hide a row
- a summary on stderr after every run and shell with a network, `--log full` for every row, `--log none` for nothing. `burner log [ID]` shows the last 32 runs, `--json` has all of it, and the run's json has it as `result.network`
- a run whose log reader dies is stopped with 125, so nothing goes unrecorded. on a mac a log macnet couldn't write is marked incomplete
- `burner explain [--net web|open] [--rules]`: what a VM could reach on this host, what it can't and why, and as root whether the loaded filter matches this config
- `burner doctor --probe` boots a VM per mode (alpine, the only image there is, or `--img`) that tries the gateway, the host, each lan and route, the tailnet, metadata, other VMs, dns to another server, a name that resolves to this host and ipv6. the host decides each row from its own log, on linux also from counters after the filter
- the network suite checks dns rebinding (a name that points at a blocked address is blocked like the address), ipv6 (no address or route in a VM, taps drop it), and the log (every blocked target is in it, it can't be forged, it survives hostile dns and floods)
- a filter loaded by an older burner is reloaded by the reaper, and a new run says to run `burner net up` instead of failing on it
- the sudoers example lets `burner log` and `burner explain` through
- remote hosts: `burner -H HOST run`, `shell`, `ls`, `log`, `kill`, `images`, `explain`, `config`, `doctor` and `version` over ssh, as you, with your own keys and ssh config. hosts go in `~/.config/burner/hosts.toml`, each with several addresses tried at once (a LAN one and a tailnet one), or `-H` takes any ssh host. `BURNER_HOST` for a whole shell, `-H local` for here
- what a remote host sends back is checked here: output escaped, a shell's terminal filtered and reset here, `~.` handled here, a result tar parsed again here, and the exit code from a line only burner there can write. remote failures are 125 with outcome `unreachable`, `remote_error` or `lost`, never ssh's 255
- `burner -H HOST doctor` checks the way there and shows that host's own doctor. `burner hosts [--check]` lists hosts.toml
- burner-tui takes `-H HOST` and switches hosts with `h`
- `tests/remote.sh`: burner -H over ssh to localhost, with a stand-in for the far end or the real burner
- a debian 13 image next to alpine, `--img debian` or `burner shell debian`, with python3, curl, sudo and gpg (no git). on linux `tools/build-image debian` builds it with mmdebstrap from a pinned snapshot.debian.org timestamp, and the build fails unless every package matches the lock file for that arch. on a mac `burner setup debian` fetches it, checked against the release and the homebrew formula's pin. the release carries it for x86_64 and aarch64, with its package list
- `burner setup` takes image names, `burner setup alpine debian`. no names is alpine, as before
- `--img debian` (or alpine) on a box that doesn't have it says how to get it: `tools/build-image debian` on linux, `burner setup debian` on a mac
- commands in a run use the image's `/bin/sh`: busybox ash on alpine, dash on debian
- a run ends about a tenth of a second sooner: guest init no longer starts a `cat` for every process when it looks for leftovers after the job
- guest init mounts `/dev/shm`, falls back to `xterm-256color` when the image has no terminfo entry for your terminal (kitty, ghostty), and checks at build time that an image has every tool it needs
- `tools/build-image` writes each image's package list next to it, and cleans up without crossing into anything still mounted
- the test suites run against any image with `BURNER_TEST_IMG`, and github runs them on alpine and debian
- on a mac, a run or shell keeps the mac out of idle sleep while its VM is up, like `caffeinate -i`, and lets go when it ends. a sleeping mac froze its VMs
- `burner doctor` on a mac says when nobody is logged in at it (VMs still run over ssh), and warns when it idle-sleeps, when FileVault is on before macOS 26 (after a reboot nothing comes back until someone types the password at the mac) and when burner or libkrun has a quarantine xattr
- `burner -H HOST doctor` checks the sudo rule's lines for `log` and `explain` too, a warning when they're missing
- `--ttl` in `burner run --help` says the command stops a little before the limit, so its output and `/out` still come back
- images need a rebuild for the new guest init: `tools/build-image alpine` on linux, `burner setup` on a mac

things to know:

- `outcome`, `rc` and `guest_*` in a run's json are the guest's word: the job is root in the VM and can write what guest init reports. a `timeout` it claims only counts once the host's clock got to the limit
- on a mac the connection log and `doctor --probe` are macnet's own account, and a log marked incomplete there doesn't stop the VM
- `burner -H HOST log` and `explain` need the `log` and `explain` lines from `dist/sudoers.example` in the sudo rule there. with them, those users can see the host's network layout through `explain`
- stop running VMs before upgrading: the new filter starts the log's counters over, so a run that spans the upgrade gets an incomplete log
- the debian image stays at its snapshot until the next burner release. `apt-get update && apt-get upgrade` in the VM when you need today's packages
- connection logs (the addresses and dns names of the last 32 runs) are kept in the state dir of the host that ran the VM, root-only on linux. over `-H` they stay on that host

## 0.2.1

- `burner setup` on a mac takes the kernel and image homebrew fetched again. it refused them because homebrew's Cellar is writable by the admin group, whose members can become root anyway. a directory only you, root or the admin group can write counts as safe now, world write and other groups still don't
- on a mac, the check that the kernel, image and config are safe to use follows symlinks to the real file and checks every directory above that, not the ones above the link
- homebrew installs a mac build of burner from the release instead of building it, so `brew install` no longer pulls in rust, llvm and z3. `burner-tui` comes with it
- `poweroff -f`, `halt -f` or `reboot -f` in a run ends it right away, with the output and `/out` up to then, exit 125 and outcome `poweroff` or `reboot`. it used to sit there until the time limit
- an `--in tar` that doesn't unpack in the VM ends with 125 and outcome `input_error`, not as a command that exited 125
- a config that doesn't load ends a run with 125 and a `--status-fd` line, where it was 1 and no line
- giving up after 10 min waiting for a slot is outcome `busy`, the same as `--no-wait`
- `burner net` on a mac exits 2, there's nothing for it to set up there
- the test suites got stricter: the memory bomb has to grow under any awk, and a network probe whose tool is missing fails instead of counting as blocked
- the release tarballs no longer carry the lima wrapper from 0.1.x
- images need a rebuild for the new guest init: `tools/build-image alpine` on linux, `burner setup` on a mac

## 0.2.0

- native on apple silicon: any M1 or newer with macOS 15 or later. no linux VM in between, burner boots each VM itself with libkrun on hypervisor.framework and runs as you, no sudo
- on a mac each VM's network is its own `burner macnet` process: a user-space tcp/ip stack under a seatbelt sandbox, with the same blocks as linux for the LAN, the host, other VMs and anything off the default route. no ping and no udp but dns yet
- `burner setup` on a mac installs the guest kernel and alpine image homebrew fetched, the kernel checked against the sha256 built into burner. `--version TAG` or `--from DIR` to get them elsewhere
- homebrew: `brew install burnervm/tap/burner` builds and signs burner and pulls in libkrun and e2fsprogs. the lima setup from 0.1.x is gone, `limactl delete burnervm` cleans it up
- `get.sh` installs the native version on a mac
- `burner shell` was reviewed from the outside and 32 problems fixed: guest output can't clear your scrollback, change tab stops or leave modes on, and the terminal reset gets through even when your terminal stalls. resizes reach the guest, `exit 3` comes back as 3, a crash or panic is 125, `poweroff`, `halt` and `reboot` end the session, `~.` works when the VM stops reading, a pasted `~.` stays text, and keys typed during boot wait for the shell
- `burner kill` makes the run exit 130 every time, not 125 when the VM died between two checks
- `burner-tui` reads the terminal itself: no held keys after a resize or after the shell, and a killed burner doesn't leave the terminal raw
- release assets: the aarch64 guest kernel, a gzipped alpine image and its package list with versions, all in SHA256SUMS and the build provenance
- images need a rebuild for the new guest init: `tools/build-image alpine` on linux, `burner setup` on a mac

## 0.1.1

- a run ends when its command ends, even with something left running in the background
- a failed filter refresh cuts open connections too, and stops VMs if nft itself fails
- taps don't answer arp for the host's other addresses
- the reaper frees slots held by a stopped wrapper
- job input and VM config are private to root and the VM's uid
- helpers run as root use a fixed PATH
- CRLF and split UTF-8 on a terminal
- help text for run
- leaving a shell shows no guest kernel reboot line, and the prompt comes back below the session
- release tarballs come with build provenance
- `get.sh`: a one-line installer and upgrader
- aarch64 tested: both suites pass on ubuntu 24.04 arm, and the README says how to run burner on a mac through lima
- the crates are burnervm and burnervm-tui on crates.io, published with every release
- ping limits per VM instead of one bucket for all of them
- an image's defaults.toml with a typo is an error, not a quiet fallback
- a fresh install writes a config with only what you change, so new defaults reach it

## 0.1.0

first release.

- `burner shell` gives you a root shell in a fresh VM, `burner run` runs one command and hands back its output and exit code
- `--in tar` or `--in stdin` to pass work in, `--result tar` to get what the command put in `/out` back out
- `--net none|web|open`: no network, http/https plus dns and ping, or any port but mail. the LAN, the host and other VMs are always blocked
- `net.block_public_ip` looks up the host's public address (behind NAT, the router's) and blocks it too
- each VM is a firecracker microVM under the jailer with its own uid, in its own cgroup, on a read-only image with a throwaway scratch disk. result tars are read by a separate user with hard limits, never mounted. a reaper timer cleans up after runs that hang or die
- `burner-tui`: pick an image and settings, start a shell or run, watch and kill running VMs
- `tools/build-image` builds images from the alpine minirootfs and a package list, no docker needed
- `burner doctor` checks kvm, the tools, the network setup and the install, and says what to fix
- `install.sh` fetches a pinned and checksummed firecracker, jailer and guest kernel, creates the user and systemd units. `--uninstall` takes it back off
- static binaries for x86_64 and aarch64 on every release (aarch64 is untested so far)
