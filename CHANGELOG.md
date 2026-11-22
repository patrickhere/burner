# changelog

## unreleased

- remote hosts: `burner -H HOST run`, `shell`, `ls`, `kill`, `images`, `config`, `doctor` and `version` over ssh, as you, with your own keys and ssh config. hosts go in `~/.config/burner/hosts.toml`, each with several addresses tried at once (a LAN one and a tailnet one), or `-H` takes any ssh host. `BURNER_HOST` for a whole shell, `-H local` for here
- what a remote host sends back is checked here: output escaped, a shell's terminal filtered and reset here, `~.` handled here, a result tar parsed again here, and the exit code from a line only burner there can write. remote failures are 125 with outcome `unreachable`, `remote_error` or `lost`, never ssh's 255
- `burner -H HOST doctor` checks the way there and shows that host's own doctor. `burner hosts [--check]` lists hosts.toml
- burner-tui takes `-H HOST` and switches hosts with `h`
- `tests/remote.sh`: burner -H over ssh to localhost, with a stand-in for the far end or the real burner

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
