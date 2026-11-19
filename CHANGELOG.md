# changelog

## unreleased

- a run ends when its command ends, even with something left running in the background
- a failed filter refresh cuts open connections too, and stops VMs if nft itself fails
- taps don't answer arp for the host's other addresses
- the reaper frees slots held by a stopped wrapper
- job input and VM config are private to root and the VM's uid
- helpers run as root use a fixed PATH
- CRLF and split UTF-8 on a terminal
- help text for run
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
