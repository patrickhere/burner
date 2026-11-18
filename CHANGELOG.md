# changelog

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
