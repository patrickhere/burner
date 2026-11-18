# burner

throwaway linux VMs on your own hardware. you ask for a VM, get a root shell or run a command in it, and it's deleted when you're done. each one is a firecracker microVM with its own kernel, and it can reach the internet but not your LAN.

it started as a sandbox on my homelab for running code i don't trust (install scripts, other people's repos, things agents want to run) away from the box that has my keys on it. this is the rebuild in rust so other people can install it. the homelab version stays private, so the history here starts with the rebuild.

```
sudo burner shell                          # root shell in a fresh VM, gone when you exit
sudo burner run -- 'uname -a; exit 3'      # run one thing, get its output and exit code back
```

## what it does

- `burner shell [image]` -> a login shell on the VM's console, your terminal size passed in. 60 min max
- `burner run -- cmd` -> boots a VM (~2-3s), runs `cmd` in `sh`, streams the output, returns its exit code, deletes the VM
- `--in tar` unpacks a tar from stdin into `/work`, `--in stdin` feeds stdin to the command, `--result tar` hands back whatever the command put in `/out`
- `--net none|web|open` -> no network, http/https and dns only, or any port but mail. the LAN, the host and other VMs are always blocked
- `burner ls`, `burner kill ID`, `burner images`, `burner doctor`

```
git archive HEAD | sudo burner run --net web --in tar -- 'npm ci && npm test'
tar -c file.zip | sudo burner run --in tar --result tar -- 'unzip -q file.zip -d /out' > res.tar
```

exit codes: the command's own, 124 when it hit the time limit, 125 when the sandbox itself failed, 2 for bad arguments, 130 when killed.

## how it works

```
burner ──jailer──> firecracker VM ──tap──> nft ──nat──> internet
                        │                   │
                        │                   └──x──> LAN, the host, other VMs
                        └── read-only image, scratch disk, job tar in, result tar out
```

- every VM runs under firecracker's jailer as the unprivileged `burner` user, in its own cgroup with cpu, memory and pid caps
- the image is mounted read-only with an overlay on a throwaway scratch disk. the command goes in as a raw tar on its own disk
- results come back as a raw tar the guest writes to another disk. the host never mounts anything the guest wrote: the tar is read by a separate burner process running as its own user, `burner-parse`, with hard rlimits, and only regular files and directories get through
- each VM gets a tap and its own /30. one nft table only lets those taps out the uplink, minus private ranges and the host's own addresses. bandwidth and disk io are capped per VM
- the time limit is enforced by burner and backed up by a reaper timer, and a VM's slot is only freed once its cgroup is empty

nothing from the host goes into a VM unless you pipe it in. `--net web` means anything that goes in can leave, so don't pipe in secrets.

## what it protects against

i run it on a box that's only reachable over a VPN. yours might sit on a home LAN or have a public IP. burner assumes the code in the VM is hostile and the host could be any of those.

- burner has no daemon and listens on no port. it's a command you run as root. if you put it behind a web app, a bot or a shared ssh account, everyone who can reach that can boot VMs, and the limits in `/etc/burner/config.toml` (`max_vms`, memory, disk, time, and `net` for the most network a run may ask for) are the only thing between them and your host. as root, burner only reads a config that root owns in a directory only root can write, so `--config` can't point it somewhere else
- a VM can't reach the host on any address, its LAN, other VMs, or anything behind a route that isn't the default one (VPNs, docker networks, tailnets). VM traffic has its own routing table with only the uplink's default route in it, so a VPN that comes up later never applies to VMs. on top of that, a blocked list built from the host's own routes and addresses is refreshed every 30s, and if that refresh fails VMs lose their network instead of keeping a stale filter
- guest packets are checked before conntrack: wrong source address, fragments and floods are dropped at the tap. connections a VM leaves behind are cleared before its slot is reused
- no ipv6 in VMs at all
- on a host with a public IP, VM traffic leaves from that IP. whatever a VM does on the internet looks like you did it. `run` has no network unless you ask, `--net open` still blocks mail ports, and every VM is rate limited, but that's damage control. if strangers can start VMs, use `--net none` or `web` only
- nothing on the LAN or the internet can open a connection into a VM, only replies to what the VM started get back in
- everything the guest sends back is treated as hostile: console output going to a terminal is escaped (piped somewhere else, it's the guest's bytes as they are), the shell goes through a filter that strips terminal tricks (window titles, clipboard writes, escape replies), and the result tar is parsed by a separate unprivileged user with hard limits
- a VM that hangs, a wrapper that gets killed, a full disk or a crash mid-run all end with the VM stopped and its slot freed by the reaper

what it doesn't cover: a bug in firecracker or kvm itself (keep the host kernel and burner's pinned firecracker updated), side channels between VMs on the same cpu, and anything you pipe in yourself.

## install

linux on x86_64 or aarch64 with kvm, cgroup v2, nftables, iproute2 and conntrack. aarch64 is untested so far.

```
cargo build --release
sudo ./install.sh                # firecracker, jailer, guest kernel (pinned + checksummed), users, units
tools/build-image alpine         # an image to boot, needs docker
sudo burner doctor
```

if ufw is on, `burner doctor` prints the one route rule it needs. settings live in `/etc/burner/config.toml`, `burner config` shows them with defaults filled in.

## tests

`tests/isolation.sh` (memory and fork bombs, disk and console floods, a hostile result tar, time limits, slots, argument fuzzing) and `tests/network.sh` (what a VM can and can't reach, with targets found on the host it runs on). both need a box with burner installed and an alpine image, and run as root through sudo.

## license

MIT or Apache-2.0, your pick. see `LICENSE-MIT` and `LICENSE-APACHE`. security reports: `SECURITY.md`.
