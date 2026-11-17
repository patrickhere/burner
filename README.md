# burner

throwaway linux VMs on your own hardware. you ask for a VM, get a root shell or run a command in it, and it's deleted when you're done. each one is a firecracker microVM with its own kernel, and it can reach the internet but not your LAN.

it started as a sandbox on my homelab for running code i don't trust (install scripts, other people's repos, things agents want to run) away from the box that has my keys on it. this is the rebuild in rust so other people can install it.

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
- results come back as a raw tar the guest writes to another disk. the host never mounts anything the guest wrote: the tar is read by a separate burner process running as `burner` with hard rlimits, and only regular files and directories get through
- each VM gets a tap and its own /30. one nft table only lets those taps out the uplink, minus private ranges and the host's own addresses. bandwidth and disk io are capped per VM
- the time limit is enforced by burner and backed up by a reaper timer, and a VM's slot is only freed once its cgroup is empty

nothing from the host goes into a VM unless you pipe it in. `--net web` means anything that goes in can leave, so don't pipe in secrets.

## install

linux on x86_64 or aarch64 with kvm, cgroup v2, nftables and iproute2. aarch64 is untested so far.

```
cargo build --release
sudo ./install.sh                # firecracker, jailer, guest kernel (pinned + checksummed), user, units
tools/build-image alpine         # an image to boot, needs docker
sudo burner doctor
```

if ufw is on, `burner doctor` prints the one route rule it needs. settings live in `/etc/burner/config.toml`, `burner config` shows them with defaults filled in.

## tests

`tests/isolation.sh` (22: memory and fork bombs, disk and console floods, a hostile result tar, time limits, slots, argument fuzzing) and `tests/network.sh` (40: what a VM can and can't reach). both need a box with burner installed and an alpine image.
