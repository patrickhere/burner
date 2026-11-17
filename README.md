# burner

throwaway linux VMs on your own hardware. you ask for a VM, get a root shell or run a command in it, and it's deleted when you're done. each one is a firecracker microVM with its own kernel, and it can reach the internet but not your LAN.

early days. the design and tests come from a version i've been running on my own box, and it's being rebuilt here in rust so other people can install it.

## what works right now

```
burner doctor     # can this machine run burner, and what to fix if not
burner config     # the config burner would use, defaults filled in
```

config lives in `/etc/burner/config.toml`. every key is optional, `burner config` shows the defaults.

## building

```
cargo build --release
sudo ./target/release/burner doctor
```

needs linux with kvm, cgroup v2, nftables and iproute2.
