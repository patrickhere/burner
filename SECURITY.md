# security

burner runs untrusted code as root's helper, so a hole in it matters. if you find one, please don't open a public issue.

- report it privately through github: the security tab on this repo, "report a vulnerability"
- or email patrick@burnervm.dev

say what you found and how to reproduce it. i'll answer as soon as i can and credit you in the fix if you want.

in scope: anything that lets code in a VM reach the host, the LAN or another VM, run something as root, leave a VM running past its limits, or mess with the caller's terminal. bugs in firecracker or kvm themselves go to [firecracker](https://github.com/firecracker-microvm/firecracker/security/policy).
