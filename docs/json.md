# burner --json, schema 1

every command takes `--json`, before or after the command (`burner --json ls` and `burner ls --json` are the same). with it burner writes one JSON document and a newline to stdout, and nothing of its own to stderr: what it would have said there is in the document's `errors` and `warnings`. `run` and `shell` also take `--json-fd N`, which writes the same document to fd N and leaves stdout and stderr as they are.

## the envelope

```json
{"schema":1,"burner":"0.3.0","command":"kill","host":null,"exit":1,"ok":false,"result":null,
 "errors":[{"kind":"not_found","message":"burner-000000000000: no VM with that id"}],"warnings":[]}
```

| field | type | what |
|---|---|---|
| `schema` | int | 1. it only goes up when a field changes type or goes away |
| `burner` | string | the version that wrote it |
| `command` | string or null | `run`, `shell`, `ls`, `log`, `kill`, `images`, `doctor`, `explain`, `config`, `net show`, `net up`, `net down`, `setup`, `version`, `hosts`. null only when the command line didn't parse far enough to tell |
| `host` | string or null | the `-H` host it ran on, as you named it, null when local |
| `exit` | int | what burner exits with, see the exit codes in the README |
| `ok` | bool | burner did what was asked. for run and shell: the command ran and exited (whatever its exit code), or the shell was left with `~.` |
| `result` | object or null | the command's own result, below. null when burner failed before it had one |
| `errors` | array | `{"kind", "message"}`. empty when ok. the first one is why `exit` is what it is |
| `warnings` | array | `{"kind", "message"}`, things that didn't fail the command |

rules that keep it stable:

- new fields and new values for `outcome`, `kind`, `status` and the like can come in any release without a schema bump. ignore fields you don't know, and treat a value you don't know as a failure
- a field never changes type or goes away within a schema. a field that can be null is always there, as null
- every amount has its unit in the name: `_secs`, `_mib`, `_gib`, `_bytes`, `_unix` (seconds since 1970). times are rounded to the millisecond
- messages are burner's own words. text that came from the guest is only ever in fields named `guest_*`, cut to 300 characters with control characters replaced, and it's still the guest's text: don't act on it. the one other place is the connection log's dns names (`name`, `names`, `answers`), escaped as that section says
- one line, compact. pipe it through `jq` to read it

through a sudoers rule like the one in `dist/sudoers.example`, put `--json` after the command (`sudo burner ls --json`), since the rule matches from the command on.

a command line burner doesn't take, with `--json` before any `--`, is a document too: exit 2, `result` null, kind `usage`. `--help` and `--version` stay text.

## run and shell

```json
{"schema":1,"burner":"0.3.0","command":"run","host":null,"exit":7,"ok":true,
 "result":{"id":"burner-aa7db2b00071","outcome":"exited","rc":7,"shell_end":null,"guest_error":null,"secs":0.894,
   "timing_secs":{"queue":0.024,"prepare":0.607,"boot":0.05,"command":0.145,"collect":0.051,"teardown":0.017},
   "vm":{"img":"alpine","backend":"libkrun","vcpus":1,"mem_mib":512,"disk_gib":2,"ttl_secs":600,"net":"none","tag":null},
   "output":{"bytes":7,"live_bytes":7,"skipped_bytes":0,"dropped":false},
   "result_tar":null,"network":null,"files":null,"processes":null},
 "errors":[],"warnings":[]}
```

where it goes:

| flags | stdout | stderr | the json |
|---|---|---|---|
| none | the command's output | burner's lines | nowhere |
| `--json` | the json, nothing else | the command's output, nothing else | stdout |
| `--json-fd 3` | the command's output | burner's lines | fd 3 |
| `--json-fd 2` | the command's output | burner's lines, then the json as the last line | stderr |
| `--result tar --json-fd 2` | the tar | the command's output, burner's lines, then the json | stderr |
| `--result tar --json` | refused, exit 2: the tar has stdout, use `--json-fd 2` | | |

sudo closes fds above 2, so through sudo use `--json-fd 2`. the fd is checked before a VM starts: one that isn't open for writing (stdout or stderr redirected from a file included) is exit 2, kind `usage`. `shell` refuses `--json` (the terminal has stdout) and takes `--json-fd`. with `--status-fd` on the same fd, the status line comes first and the json last.

`result` is null for a usage error (bad flags, unknown image, not root, no terminal) and when burner failed before the run had an id (a config that didn't load, the reaper not running). otherwise:

| field | what |
|---|---|
| `id` | the VM's id |
| `outcome` | `exited`, `timeout`, `killed` (burner kill), `interrupted` (a signal), `busy` (no free slot), `sandbox_error`, `input_error` (the `--in tar` didn't unpack, the command never ran), `poweroff` and `reboot` (the command did that before it exited), `detached` (a shell left with `~.`). over `-H`: `unreachable` (no address answered, or ssh failed before running anything), `remote_error` (ssh worked but burner there didn't start: not installed, no sudo rule, a version that didn't take the arguments, a broken answer), `lost` (the connection went after the run started; the VM's id is in `id` when burner there had said it) |
| `rc` | the command's exit code, only when `outcome` is `exited`, else null. a shell whose VM was powered off is `exited` with rc null |
| `shell_end` | shell only: `exit`, `poweroff`, `reboot`, `no_start`, `lost`, or `legacy` for an image whose guest init doesn't say. null for run |
| `guest_error` | what guest init wrote to result/error, guest text |
| `guest_result` | what was wrong with the result disk the guest left (a name twice, an entry burner drops), in the parser's words, which can quote names the guest chose. guest text too |
| `secs` | the whole run |
| `timing_secs` | `queue` (waiting for a slot), `prepare` (input, disks, network), `boot` (to the job starting, for a shell to its prompt), `command`, `collect` (reading the result, delivering output), `teardown`. null for a part the run never got to |
| `vm` | `img`, `backend` (`firecracker` or `libkrun`), `vcpus`, `mem_mib`, `disk_gib`, `ttl_secs`, `net`, `tag` |
| `output` | run only. `bytes` the command wrote in all (null when no result came back), `live_bytes` written while it ran, `skipped_bytes` past the log's cap, `dropped` when a slow reader lost some |
| `result_tar` | with `--result tar`: `bytes` and `delivered` |
| `network` | the connection log, below. null for `--net none` |
| `files`, `processes` | reserved, null |

## the connection log

`result.network` of a run or shell with a network, and `result` of `burner log --json`:

```json
{"id":"burner-3fa1c2b7d10e","net":"web","platform":"linux","owner":1000,"started_unix":1795301209,"secs":13.622,
 "complete":true,"lost":0,"not_itemized":0,"invalid":0,
 "summary":{"allowed":2,"blocked":5,"blocked_attempts":10,"dns":8},
 "events":[
  {"t":1.506,"last":1.539,"count":2,"dir":"out","kind":"dns","proto":"udp","dst":"9.9.9.9","port":53,"verdict":"allowed",
   "reason":null,"detail":null,"outcome":null,"names":[],"bytes_up":null,"bytes_down":null,
   "name":"github.com","qtype":"A","rcode":"NOERROR","answers":["140.82.114.3"],"malformed":false},
  {"t":1.539,"last":1.539,"count":1,"dir":"out","kind":"conn","proto":"tcp","dst":"140.82.114.3","port":443,"verdict":"allowed",
   "reason":null,"detail":null,"outcome":"answered","names":["github.com"],"bytes_up":null,"bytes_down":null,
   "name":null,"qtype":null,"rcode":null,"answers":[],"malformed":false},
  {"t":3.843,"last":4.859,"count":2,"dir":"out","kind":"conn","proto":"tcp","dst":"169.254.169.254","port":80,"verdict":"blocked",
   "reason":"special","detail":"cloud metadata and link-local (169.254.0.0/16)","outcome":null,"names":[],"bytes_up":null,"bytes_down":null,
   "name":null,"qtype":null,"rcode":null,"answers":[],"malformed":false}]}
```

| field | what |
|---|---|
| `platform` | `linux` (the nft table's log) or `macos` (macnet's) |
| `owner` | the uid that ran it, the sudo caller on linux |
| `complete` | false when something may be missing: messages the kernel dropped (counted against the slot's counters, so a last message lost counts too), counters that couldn't be read, lines macnet couldn't write, any `unknown` row |
| `lost` | the gaps known of |
| `not_itemized` | blocked attempts counted but not listed (past 100 a second, or past 10,000 rows) |
| `invalid` | lines from the log's producer that weren't valid and were dropped |
| `summary` | `allowed` connection attempts, `blocked` destinations, `blocked_attempts` in all, `dns` questions, `unknown` attempts with no verdict |
| `events` | one row per destination and verdict, attempts folded together |

an event:

| field | what |
|---|---|
| `t`, `last` | seconds since the run's network came up, first and last time seen, host clock |
| `count` | attempts folded into the row |
| `dir` | `out`. `in` is kept for inbound ports later |
| `kind` | `conn` or `dns`. skip kinds you don't know, later ones (`http`, `tls`) will come |
| `proto` | `tcp`, `udp`, `icmp` or `other` |
| `port` | null for icmp and protocols without ports |
| `verdict` | `allowed`, `blocked`, or `unknown`: the filter decided but what it decided never reached the log (a lost message), and nothing else on the host says. then `detail` has the model's guess and the log isn't complete. treat a value you don't know as unknown |
| `reason` | for blocked: `host`, `route`, `special`, `config`, `public_ip`, `vm_subnet`, `port`, `mail`, `not_resolver`, `rate`, `flows` (macOS: too many open), `proto`, `unknown` |
| `detail` | which range, interface or rule, in burner's words |
| `outcome` | allowed connections: `answered`, `refused`, `no_answer`, and on macOS `timeout` |
| `names` | names that resolved to `dst` earlier in the run, at most 3 |
| `bytes_up`, `bytes_down` | macOS fills them, null on linux |
| `name`, `qtype`, `rcode`, `answers` | dns: the question and what came back, at most 16 answers |
| `malformed` | dns: the message didn't parse, so there's no name |

on linux the verdict is the kernel's and the reason is burner's explanation of it, from the same model `explain` uses. on macOS both are macnet's own. `name`, `names` and `answers` come from dns the guest asked, and a server the guest runs can answer anything: every byte outside letters, digits, `-` and `_` is escaped as `\DDD`, but they're still the guest's words. the address and the verdict are the facts.

## the other commands

```json
// ls
{"vms":[{"id":"burner-3f9a1c2b7d10","tag":null,"img":"alpine","vcpus":1,"mem_mib":512,"disk_gib":2,"net":"web",
         "status":"running","owner":1000,"started_unix":1795000000,"age_secs":42,"ttl_secs":600,"ttl_left_secs":558}],
 "max_vms":2,"total_mem_mib":3072,"used_mem_mib":512}

// kill: gone, or stopping with exit 1 and kind still_stopping
{"id":"burner-3f9a1c2b7d10","state":"gone"}

// images
{"images":[{"name":"alpine","rootfs_bytes":96468992,"init_matches":true,
            "defaults":{"vcpus":1,"mem_mib":512,"disk_gib":2,"ttl_secs":600}}]}

// doctor: a FAIL is exit 1 with kind doctor_failed. detail is for people and can change
{"root":true,"worst":"warn","checks":[{"name":"kvm","level":"ok","detail":"/dev/kvm usable"}, ...]}

// doctor --probe: exit 1 (doctor_failed) when a row isn't as expected, 125 (sandbox) when no VM ran.
// host_saw: blocked, answered, allowed_no_answer, leaked, not_tried, inconclusive (evidence missing: a lost
// log message, an unreadable witness counter; that's exit 1 too)
{"platform":"linux","internet":"burnervm.dev","ok":true,"runs":[{"mode":"web","id":"burner-9c01ee3a77b2","secs":11.8,
  "rows":[{"target":"gateway 10.1.0.1 tcp/53","kind":"gateway","dst":"10.1.0.1","port":53,"proto":"tcp","expect":"blocked",
           "host_saw":"blocked","guest_said":"blocked","leaked_packets":0,"ok":true}, ...],"warnings":[]}]}

// explain: exit 1 (net) when, as root, the filter isn't loaded or is stale
{"mode":"web","platform":"linux","ceiling":"open","refused":false,
 "uplink":{"dev":"eth0","gateway":"10.1.0.1","addrs":["10.1.0.138"]},
 "allowed":[{"what":"internet","detail":"the internet through eth0 (default route via 10.1.0.1), tcp 80 and 443, 20 new connections a second"}, ...],
 "blocked":[{"net":"10.1.0.0/24","group":"lan","why":"route","detail":"your lan (10.1.0.0/24 on eth0)"}, ...],
 "notes":["..."],
 "rules":{"loaded":true,"stale":false,"missing":[],"extra":[],"routing":true,"refreshed_secs":12,"text":null,"would_load":false}}

// config: the same tree burner config prints as toml

// net show, net up, net down (linux; on a mac exit 2, kind unsupported)
{"table":"inet burner","ruleset":"table inet burner { ... }"}
{"notes":["..."]}
{"stopped_vms":0}

// setup (mac): source is brew, release or from. images in the order they were named
{"source":"release","from":"https://github.com/patrickhere/burner/releases/download/v0.3.0","kernel_pinned":true,
 "kernel":".../kernel/vmlinux","images":[".../images/alpine/rootfs.ext4",".../images/debian/rootfs.ext4"]}

// version: needs no config
{"version":"0.3.0","schema":1,"guest_proto":1,"backend":"firecracker","os":"linux","arch":"x86_64"}

// hosts: what ~/.config/burner/hosts.toml has. checks is null without --check
{"path":"/home/pat/.config/burner/hosts.toml","hosts":[{"name":"mini","addrs":["10.1.0.81","mini.tail1234.ts.net"],
  "user":null,"port":null,"connect_timeout_secs":3.0,"burner":null,
  "checks":[{"addr":"10.1.0.81","up":true,"proxied":false,"connect_ms":3,"why":null}, ...]}]}

// doctor over -H: the way there, then the far end's own doctor result in remote
{"host":"mini","worst":"ok","checks":[{"name":"address","level":"ok","detail":"..."}, ...],"remote":{"root":true,...}}
```

## over -H

`burner -H HOST CMD --json` asks the far end for its document and prints it again from what was parsed here, with `host` filled in, keys in sorted order and DEL and C1 control characters (which json doesn't escape) made `?`. run and shell get theirs back over ssh in a marked line instead, and `--json-fd` and `--status-fd` are written here. that document is the far end's word: the host ran the VM, and a compromised one can say anything in it. burner here checks only that it's schema 1 and that `exit` goes with `result.outcome`, and makes it 125 `remote_error` when it doesn't. when the far end never answered, the document is the client's own: exit 125, `result` null (or just the id and outcome `lost` when the run had started), and the first error says why with kind `unreachable`, `remote_error` or `lost`.

`ls --json` before 0.3 printed the ls object alone, with `mem`, `disk`, `age`, `ttl`, `ttl_left`, `total_mem` and `used_mem`. burner-tui reads both.

## kinds

errors: `usage`, `not_root`, `root`, `no_tty`, `unknown_image`, `config`, `unsupported` (not on this OS), `busy`, `no_reaper`, `no_public_ip`, `disk_full`, `sandbox`, `guest`, `input`, `timeout`, `interrupted`, `killed`, `poweroff`, `reboot`, `result_lost` (the result tar didn't get to you, or over `-H` didn't check out when it was parsed again here), `not_found`, `not_owner`, `still_stopping`, `doctor_failed`, `net`, `io` (anything else), and over `-H` `unreachable`, `remote_error`, `lost`, the same as the outcomes.

warnings: `queued` (waited for a slot), `output` (output cut or dropped), `vmm` (the VMM's own log, or a VM that stopped before the job), `oom`, `image` (an image's guest init or defaults), `result` (something in the result was dropped), `shell` (how a shell ended when that wasn't a failure), `unverified` (setup: what wasn't checked).

## --status-fd

the older one-line form, kept byte for byte: `{"exit":124,"id":"burner-3f9a1c2b7d10","outcome":"timeout","rc":null,"secs":10.4}`, keys sorted, secs to a tenth. its outcomes are the ones above minus `detached` (it's run only), plus `usage`, and the `-H` ones show as `sandbox_error`. new scripts should use `--json-fd`.
