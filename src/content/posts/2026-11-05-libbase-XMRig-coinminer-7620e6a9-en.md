---
title: "Malware Analysis: libbase XMRig coinminer (ELF · elf · 7620e6a9)"
published: 2026-11-05
draft: false
description: "Malicious (medium confidence): libbase XMRig coinminer · miner/backdoor · difficulty medium · static analysis only"
tags: ["miner", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-libbase-XMRig-coinminer-7620e6a9"
---

> [!WARNING]
> **Verdict: Malicious** · Family **libbase XMRig coinminer** (uncertain) · Confidence **medium**
> 
> Aliases: XMRig-based Linux coinminer, system-helper miner, snapd/snap masquerading miner, ssh-session-gate backdoor
> 
> The sample embeds a complete XMRig/RandomX Monero mining engine (donate-level=0) and implements multiple persistence and backdoor components such as libbase, system-helper and ssh-session-gate, showing clear intent of resource abuse and long-term residency; no ransomware, file encryption or credential-stealing logic was found.

## Overview

| Item | Content |
|:--|:--|
| Family | **libbase XMRig coinminer** · aliases XMRig-based Linux coinminer, system-helper miner, snapd/snap masquerading miner, ssh-session-gate backdoor · _uncertain_ |
| Confidence | **medium** |
| Behavior class | miner · backdoor |
| Difficulty | medium |
| First seen | 2026-11-01 17:20:24 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/7620e6a995b46fef7f2de8b214deceb27ef1a6cdd56ec05b763f0fcb30c4514b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Embedded XMRig miner</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1496</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Spawn watchdog every minute</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Fake systemd services</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Hijack login shell</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1546.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Preload malicious library</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.006</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `7620e6a995b46fef7f2de8b214deceb27ef1a6cdd56ec05b763f0fcb30c4514b` |
| MD5 | _not recorded_ |
| Size | 2,588,672 bytes (2.5 MB) |
| Type | ELF · `elf` |

## Behavior analysis

**12** behaviors in total, each backed by evidence, and all are statically recoverable.

### 1. Embedded XMRig miner

`T1496` · Confidence **high** · static

Statically linked with a full XMRig/RandomX Monero mining engine, the configuration template sets donate-level to 0 and embeds 7 default supportxmr pools; at runtime it connects to the pool as configured and submits hashing power.

> **Evidence**: config template off 1336428-1336663 (algo rx/0, pass 16); pool strings from off 1389735; RandomX/Argon2/MSR strings and /dev/cpu/{}/msr reference 0x44807D
> 
> **Source**: `ref:e67796d665` · `ref:756fa2f42e`

### 2. Spawn watchdog every minute

`T1053.003` · Confidence **high** · static

Writes /etc/cron.d/system-helper and user crontab @reboot and every-minute jobs that repeatedly execute /var/tmp/snap, /var/tmp/snapd and $HOME/.X0-lock, achieving start-up on reboot and periodic self-restart.

> **Evidence**: cron lines off 1375299-1375672; /etc/cron.d/system-helper reference 0x42C850
> 
> **Source**: `ref:e67796d665` · `ref:5cfe41c619`

### 3. Fake systemd services

`T1543.002` · Confidence **high** · static

Installs system-helper.service (Type=oneshot, runs /usr/local/bin/system-helper-run) and system-helper.timer (OnBootSec=0, OnCalendar=*:0/1), persisting at boot and every minute under the guise of a system helper.

> **Evidence**: unit text off 1376659-1377182; /etc/systemd/system/system-helper.service reference 0x42C3B0
> 
> **Source**: `ref:e67796d665` · `ref:5cfe41c619`

### 4. Hijack login shell

`T1546.004` · Confidence **high** · static

Installs libbase.sh to /usr/local/libexec and /etc/profile.d, and writes ~/.bashrc and ~/.zshrc; it wraps interactive shells with --libbase-run, backs up and replaces /bin/sh (/bin/sh.bak), and takes over the session when a user logs in.

> **Evidence**: libbase.sh path off 1380866-1381101; /bin/sh.bak reference 0x431361; main at 0x4027EE checks argv[1]==--libbase-run and jumps to 0x43148B
> 
> **Source**: `ref:e67796d665` · `ref:5d344ce76f` · `ref:5cfe41c619`

### 5. Preload malicious shared library

`T1574.006` · Confidence **high** · static

Writes libcommon.so into /usr/local/lib and keeps a .bak copy, forcing it to load through LD_PRELOAD and /etc/ld.so.preload, giving it userland hijacking/hiding capability.

> **Evidence**: LD_PRELOAD= reference 0x42A5B7; /etc/ld.so.preload reference 0x42AE32; libcommon.so/.bak strings off 1375782-1375828
> 
> **Source**: `ref:5cfe41c619` · `ref:e67796d665`

### 6. Tamper with system monitoring commands

`T1014` · Confidence **high** · static

In the shell environment it overrides commands such as top, crontab and kill to filter out processes and scheduled jobs whose names contain 16 or libbase.sh, making the mining process and persistence entries hard for users to notice.

> **Evidence**: top filter /16/d, /libbase.sh/d at off 1377320; crontab/kill wrappers at off 1377881 and 1378592
> 
> **Source**: `ref:e67796d665`

### 7. Clear history and logs

`T1070.003` · Confidence **high** · static

Deletes $HOME/.bash_history, /var/tmp/apt.log and /var/tmp/yum.log, and kills processes whose names contain b0s, yum.log or apt.log, reducing the chance of forensics and tracing.

> **Evidence**: pkill -9 -f '.b0s' and similar commands at off 1379387, reference 0x4303C5
> 
> **Source**: `ref:e67796d665` · `ref:5cfe41c619`

### 8. Kill competing miners

`T1489` · Confidence **high** · static

It finds same-named processes via comm=16 or pgrep -x 16 and keeps the one using the most CPU while killing the rest; it also terminates competing miners such as ./init seen in nvidia-smi, monopolizing the victim host's computing power.

> **Evidence**: ps/pgrep/kill logic off 1379295-1380271; pkill '.b0s' reference 0x4303C5
> 
> **Source**: `ref:e67796d665` · `ref:5cfe41c619`

### 9. Tamper with sshd session gate

`T1556` · Confidence **high** · static

Modifies /etc/ssh/sshd_config, adding ForceCommand to call /usr/local/sbin/ssh-session-gate and disabling X11/Agent forwarding; the session gate reads SSH_ORIGINAL_COMMAND and wraps scp/rsync/sftp-server, able to hijack or record SSH session commands.

> **Evidence**: sshd_config references 0x44A099 and 0x4329D2; main at 0x402925 checks the ssh-session-gate path, at 0x402939 reads SSH_ORIGINAL_COMMAND/SSH_TTY
> 
> **Source**: `ref:5cfe41c619` · `ref:5d344ce76f` · `ref:e67796d665`

### 10. Set up firewall self-defense

`T1562.004` · Confidence **high** · static

Installs iptables and fail2ban and writes jail.local (maxretry=3, bantime=-1, banaction=iptables-multiport, ignorecommand=/bin/false) to permanently ban scanning and competing access.

> **Evidence**: fail2ban/iptables command strings off 1380271
> 
> **Source**: `ref:e67796d665`

### 11. Embedded encrypted second stage

`T1027.009` · Confidence **medium** · static

At file offset 0x1634B8 it embeds a second ELF64 header (ET_EXEC, x86-64, entry 0xC1F400, phnum=3, no section headers); the following 1,133,384-byte block has entropy 8.00 and appears to be an encrypted or compressed second-stage payload, currently undecrypted.

> **Evidence**: embedded ELF header off 0x1634B8; block entropy 8.00; overall entropy 7.424
> 
> **Source**: `ref:5cfe41c619`

### 12. Beacon to port 80

`T1071.001` · Confidence **medium** · static

It builds an HTTP request to path /f/m/.X0-lock_ on port 80 of the runtime host, together with server::alive liveness logic; the target host is not visible in static data and is inferred to come from runtime configuration or external resolution.

> **Evidence**: lea rdx,[rip+0x11d8e6] @0x433C3E points to /f/m/.X0-lock_; server::alive reference 0x4342BE; hxxp:// and :80 follow in the same string region
> 
> **Source**: `ref:5cfe41c619` · `ref:e67796d665`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `pool-fr[.]supportxmr[.]com` | 5555 | c2 | static | — |
| tcp | `pool-phx[.]supportxmr[.]com` | 5555 | c2 | static | — |
| tcp | `pool-nyc[.]supportxmr[.]com` | 5555 | c2 | static | — |
| tcp | `pool-hk[.]supportxmr[.]com` | 5555 | c2 | static | — |
| tcp | `pool-sg[.]supportxmr[.]com` | 5555 | c2 | static | — |
| tcp | `pool-aus[.]supportxmr[.]com` | 5555 | c2 | static | — |
| tcp | `pool-ca[.]supportxmr[.]com` | 5555 | c2 | static | — |
| http | `hxxp://[runtime-host]:80/f/m/.X0-lock_` | 80 | c2 | static | ⏳ not observed |

### Host

**Dropped paths**

- `/var/tmp/snap`
- `/var/tmp/snapd`
- `$HOME/.X0-lock`
- `/usr/local/libexec/libbase.sh`
- `/etc/profile.d/libbase.sh`
- `/etc/profile.d/libcommon.csh`
- `/usr/local/lib/libcommon.so`
- `/usr/local/lib/libcommon.so.bak`
- `/usr/local/sbin/ssh-session-gate`
- `/usr/local/bin/system-helper-run`
- `/etc/systemd/system/system-helper.service`
- `/etc/systemd/system/system-helper.timer`
- `/etc/cron.d/system-helper`
- `/etc/ld.so.preload`
- `/etc/fail2ban/jail.local`
- `/bin/sh.bak`
- `/etc/ssh/sshd_config`

**Services**

- `system-helper.service`
- `system-helper.timer`

**Scheduled tasks**

- `@reboot [ -f /var/tmp/snap ] && chmod +x /var/tmp/snap && /var/tmp/snap`
- `@reboot [ -f /var/tmp/snapd ] && chmod +x /var/tmp/snapd && /var/tmp/snapd`
- `@reboot [ -f $HOME/.X0-lock ] && chmod +x $HOME/.X0-lock && $HOME/.X0-lock`
- `* * * * * [ -f /var/tmp/snap ] && chmod +x /var/tmp/snap && /var/tmp/snap`
- `* * * * * [ -f /var/tmp/snapd ] && chmod +x /var/tmp/snapd && /var/tmp/snapd`
- `* * * * * [ -f $HOME/.X0-lock ] && chmod +x $HOME/.X0-lock && $HOME/.X0-lock`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `pool-fr[.]supportxmr[.]com:5555, pool-phx[.]supportxmr[.]com:5555, pool-nyc[.]supportxmr[.]com:5555, pool-hk[.]supportxmr[.]com:5555, pool-sg[.]supportxmr[.]com:5555, pool-aus[.]supportxmr[.]com:5555, pool-ca[.]supportxmr[.]com:5555` | yes | static |
| `mining_algo` | `rx/0 (RandomX, Monero/XMR)` | yes | static |
| `donate_level` | `0` | no | static |
| `pool_password` | `16` | no | static |
| `beacon_path` | `/f/m/.X0-lock_` | yes | static |
| `persistence_entry` | `/usr/local/libexec/libbase.sh (via /etc/profile.d/libbase.sh, ~/.bashrc, ~/.zshrc, /bin/sh wrapper)` | yes | static |
| `preload_library` | `/usr/local/lib/libcommon.so via /etc/ld.so.preload` | no | static |
| `mining_wallet` | `-` | yes | dynamic |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not report it as ransomware: no file encryption, extension rewriting or ransom-note code was found; the behavior centers on CPU mining and persistence.
- Do not report it as a credential stealer: no logic reading browser password stores, wallet files, SSH private keys or system credentials was observed.
- Do not claim SSH brute-force/lateral-worm capability based on this: no password dictionaries, known_hosts scanning or bulk authentication code appears in the static data.
- The default supportxmr pool does not equal the actual payout address: the pool list is an embedded configuration template, and the real pool/wallet may be overridden by runtime configuration and does not appear in plaintext in the sample.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | no |

**Limitations and pending verification**

1. This is a static analysis only; the sample was not detonated on an isolated host, and no actual process, network connection or file drop was observed; the conclusions come from structural, string and instruction-level evidence.
2. The real mining pool account and payout wallet could not be determined statically; the embedded supportxmr list may just be the XMRig default template.
3. The host part of the HTTP liveness path is determined by runtime configuration/resolution; no plaintext C2 domain or IP exists in the static data.
4. The second-stage ELF body at file offset 0x1634B8 is high-entropy encrypted/compressed data that was not unpacked or decrypted, so its function is unknown.
5. No vendor engine, YARA rule or multi-engine naming evidence was available; the family name is a candidate and carries uncertainty.
6. Some script strings exist in the sample as concatenated or escaped forms; the report restores them by readable semantics, and individual paths/parameters may be subject to runtime variable substitution.

## Evidence index

<details>
<summary>Expand 8 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:98eb859d23` | ELF structure parsing | ELF64 x86-64 EXEC, statically linked, entry 0x4070D7, two LOAD segments, GNU_STACK RWX, no section headers/symbols/imports, anomalous shdr_oob. |
| `ref:a9b8e93f9c` | elf.sections | Segment table confirms R-X and RW- LOAD, TLS, GNU_RELRO, RWX GNU_STACK; no section table. |
| `ref:756fa2f42e` | string extraction | First string-extraction pass (3,119 ASCII strings), hitting hugepages/randomized alphabet strings. |
| `ref:e67796d665` | string extraction | Long-string extraction: XMRig configuration template, 7 supportxmr pools, cron/systemd/libbase/sshd/LD_PRELOAD/anti-forensics persistence strings and offsets. |
| `ref:5d344ce76f` | decompile.function | main @0x4027EE decompilation: dispatches --libbase-run, checks /usr/local/sbin/ssh-session-gate, reads SSH_ORIGINAL_COMMAND/SSH_TTY, wraps sftp/rsync/scp. |
| `ref:cf57a551da` | disasm.function | main entry instruction flow, confirming argument checks and ssh-session-gate string references. |
| `ref:b30fde2b2b` | decompile.symbols | Identified 3,044 functions in the static ELF, mostly C++ (libuv/XMRig style), with no readable symbols. |
| `ref:5cfe41c619` | evidence.record | Instruction-level cross-references locating install/persistence/liveness/sshd function addresses; located and measured the embedded encrypted ELF second stage (0x1634B8, 1,133,384 bytes, block entropy 8.00). |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
