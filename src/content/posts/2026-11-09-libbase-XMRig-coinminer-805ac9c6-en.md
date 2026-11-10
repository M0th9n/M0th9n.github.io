---
title: "Malware Analysis: libbase XMRig coinminer (ELF · elf · 805ac9c6)"
published: 2026-11-09
draft: false
description: "Malicious (medium confidence): libbase XMRig coinminer · miner/backdoor · difficulty medium · Pure static analysis"
tags: ["libbase XMRig", "miner", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-libbase-XMRig-coinminer-805ac9c6"
---

> [!WARNING]
> **Verdict: Malicious** · Family **libbase XMRig coinminer** (uncertain) · Confidence **medium**
> 
> Aliases: XMRig-based Linux coinminer, system-helper miner, snapd/snap masquerading miner, ssh-session-gate backdoor
> 
> The sample embeds a complete XMRig/RandomX Monero mining engine and carries code and scripts for a system-helper service, per-minute cron restart, libbase.sh login-shell hijacking, /etc/ld.so.preload preloading, an sshd ForceCommand session gate, permanent fail2ban banning for self-protection, competing-miner cleanup and log wiping; it also has XOR 0x5A-obfuscated C2 configuration (two IPs and project0[.]cc) and an embedded encrypted ELF second stage. The intent to profit by mining and persist long-term is clear.

## Overview

| Item | Content |
|:--|:--|
| Family | **libbase XMRig coinminer** · aliases XMRig-based Linux coinminer, system-helper miner, snapd/snap masquerading miner, ssh-session-gate backdoor · _uncertain_ |
| Confidence | **medium** |
| Behavior class | miner · backdoor |
| Difficulty | medium |
| First seen | 2026-11-07 15:02:26 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/805ac9c67e7b44520283963ac357d6f2b9a84291a0086ac4e02caf56aeaeed23/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Built-in Monero mining engine</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1496</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Hijack login shell sessions</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1546.004</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Launch daemon every minute</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Fake systemd helper service</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Preload malicious shared library</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.006</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `805ac9c67e7b44520283963ac357d6f2b9a84291a0086ac4e02caf56aeaeed23` |
| MD5 | _not recorded_ |
| Size | 1,703,936 bytes (1.6 MB) |
| Type | ELF · `elf` |

## Behavior analysis

**12** behaviors in total, each backed by evidence, and all are statically available.

### 1. Built-in Monero mining engine

`T1496` · Confidence **high** · static

It statically links the complete XMRig/RandomX mining engine, including the rx/0 algorithm, MSR/huge-pages optimization, seven supportxmr pools and a built-in configuration template with donate-level=0.

> **Evidence**: 0x552280 'RandomX', 0x551773 'no valid configuration found, try hxxps://xmrig[.]com/wizard', cron from 0x54fc43 and the configuration template at 0x552xxx
> 
> **Source**: `ref:1230379508` · `ref:3a1200a943`

### 2. Hijacks login shell sessions

`T1546.004` · Confidence **high** · static

main recognizes the --libbase-run argument and enters the libbase.sh wrapper logic, writes startup hooks into /usr/local/libexec/libbase.sh, /etc/profile.d, ~/.bashrc and ~/.zshrc, backs up and replaces /bin/sh (/bin/sh.bak), and takes over interactive shell startup.

> **Evidence**: 0x402812 lea rsi,'--libbase-run'; 0x40284f lea rsi,'libbase.sh'; 0x402976 lea r13,'/bin/sh'
> 
> **Source**: `ref:3a1200a943` · `ref:1230379508`

### 3. Launches daemon every minute

`T1053.003` · Confidence **high** · static

It writes @reboot and * * * * * tasks into the user crontab that periodically run /var/tmp/snap, /var/tmp/snapd and $HOME/.X0-lock, achieving restart and per-minute self-healing.

> **Evidence**: six cron lines from 0x54fc43 / 0x54fcd6; 0x5503d5 '/etc/cron.d/system-helper'
> 
> **Source**: `ref:1230379508`

### 4. Masquerades as systemd helper service

`T1543.002` · Confidence **high** · static

It writes system-helper.service (Type=oneshot, ExecStart=/usr/local/bin/system-helper-run) and system-helper.timer (OnBootSec=0, every minute), masquerading as a system helper to achieve boot-time and periodic persistence.

> **Evidence**: 0x55018c unit text; 0x550227 timer text; 0x5502b2/0x5502dc unit paths
> 
> **Source**: `ref:1230379508`

### 5. Preloads malicious shared library

`T1574.006` · Confidence **high** · static

It writes /usr/local/lib/libcommon.so and keeps a .bak, forcing it to load via LD_PRELOAD and /etc/ld.so.preload, providing userland hijacking and hiding capability.

> **Evidence**: 0x550017 '/etc/ld.so.preload'; 0x54fe35 'libcommon.so'; 0x54fe2x 'LD_PRELOAD='
> 
> **Source**: `ref:1230379508`

### 6. Hides tasks and processes from monitoring

`T1014` · Confidence **high** · static

In login shells it overrides top, crontab and kill: top filters lines containing 16 and libbase.sh, crontab reads/writes hide snap/snapd/.X0-lock entries, and kill -9 is rewritten so no SIGKILL is sent, making the persistence and mining processes hard to discover.

> **Evidence**: 0x550428 top wrapper; 0x550659 crontab wrapper; 0x5509d4 kill wrapper
> 
> **Source**: `ref:1230379508`

### 7. Clears history and system logs

`T1070.003` · Confidence **high** · static

It runs pkill to clean up processes related to b0s/yum.log/apt.log and deletes $HOME/.bash_history, /var/tmp/apt.log and /var/tmp/yum.log, reducing the chance of forensics and tracing.

> **Evidence**: 0x550c3b 'pkill -9 -f .b0s; ... rm -f $HOME/.bash_history /var/tmp/apt.log /var/tmp/yum.log'
> 
> **Source**: `ref:1230379508`

### 8. Kills competing mining processes

`T1489` · Confidence **high** · static

Using ps/pgrep it finds same-named processes with comm 16, keeps the one with the highest CPU usage and kills the other instances; it also cleans up competing miners such as ./init shown in nvidia-smi, monopolizing the victim's compute.

> **Evidence**: 0x403426 ps command; 0x550bdf nvidia-smi cleanup; 0x550d64 pgrep -x 16
> 
> **Source**: `ref:3a1200a943` · `ref:1230379508`

### 9. Tampers with sshd session gate

`T1556` · Confidence **high** · static

In main it checks /usr/local/sbin/ssh-session-gate and reads SSH_ORIGINAL_COMMAND/SSH_TTY, wrapping sftp-server, rsync and scp invocations; the sample also contains sshd_config and ForceCommand strings, indicating the ability to gate and hijack SSH sessions.

> **Evidence**: 0x402916 lea rsi,'/usr/local/sbin/ssh-session-gate'; 0x40292d 'SSH_ORIGINAL_COMMAND'; 0x402939 'SSH_TTY'; 0x55270e 'sshd_config'
> 
> **Source**: `ref:3a1200a943` · `ref:1230379508`

### 10. Firewall and ban self-protection

`T1562.004` · Confidence **high** · static

It installs iptables and fail2ban and writes jail.local (maxretry=3, bantime=-1, banaction=iptables-multiport, ignorecommand=/bin/false), using permanent bans to suppress scanning and competing access.

> **Evidence**: fail2ban/iptables command strings from 0x550faf; 0x551199 '/etc/fail2ban/jail.local'
> 
> **Source**: `ref:1230379508`

### 11. C2 check-in and payload retrieval

`T1071.001` · Confidence **medium** · static

It embeds XOR 0x5A-obfuscated configuration fields (two IPv4 addresses: 169.58.248[.]162, 5.189.149[.]171, domain project0[.]cc, a 96-character token) and builds HTTP check-in/retrieval requests using the :80/f/m/.X0-lock_ path and the server::alive status word.

> **Evidence**: 0x1520C8/0x1520D8/0x1520E8/0x153940 XOR 0x5A yields IP/domain/token; 0x55152b ':80/f/m/.X0-lock_'; 0x55153d 'server::alive'
> 
> **Source**: `ref:bf524934c6` · `ref:1230379508`

### 12. Embedded encrypted second-stage payload

`T1027.009` · Confidence **medium** · static

A second ELF64 header is embedded at 0x1634B8 (ET_EXEC, x86-64, entry 0xC1F400, phnum=3, no section headers), and the block after it has entropy around 8.0, likely an encrypted/compressed second-stage payload; this embedded body is also truncated in this sample.

> **Evidence**: embedded ELF header at 0x1634b8; 0x16xxxx-0x19xxxx entropy 7.8-8.0; 248,648 bytes of second stage remain
> 
> **Source**: `ref:bf524934c6` · `ref:32cc11dc7d`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://169.58.248[.]162/f/m/.X0-lock_` | 80 | c2 | static | ⏳ not observed |
| http | `hxxp://5.189.149[.]171/f/m/.X0-lock_` | 80 | c2 | static | ⏳ not observed |
| dns | `project0[.]cc` | - | c2 | static | ⏳ not observed |
| tcp | `pool-fr[.]supportxmr[.]com` | 5555 | c2 | static | ⏳ not observed |
| tcp | `pool-phx[.]supportxmr[.]com` | 5555 | c2 | static | ⏳ not observed |
| tcp | `pool-nyc[.]supportxmr[.]com` | 5555 | c2 | static | ⏳ not observed |
| tcp | `pool-hk[.]supportxmr[.]com` | 5555 | c2 | static | ⏳ not observed |
| tcp | `pool-sg[.]supportxmr[.]com` | 5555 | c2 | static | ⏳ not observed |
| tcp | `pool-aus[.]supportxmr[.]com` | 5555 | c2 | static | ⏳ not observed |
| tcp | `pool-ca[.]supportxmr[.]com` | 5555 | c2 | static | ⏳ not observed |

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

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `169.58.248[.]162, 5.189.149[.]171, project0[.]cc` | yes | static |
| `beacon_path` | `/f/m/.X0-lock_` | yes | static |
| `c2_port` | `80` | no | static |
| `mining_algo` | `rx/0 (RandomX/Monero)` | yes | static |
| `mining_pools` | `pool-fr/phx/nyc/hk/sg/aus/ca[.]supportxmr[.]com:5555` | no | static |
| `donate_level` | `0` | no | static |
| `string_obfuscation` | `single-byte XOR 0x5A` | yes | static |
| `bot_token` | `89PNDJssF3RbL6m7aSydYB4tLrvjZ28Cr8n4LucmFHat8botWkWr6oDPEaSHfeZn4wfA3dC5QsE7nZV1P6tE81sK2i9heamZ` | no | static |
| `install_path` | `/usr/local/libexec/libbase.sh` | yes | static |
| `preload_library` | `/usr/local/lib/libcommon.so` | no | static |
| `mining_wallet` | `-` | yes | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not report it as ransomware: no file encryption, extension rewriting or ransom-note logic was seen; the behavior centers on mining and persistence.
- Do not report it as a credential stealer: no browser password-store, wallet-file or SSH private-key reading logic was seen.
- Do not assert SSH brute-forcing/worm-like lateral movement capability based on this: no dictionary, known_hosts scanning or bulk authentication code was seen in the static data.
- Do not treat the embedded supportxmr pool list as the actual payout pool or wallet: that list is XMRig's default configuration template and the real wallet does not appear in plaintext in the sample.
- Do not assert that the C2 is currently alive or that a session was established: only the IP/domain and check-in path were statically recovered, without any real network interaction.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. The sample is truncated (its size is only about half of what the ELF headers declare), so the RW data segment, the latter half of the code and most of the embedded second stage are missing; it cannot be run or emulated for verification, and the conclusions are limited to the bytes present.
2. No real dynamic detonation was performed, so no process, file drop or network session was observed; the C2 and configuration are marked as statically recovered and pending dynamic verification.
3. The 96-character configuration token uses a custom base64 alphabet protected by the same XOR key; its plaintext has not been recovered, so it cannot be confirmed whether it is a wallet, bot ID or encrypted configuration.
4. No plaintext Monero wallet address was found in the sample; the embedded supportxmr pools may be overridden by runtime arguments.
5. The family name comes from string combinations and existing community naming, lacking vendor-engine/YARA naming support, so uncertainty remains.
6. The code referencing the C2/check-in path lies in the truncated latter half, so instruction-level evidence of the call site for that configuration could not be provided.

## Evidence index

<details>
<summary>Expand 8 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:dd9a6af2bc` | ELF structure parsing | ELF64 x86-64 EXEC, statically linked, entry 0x407017, two LOAD segments, TLS, GNU_RELRO, RWX GNU_STACK, no section headers/symbols/imports, shdr out-of-bounds anomaly. |
| `ref:65131aaf08` | elf.sections | section table confirms R-X and RW- LOAD, TLS, GNU_RELRO, RWX GNU_STACK, no section table. |
| `ref:1230379508` | string extraction | extracted 3,955 ASCII strings, including the XMRig configuration template, supportxmr pools, cron/systemd/libbase/sshd/LD_PRELOAD/fail2ban/anti-forensics scripts and paths. |
| `ref:32cc11dc7d` | scan.entropy | overall entropy 6.859; the embedded second-stage block has entropy around 8.0. |
| `ref:f345abc908` | cryptographic constant identification | identified standard and URL-safe base64 alphabet constants, at locations consistent with the custom encoding table. |
| `ref:b99c135240` | disasm.function | entry 0x407017 instruction flow: __libc_start_main(main=0x4027EE). |
| `ref:3a1200a943` | disasm.function | main 0x4027EE disassembly: --libbase-run dispatch, libbase.sh installation, ssh-session-gate, SSH_ORIGINAL_COMMAND/SSH_TTY, sftp/rsync/scp wrapping, IP probing and '16' process cleanup. |
| `ref:bf524934c6` | evidence.record | custom script: confirms the sample truncation (1,703,936 vs 3,325,013), the embedded ELF second stage (0x1634B8, entry 0xC1F400), and XOR 0x5A recovery of the two C2 IPs, project0[.]cc and the 96-character token. |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
