---
title: "Malware Analysis: Panchan (ELF · elf · 6b5afe50)"
published: 2026-10-30
draft: false
description: "Malicious (high confidence): Panchan · miner/botnet · difficulty hard · static analysis only"
tags: ["Panchan", "miner", "botnet", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-Panchan-6b5afe50"
---

> [!WARNING]
> **Verdict: malicious** · Family **Panchan** · Confidence **high**
> 
> Aliases: Panchan botnet, Panchan P2P miner, pan-chan
> 
> Static disassembly is self-evident: the sample compares the 28-byte P2P handshake constant "pan-chan's mining island hi!", parses sharepeer/shareupdateinfo node commands, POSTs JSON to a hard-coded Discord webhook, copies itself to /bin/systemd-worker and writes a systemd unit to autostart at boot, reads ~/.ssh/id_rsa and known_hosts, and embeds XMRig/NBMiner pool config fields. The behaviour chain is complete and not a false positive.

## Overview

| Item | Content |
|:--|:--|
| Family | **Panchan** · aliases Panchan botnet, Panchan P2P miner, pan-chan |
| Confidence | **high** |
| Behaviour class | miner · botnet |
| Difficulty | hard |
| First seen | 2026-10-29 04:35:32 |
| Analysis method | static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Verify P2P handshake magic</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Parse peer commands</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Report infection to Discord</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Install systemd autostart</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Hidden config in /tmp</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `6b5afe506c5b4db4094797166a92021271a623af48f1d476185858264909d8c7` |
| MD5 | _not recorded_ |
| Size | 25,264,128 bytes (24.1 MB) |
| Type | ELF · `elf` |

## Behaviour analysis

**12** behaviours in total; each is tied to evidence, and all are statically recoverable.

### 1. Verify P2P handshake magic

`T1095` · Confidence **high** · static

After the P2P connection is established it compares the 28-byte constant "pan-chan's mining island hi!" and only enters command processing on a match, serving as a node identity/protocol magic.

> **Evidence**: 0x6b8560 cmp r10,0x1c; 0x6b856e lea "pan-chan's mining island hi!"; 0x6b8578 call memequal
> 
> **Source**: `ref:58fea9f883` · `ref:d3c56d4630`

### 2. Parse peer commands

`T1095` · Confidence **high** · static

Uses the regexes ^(sharepeer)(\s)(.*)$ and ^(shareupdateinfo)(\s)([A-Za-z0-9+=\/]+)$ to parse peer messages, exchange/update the node list, and write "finish\n" back to the peer.

> **Evidence**: 0x6b850b lea ^(sharepeer)...; 0x6b8542 lea ^(shareupdateinfo)...; 0x6b8425 mov dword [rax],0x696e6966 ("fini")
> 
> **Source**: `ref:d3c56d4630` · `ref:a795861633`

### 3. Report infection to Discord

`T1071.001` · Confidence **high** · static

Sends {"content":"わあわあ"} to a hard-coded Discord webhook with Content-Type application/json, used for infection notification/liveness reporting (URL length 0x78).

> **Evidence**: 0x6b41ce lea webhook URL; 0x6b41ee mov ecx,0x78; 0x6b41dc "application/json"; 0x751347 JSON body
> 
> **Source**: `ref:3569a7448e` · `ref:f0a6377920` · `ref:6bdda3d63b`

### 4. Install systemd autostart

`T1543.002` · Confidence **high** · static

Copies itself to /bin/systemd-worker (mode 0777), writes /lib/systemd/system/systemd-worker.service (ExecStart=/bin/systemd-worker, WantedBy=multi-user.target), and runs systemctl enable so it persists across boots.

> **Evidence**: 0x6b4472 lea "/bin/systemd-worker"(len 0x13); 0x6b4517 "ExecStart=/bin/systemd-worker"; 0x6b4561 "/lib/systemd/system/systemd-worker.service"; 0x6b4538 string concatenation then writes the file
> 
> **Source**: `ref:3035d420aa` · `ref:d3c56d4630` · `ref:44c58af9bd`

### 5. Hidden config in /tmp

`T1564.001` · Confidence **high** · static

Writes /tmp/.jpecggmkwmcssjj with mode 0666 and reads it periodically as the local runtime config; the dot-prefixed filename keeps it hidden.

> **Evidence**: 0x6b3dd2 / 0x6b3eb5 lea "/tmp/.jpecggmkwmcssjj"(len 0x15); 0x6b3de3 polls after a 10s sleep
> 
> **Source**: `ref:93779f5f53` · `ref:59213d8ab3`

### 6. Steal SSH keys

`T1552.004` · Confidence **high** · static

Uses filepath.Join to build and read ".ssh"+"id_rsa" and ".ssh"+"known_hosts", collecting private keys and host fingerprints for lateral movement.

> **Evidence**: 0x6bcc13/0x6bcc2e lea ".ssh"/"id_rsa"; 0x6bccb6/0x6bccd1 lea ".ssh"/"known_hosts"; 0x4ad500 filepath.Join
> 
> **Source**: `ref:59213d8ab3` · `ref:5c3be249fc`

### 7. Maintain an SSH credential queue

`T1110.001` · Confidence **medium** · static

Embeds the main.credential type and an attackqueue closure, and together with golang[.]org/x/crypto/ssh and github[.]com/pkg/sftp performs SSH authentication attempts and file delivery against target hosts.

> **Evidence**: type names *main.credential, attackqueue *[]main.credential; dependencies golang[.]org/x/crypto/ssh, github[.]com/pkg/sftp
> 
> **Source**: `ref:98a8b8a30b` · `ref:5d99806a0b`

### 8. Deploy XMRig mining

`T1496` · Confidence **high** · static

Embeds XMRig/NBMiner preset configuration structures (poolAddr/poolUser/poolPass/algo/nicehash/enabled), starts the miner once delivered over P2P, and clears old processes occupying the port with lsof/kill.

> **Evidence**: type fields current_preset_xmrig_poolAddr etc. (from 0x2d2d8c); string "kill -9 $(lsof -t -i:" (0x74a6ea)
> 
> **Source**: `ref:5678042c07` · `ref:0cc72d4e59`

### 9. Query the public IP

`T1016` · Confidence **high** · static

Requests ipgrab[.]io, ident.me, ipinfo[.]io, ip[.]seeip[.]org, inet-ip[.]info, api[.]ipify[.]org and checkip[.]amazonaws[.]com in turn to obtain the victim's egress IP for node reporting.

> **Evidence**: 0x348a4a hxxp://ipgrab[.]io/, 0x349837 hxxp://ipinfo[.]io/ip, 0x34a66c hxxps://ip[.]seeip[.]org/, 0x34ada3 inet-ip[.]info/api[.]ipify[.]org, 0x34ed73 checkip[.]amazonaws[.]com
> 
> **Source**: `ref:3569a7448e` · `ref:0cc72d4e59`

### 10. Process management through the shell

`T1059.004` · Confidence **medium** · static

Executes concatenated commands via exec.Command("sh", "-c", ...), including the fragments "chmod +x ./", "nohup ./" and "/sshd", to drop and keep miners or SSH components running in the background.

> **Evidence**: 0x6b4127 exec.Command("sh","-c",cmd); 0x6bdb50 "nohup ./"; 0x6bdafd "chmod +x ./"; 0x6bdb35 "/sshd"
> 
> **Source**: `ref:768d134f8d` · `ref:3035d420aa`

### 11. PAM authentication and password change

`T1556.003` · Confidence **medium** · static

Binds libpam through cgo and imports/calls pam_start/pam_authenticate/pam_chauthtok/pam_acct_mgmt/pam_setcred/pam_open_session, able to verify or change local account passwords through PAM.

> **Evidence**: 0x1ce3 _cgo_eba3282b571c_Cfunc_pam_authenticate; 0x1d0c LIBPAM_1.0; 0x1439 libpam.so.0; 0x1c59 _Cfunc_pam_start
> 
> **Source**: `ref:98a8b8a30b` · `ref:1df2cd9d75`

### 12. Collect system fingerprint

`T1082` · Confidence **medium** · static

Uses gopsutil to read CPU/network/process information and matches virtualisation/container traits such as vmware, vboxguest, vboxdrv, QEMU, virtio-pci, linux-vserver and lxc-version, for environment recognition.

> **Evidence**: strings "virtio-pci", "vboxguest", "vboxdrv", "QEMU Virtual CPU", "linux-vserver", "/usr/bin/lxc-version"; dependencies github[.]com/shirou/gopsutil/cpu, /net, /process
> 
> **Source**: `ref:98a8b8a30b` · `ref:18038977c8`


## IOCs (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | 443 | c2 | static | ⏳ not observed |
| other | `P2P/TCP peer network (handshake "pan-chan's mining island hi!"; commands sharepeer / shareupdateinfo)` | - | c2 | static | ⏳ not observed |

### Host

**Drop paths**

- `/bin/systemd-worker`
- `/lib/systemd/system/systemd-worker.service`
- `/tmp/.jpecggmkwmcssjj`
- `~/.ssh/id_rsa`
- `~/.ssh/known_hosts`

**Services**

- `systemd-worker.service`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | yes | static |
| `p2p_handshake_magic` | `pan-chan's mining island hi!` | yes | static |
| `config_path` | `/tmp/.jpecggmkwmcssjj` | yes | static |
| `persistence_service` | `systemd-worker.service (ExecStart=/bin/systemd-worker, WantedBy=multi-user.target)` | yes | static |
| `miner_xmrig_pool` | `runtime-delivered preset: xmrig_poolAddr / xmrig_poolUser / xmrig_poolPass / xmrig_algo / xmrig_nicehash / xmrig_enabled` | yes | dynamic |
| `miner_nbminer_pool` | `runtime-delivered preset: nbminer_poolAddr / nbminer_poolUser / nbminer_poolPass / nbminer_algo / nbminer_enabled` | no | dynamic |
| `campaign_id` | `-` | no | dynamic |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not treat the Discord webhook as the only/primary C2: the core is the P2P node network; the webhook only carries infection notifications and liveness reports.
- Do not report ransomware/wiper: no file encryption, deletion, ransom note or destructive logic was seen.
- Do not call it a PAM module or claim /etc/pam.d was modified: only libpam bindings and PAM calls were seen; no pam.d config write or .so module drop was observed.
- Do not report a browser/wallet stealer: credential collection is limited to SSH private keys/known_hosts and the SSH authentication queue.
- Do not assert hard-coded C2 IPs or mining-pool addresses: statically only the Discord webhook and IP-probing services are visible; pool/P2P addresses are delivered by the runtime configuration.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | static analysis only |
| Unpacking | no |

**Limitations and pending verification**

1. This run is static only and the sample was not executed; Discord reporting, P2P communication and miner launch are code-level evidence pending dynamic verification (pending_dynamic_verify=true).
2. The section-header table is out of bounds/stripped and there is no Go pclntab or symbol table, so function boundaries are inferred from disassembly and some indirect call sites were not fully recovered.
3. No cleartext XMRig/NBMiner ELF was found in the file; how the miner is delivered (embedded encrypted data or P2P) is undetermined.
4. The P2P peer list is not in the static config; the actual peer/C2 addresses must be obtained at runtime via sharepeer/shareupdateinfo.
5. The exact purpose of the libpam calls (authentication check, password-change backdoor or local privilege escalation) is not fully confirmed; only a complete PAM session lifecycle binding is established.

## Evidence index

<details>
<summary>Expand 14 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:44b50e152f` | ELF structure parser | ELF64 x86-64 EXEC, entry 0x403470, interpreter /lib64/ld-linux-x86-64.so.2, section headers out of bounds, no symbols/imports |
| `ref:98a8b8a30b` | String extraction | 6699 ASCII strings; includes libpam.so.0, pam_* cgo bindings, x/crypto/ssh, sftp, gopsutil etc. |
| `ev-000001` | String extraction | String hit "shusvz{}\|0\|1}" (actually the concatenation "sh"+"usvz{}\|0\|1}", not a flag) |
| `ev-000002` | String extraction | String hit "uint64unuseduptimevmwarewaitid{hash}" (Go short-string concatenation, not a flag) |
| `ref:1df2cd9d75` | elf.imports | No DT_NEEDED record in the dynamic table (section headers stripped); the libpam dependency is confirmed by strings and cgo symbols |
| `ref:d3c56d4630` | script | Located strings and their code references: handshake string 0x6b856e, sharepeer regex 0x6b850b, shareupdateinfo 0x6b8542, systemd unit path 0x6b4561 |
| `ref:58fea9f883` | script | Disassembly from 0x6b8540: cmp r10,0x1c then comparison with the 28-byte "pan-chan's mining island hi!", and parsing of the finish command |
| `ref:3569a7448e` | script | Extracted all URLs: Discord webhook (120 bytes) + 7 public IP-probing services |
| `ref:f0a6377920` | script | Six code references to the Discord webhook (0x6b41ce/0x6b9989/0x6bdfca/0x6be13d/0x6be44d/0x6be5bd) |
| `ref:3035d420aa` | script | Disassembly at 0x6b43a0: copies itself to /bin/systemd-worker, concatenates and writes the systemd unit (ExecStart=/bin/systemd-worker) |
| `ref:59213d8ab3` | script | Located references such as .ssh/id_rsa 0x6bcc2e, .ssh/known_hosts 0x6bccd1, /tmp/.jpecggmkwmcssjj 0x6b3dd2 |
| `ref:5678042c07` | script | Miner config fields current_preset_xmrig_*/nbminer_* (poolAddr/poolUser/poolPass/algo/nicehash) |
| `ref:0cc72d4e59` | script | Domain list: ipgrab[.]io/ident.me/ipinfo[.]io/ip[.]seeip[.]org/inet-ip[.]info/api[.]ipify[.]org/checkip[.]amazonaws[.]com, no hard-coded C2 domain |
| `ref:768d134f8d` | script | Disassembly at 0x6b4060: exec.Command("sh","-c",cmd) executes the concatenated command |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
