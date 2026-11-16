---
title: "Malware Analysis: Go SSH/PAM Mining Botnet (systemd-worker) (ELF · elf · 11707e39)"
published: 2026-11-15
draft: false
description: "Malicious (medium confidence): Go SSH/PAM mining botnet (systemd-worker) · botnet/miner/backdoor · difficulty hard · purely static analysis"
tags: ["语言 SSH", "botnet", "miner", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-Go-语言-SSH-PAM-挖矿僵尸网络-systemd-worker-11707e39"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Go SSH/PAM mining botnet (systemd-worker)** (uncertain) · Confidence **Medium**
> 
> Aliases: systemd-worker miner bot, Go P2P miner bot
> 
> The sample is an x86-64 ELF written in Go and linked against libpam. Direct forensic evidence in the binary includes: a Discord webhook exfiltration address and the {"content":...} payload format, systemd service self-installation (/bin/systemd-worker, /lib/systemd/system/systemd-worker.service, systemctl enable systemd-worker.service), an SSH/PAM remote-login service on 0.0.0[.]0:22, XMRig/NBMiner pool preset fields, an attackqueue credential queue, P2P commands sharepeer/sharerigconfig/shareupdateinfo, plus virtualization-environment detection and public egress-IP probing. These capabilities combined have no legitimate use. The C2 peers and mining-pool addresses are delivered at runtime, and no successful emulation was obtained, so dynamic behavior was not observed and all conclusions come from static decompilation and byte-level forensics.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Go SSH/PAM mining botnet (systemd-worker)** · aliases systemd-worker miner bot, Go P2P miner bot · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | botnet · miner · backdoor |
| Difficulty | hard |
| First seen | 2026-11-12 16:54:03 |
| Analysis method | Purely static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/11707e3902992c8e20e19de09cbc78381e43234c4560a706a031fe01ce7e96fb/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Install as system service</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Expose SSH backdoor</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1133</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Collect SSH credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1078</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Brute-force SSH laterally</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1110.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Share peer configuration</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `11707e3902992c8e20e19de09cbc78381e43234c4560a706a031fe01ce7e96fb` |
| MD5 | _not recorded_ |
| Size | 3,637,248 bytes (3.5 MB) |
| Type | ELF · `elf` |

## Behavior Analysis

**11** behaviors in total, each backed by evidence, and all are statically available.

### 1. Install as a system service

`T1543.002` · Confidence **High** · Static

Drops itself as /bin/systemd-worker, writes /lib/systemd/system/systemd-worker.service (ExecStart=/bin/systemd-worker, WantedBy=multi-user.target), and runs systemctl enable systemd-worker.service to autostart at boot and stay resident.

> **Evidence**: File offset 0x349473 literal /bin/systemd-worker; 0x35410a literal /lib/systemd/system/systemd-worker.service; 0x34e26e contains ExecStart=/bin/systemd-worker; 0x35219d contains [Install] WantedBy=multi-user.target; 0x359590 contains service systemd-worker enable || systemctl enable systemd-worker.service
> 
> **Source**: `ref:fb062e220c` · `ref:e500dc17ff`

### 2. Expose an SSH backdoor

`T1133` · Confidence **High** · Static

Listens for SSH on 0.0.0[.]0:22, reads /etc/ssh/ssh_host_rsa_key, ssh_host_ecdsa_key and ssh_host_ed25519_key as host keys, calls libpam's pam_authenticate for system password authentication, and supports PTY and SFTP sessions, effectively keeping a long-term login entry on the victim host.

> **Evidence**: 0x345fb5 literal 0.0.0[.]0:22 (VA 0x745fb5); import table 0x1439 libpam.so.0 and 0x1ce3 _cgo_eba3282b571c_Cfunc_pam_authenticate; 0x34c215/0x34d0f1/0x34e225 SSH host-key paths; type table 0x2c6135 *pam.Style and RequestPty
> 
> **Source**: `ref:0339085ba8` · `ref:3abe169092` · `ev-000003`

### 3. Collect SSH credentials

`T1078` · Confidence **High** · Static

Defines a credential structure and an attackqueue with fields ip, username, password, privatekey, queuing successfully logged-in or captured SSH hosts, accounts, passwords and private keys for later lateral reuse.

> **Evidence**: 0x2d7473 type metadata '*struct { F uintptr; attackqueue *[]main.credential }'; 0x2ed41f closure structure '{ privatekey string; username string; ip string; password string }'; 0x2cd369 '*main._rig_config'
> 
> **Source**: `ref:82600ab013` · `ref:fb062e220c` · `ref:28a2c2a72c`

### 4. Brute-force SSH laterally

`T1110.001` · Confidence **Medium** · Static

Embeds username and weak-password candidates such as admin/root/passwd/qwerty/123456/a123456/ubuntu/centos, with SSH client, known_hosts and id_rsa handling logic, trying to log in to each reachable SSH service and feeding successful credentials back into attackqueue.

> **Evidence**: 0x3444a0-0x344604 short-string region contains admin, passwd, qwerty, root, id_rsa, known_hosts, a123456, ubuntu, centos and others; 0x3533e3 'username/password authentication failed'; 0x2c6d4d privatekey field name
> 
> **Source**: `ref:fb062e220c` · `ref:64820a9cf0` · `ref:e500dc17ff`

### 5. Share peer configuration

`T1071` · Confidence **High** · Static

Parses control commands with the three regexes ^(sharepeer)(\s)(.*)$, ^(sharerigconfig)(\s)([A-Za-z0-9+=\/]+)$ and ^(shareupdateinfo)(\s)([A-Za-z0-9+=\/]+)$, sharing peer information, miner configuration and update information among nodes to form a decentralized control plane.

> **Evidence**: 0x35357f regex ^(sharerigconfig)...; 0x353c14 regex ^(shareupdateinfo)...; 0x34a491 regex ^(sharepeer)(\s)(.*)$
> 
> **Source**: `ref:47ce4eadd7` · `ref:fb062e220c`

### 6. Deliver miner and mine

`T1496` · Confidence **High** · Static

The configuration structure contains xmrig/nbminer enabled, nicehash, algo, poolAddr, poolUser and poolPass fields plus downloadURL and checksum, used to download and start the miner and connect to a pool to consume the victim host's CPU power.

> **Evidence**: 0x2d5825 json tags Xmrig_nicehash/Xmrig_poolAddr/Xmrig_poolPass/Xmrig_poolUser; 0x2d6099 Nbminer_poolAddr/Nbminer_poolPass; 0x2d474f DownloadURL json:"downloadURL", Checksum json:"checksum"; 0x2d43b5 current_preset_xmrig_poolAddr
> 
> **Source**: `ref:99381340aa` · `ref:47ce4eadd7`

### 7. Discord data exfiltration

`T1567.002` · Confidence **High** · Static

Embeds a Discord webhook URL and builds HTTP request bodies in the '{"content": "..."}' form, submitting victim host information and exfiltrated content to discord[.]com/api/webhooks/<id>/<token>.

> **Evidence**: 0x35a713 literal hxxps://discord[.]com/api/webhooks/960954050583613549/YAk... (VA 0x75a713); 0x35134c payload format '{\n"content": "'
> 
> **Source**: `ref:df4258af15` · `ref:99381340aa`

### 8. Probe public egress IP

`T1016` · Confidence **High** · Static

Sequentially requests external echo services hxxp://ipgrab[.]io/, hxxps://ident[.]me/, hxxp://ipinfo[.]io/ip, hxxps://api[.]ipify[.]org, hxxp://inet-ip[.]info/ip, hxxps://checkip[.]amazonaws[.]com, hxxps://ip[.]seeip[.]org/ and others to obtain the egress IP, used for reporting, deduplication and node discovery.

> **Evidence**: 0x348a51 hxxp://ipgrab[.]io/ and hxxps://ident[.]me/; 0x349837 hxxp://ipinfo[.]io/ip; 0x34a66c hxxps://ip[.]seeip[.]org/; 0x34ada3 hxxp://inet-ip[.]info/ip and hxxps://api[.]ipify[.]org; 0x34ed73 hxxps://checkip[.]amazonaws[.]com
> 
> **Source**: `ref:23e0fbad7d` · `ref:fb062e220c`

### 9. Detect virtualization environment

`T1497.001` · Confidence **Medium** · Static

Embeds detection clues such as vmware, vboxdrv, vboxguest, qemu, xen, kvm, openvz, docker, lxc, virtio-pci and /proc/self/status to determine whether it is running in a VM or container, so as to change behavior or evade the analysis environment.

> **Evidence**: Literals vmware/virtualbox near 0x344ed8; 0x345379 vboxdrv/vboxguest; 0x345932 /dev/ptmx, /dev/pts/0; 0x346433 virtio-pci; 0xac0f8 /etc/loc… (locale path fragment)
> 
> **Source**: `ref:fb062e220c` · `ref:64820a9cf0`

### 10. Terminate competing miner processes

`T1489` · Confidence **Medium** · Static

Builds shell commands such as kill -9 $(lsof -t -i:<port>), using os/exec to terminate competing processes occupying the target port or resources, clearing the way for its own miner and backdoor.

> **Evidence**: 0x34a6f4 literal kill -9 $(lsof -t -i:; 0x2c34ec os/exec package name; 0x3467f3 chmod +x ./; 0x345192 nohup ./p
> 
> **Source**: `ref:fb062e220c` · `ref:64820a9cf0`

### 11. Stash in a hidden temp directory

`T1074.001` · Confidence **High** · Static

Uses the dot-prefixed /tmp/.jpec as a temporary working directory to stage components and intermediate files, reducing the chance of manual discovery under /tmp.

> **Evidence**: 0x34a3e1 literal /tmp/.jpec (starting at 0x34a3e7); the same string region contains chmod +x ./ and nohup ./p
> 
> **Source**: `ref:e500dc17ff` · `ref:fb062e220c`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | 443 | exfil | Static | ⏳ Not observed |
| other | `P2P peer control channel (sharepeer / sharerigconfig / shareupdateinfo commands; node addresses delivered at runtime, no fixed endpoint in the sample)` | - | c2 | Static | ⏳ Not observed |

### Host

**Dropped paths**

- `/bin/systemd-worker`
- `/lib/systemd/system/systemd-worker.service`
- `/tmp/.jpec`
- `/etc/ssh/ssh_host_rsa_key`
- `/etc/ssh/ssh_host_ecdsa_key`
- `/etc/ssh/ssh_host_ed25519_key`

**Services**

- `systemd-worker`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `exfil_webhook` | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | Yes | Static |
| `exfil_payload_format` | `{"content": "..."} (Discord webhook text payload, see literal '{\n"content": "')` | Yes | Static |
| `c2_hosts` | `P2P peers; exchanges peer, miner configuration and update information via sharepeer/sharerigconfig/shareupdateinfo commands, addresses delivered at runtime` | Yes | Static |
| `remote_access_listen` | `0.0.0[.]0:22` | Yes | Static |
| `install_path` | `/bin/systemd-worker` | Yes | Static |
| `service_unit_path` | `/lib/systemd/system/systemd-worker.service` | Yes | Static |
| `service_name` | `systemd-worker` | Yes | Static |
| `work_dir` | `/tmp/.jpec` | No | Static |
| `miner_presets` | `xmrig_{enabled,nicehash,algo,poolAddr,poolUser,poolPass} and nbminer_{enabled,algo,poolAddr,poolUser,poolPass}` | Yes | Static |
| `update` | `downloadURL + checksum (update payload download address and checksum delivered at runtime)` | No | Static |
| `credential_queue` | `attackqueue: {ip, username, password, privatekey}` | Yes | Static |
| `encryption_algo` | `no custom encryption; only standard base64/base36 encoding and SSH built-in encryption (no custom AES constants or ransomware encryption logic seen)` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not conclude from the crypto/aes package and base64 constants that the sample encrypts files or configuration for extortion: it uses only the standard library's SSH encryption and base64/base36 encoding, with no ransomware file operations or custom AES implementation.
- Do not treat the embedded Discord webhook as the only command channel: it handles exfiltration/reporting, while the command surface is runtime P2P configuration (sharepeer/sharerigconfig/shareupdateinfo); there is no fixed C2 host in the sample.
- Do not assert from /bin/systemd-worker and 0.0.0[.]0:22 alone that a service was created or a port is already listening on the victim host: static analysis only proves the code has that capability, and no runtime behavior was obtained in this run.
- Do not treat the 88-character base64 string near the file header (TegskTGfBzL5...) as a hardcoded key: it decodes to the Go build ID (.note.go.buildid).
- Do not assert the sample has actually mined or communicated with a pool: the pool address, downloadURL and checksum are all delivered at runtime, and there is no plaintext mining-pool endpoint in the sample.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Purely static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. File truncation leaves the capability surface incomplete: e_shoff=0x1ce6018 is out of bounds, the section count is 35 but the section table is missing; the read-only segment claims 27 MB while only about 0.75 MB is readable, the write segment and DYNAMIC are missing, and the symbol table is empty, so the complete import table and function boundaries cannot be recovered.
2. No real dynamic evidence: per the analysis rules the ELF was not executed on a real machine; emulated execution returned an empty result and no runtime behavior was observed, so c2/config are all marked recoverability=static with pending_dynamic_verify=true.
3. Family attribution is uncertain: lacking multi-engine, YARA or public-report cross-validation, the family name is a candidate based on capabilities and internal naming (uncertain=true) and does not represent an existing vendor naming.
4. The concrete values of the miner binary, pool address and downloadURL/checksum are unavailable: only configuration fields and delivery logic were seen, and the actual payload was not supplied with the sample.
5. The 'shusvz{}|0|1}' and 'uint64unuseduptimevmwarewaitid{hash}' string-scan hits are Go short-string concatenation artifacts, not real flags or credentials.
6. The mutex/registry/tasks fields in host artifacts are empty because this is a Linux ELF and was not executed; this cannot rule out mutexes or cron behavior at runtime.
7. The purpose of the string 'Please type "I am human" to prove that you are human:' cannot be statically confirmed and was not counted in the behavior conclusions.

## Evidence Index

<details>
<summary>Expand 20 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Flag-shape hit shusvz{}\|0\|1} @0x3443d8, verified as a Go short-string concatenation artifact |
| `ev-000002` | String extraction | Flag-shape hit uint64unuseduptimevmwarewaitid{hash} @0x344f86, a Go string-table concatenation artifact |
| `ev-000003` | String extraction | Extracted 9,624 ASCII strings; confirmed libpam/libpthread/libc imports and PAM, pthread-related symbols |
| `ev-000004` | Cryptographic constant identification | CRC32 IEEE constant @0x1e82d4 |
| `ev-000005` | Cryptographic constant identification | Standard base64 alphabet @0x358b7a |
| `ev-000006` | Cryptographic constant identification | URL-safe base64 alphabet @0x358bba; no custom AES/SHA implementation constants found |
| `ref:4d83efb0e8` | ELF structure parsing | ELF64 x86-64 EXEC, entry RVA 13424/VA 4207728, links libpam.so.0 and libc.so.6, 12 program headers, section table out of bounds |
| `ref:3abe169092` | decompile.symbols | Symbols stripped, only 909 anonymous functions (FUN_*) recovered; libpam/PAM-related cgo symbols visible |
| `ref:97128bc087` | Custom string extraction | Go dependency paths: github[.]com/msteinert/pam, github[.]com/pkg/sftp, github[.]com/shirou/gopsutil/{cpu,net,process}, golang[.]org/x/crypto/ssh, golang[.]org/x/term |
| `ref:28a2c2a72c` | Custom string extraction | Main package type names main._rig_config, main._update, main.credential |
| `ref:82600ab013` | Custom string extraction | Type metadata attackqueue *[]main.credential, and closure fields privatekey/username/ip/password |
| `ref:64820a9cf0` | Custom string extraction | Import symbol strings (libpam, pam_*, os/exec, ssh, password, sftp) and keyword context |
| `ref:fb062e220c` | Custom string extraction | Literals after 0x2e0000: /bin/systemd-worker, systemd unit, /tmp/.jpec, kill -9 $(lsof -t -i:, vmware/vbox, weak-password dictionary, chmod +x/nohup |
| `ref:23e0fbad7d` | Custom string extraction | URLs and domains: ipgrab[.]io, ident[.]me, ipinfo[.]io, ipify[.]org, inet-ip[.]info, seeip[.]org, checkip[.]amazonaws[.]com |
| `ref:99381340aa` | Custom string extraction | 46 JSON tags (xmrig_*/nbminer_*/downloadURL/checksum and others) and the Discord webhook literal |
| `ref:47ce4eadd7` | Custom string extraction | sharepeer/sharerigconfig/shareupdateinfo regexes and attack-queue/rig configuration context |
| `ref:e500dc17ff` | Custom string extraction | 0.0.0[.]0:22, SSH host-key paths, systemd unit tail, /tmp/.jpec, short-password dictionary and 'I am human' prompt string |
| `ref:df4258af15` | addr.translate | Discord webhook literal off 0x35a713 → RVA 0x35a713 / VA 0x75a713 |
| `ref:0339085ba8` | addr.translate | 0.0.0[.]0:22 literal off 0x345fb5 → RVA 0x345fb5 / VA 0x745fb5 |
| `ref:957e447114` | Custom header parsing | The 88-character base64 in .note.go.buildid decodes to a Go build ID; e_shnum=35 and e_shoff out of bounds confirm file truncation |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
