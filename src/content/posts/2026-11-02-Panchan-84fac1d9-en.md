---
title: "Malware Analysis: Panchan (ELF · elf · 84fac1d9)"
published: 2026-11-02
draft: false
description: "Malicious (medium confidence): Panchan · backdoor/miner/botnet · difficulty medium · static analysis only"
tags: ["Panchan", "backdoor", "miner", "botnet", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-02-Panchan-84fac1d9"
---

> [!WARNING]
> **Verdict: malicious** · Family **Panchan** · Confidence **medium**
> 
> Aliases: Pan-chan, Golang P2P SSH miner worm
> 
> Static reverse engineering directly recovered the complete attack chain: the ELF is a Go/cgo program linking libpam, listening on 0.0.0[.]0:22 and loading /etc/ssh/ssh_host_*_key to provide an SSH service; it handles login credentials through PAM callbacks and main.credential; writes /lib/systemd/system/systemd-worker.service and runs systemctl enable; exfiltrates data to a Discord webhook; and embeds XMRig/NBMiner mining-pool configuration fields. These are not vendor labels or heuristic guesses but functions directly verifiable through code cross-references and string/type metadata.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Panchan** · Aliases Pan-chan, Golang P2P SSH miner worm |
| Confidence | **Medium** |
| Behavior classes | backdoor · miner · botnet |
| Difficulty | medium |
| First seen | 2026-11-02 09:00:11 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/84fac1d9c9d83182fa6428365907f7fbeb4c621eb7eb2b2a0140fdcd245b20e9/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">SSH backdoor on port 22</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1021.004</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Harvest logins via PAM</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Persist via systemd unit</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as systemd worker</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Read SSH host private keys</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1552.004</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `84fac1d9c9d83182fa6428365907f7fbeb4c621eb7eb2b2a0140fdcd245b20e9` |
| MD5 | _not recorded_ |
| Size | 8,290,304 bytes (7.9 MB) |
| Type | ELF · `elf` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all are obtainable statically.

### 1. SSH backdoor on port 22

`T1021.004` · Confidence **High** · Static

The program loads the string 0.0.0[.]0:22 at 0x6b95bb and enters the listen/session-handling path; 0x6b94d7, 0x6b94f2, and 0x6b950d load /etc/ssh/ssh_host_ecdsa_key, /etc/ssh/ssh_host_ed25519_key, and /etc/ssh/ssh_host_rsa_key as server host keys. Together with golang[.]org/x/crypto/ssh ServerConfig/PasswordCallback and the github[.]com/msteinert/pam binding, this forms a login-capable SSH server.

> **Evidence**: 0x6b95bb lea rcx, [rip+...] -> '0.0.0[.]0:22'; 0x6b94d7/0x6b94f2/0x6b950d -> /etc/ssh/ssh_host_*_key; libpam.so.0 + ssh.ServerConfig
> 
> **Source**: `ev-000007` · `ev-000008` · `ref:f4d4fb4d6c`

### 2. Harvest logins via PAM

`T1056.001` · Confidence **Medium** · Static

Dynamic dependencies include libpam.so.0; the binary has cgo symbols for pam_start/pam_authenticate/pam_acct_mgmt/pam_open_session/pam_close_session/pam_setcred, plus *pam.Transaction, PasswordCallback, and *main.credential types. The PAM session callback captures login usernames/passwords into a Go struct, giving it credential-harvesting capability.

> **Evidence**: ELF dynstr: libpam.so.0; symbols _cgo_eba3282b571c_Cfunc_pam_authenticate/pam_start; types *pam.Transaction/*main.credential; field PasswordCallback
> 
> **Source**: `ev-000008` · `ref:f4d4fb4d6c`

### 3. Persist via systemd unit

`T1543.002` · Confidence **High** · Static

0x6b4517 loads ExecStart=/bin/systemd-worker, 0x6b4561 loads /lib/systemd/system/systemd-worker.service, and 0x6b45a3 loads 'service systemd-worker enable || systemctl enable systemd-worker.service', indicating that it writes a unit file and enables the service for boot-time autostart.

> **Evidence**: 0x6b4517 'ExecStart=/bin/systemd-worker'; 0x6b4561 '/lib/systemd/system/systemd-worker.service'; 0x6b45a3 'service systemd-worker enable || systemctl enable systemd-worker.service'
> 
> **Source**: `ev-000007` · `ref:f4d4fb4d6c`

### 4. Masquerade as systemd worker

`T1036.005` · Confidence **High** · Static

0x6b4472 loads /bin/systemd-worker; both the service name and the binary name use systemd-worker, deliberately imitating systemd worker-process naming to reduce the chance of an administrator noticing.

> **Evidence**: 0x6b4472 -> '/bin/systemd-worker'; service unit name systemd-worker
> 
> **Source**: `ev-000007`

### 5. Read SSH host private keys

`T1552.004` · Confidence **High** · Static

The code directly references the three host private-key paths /etc/ssh/ssh_host_rsa_key, /etc/ssh/ssh_host_ecdsa_key, and /etc/ssh/ssh_host_ed25519_key and uses them for the SSH server configuration; reading host private keys can be used to impersonate the local SSH identity or assist lateral movement.

> **Evidence**: 0x6b950d /etc/ssh/ssh_host_rsa_key; 0x6b94d7 ecdsa; 0x6b94f2 ed25519
> 
> **Source**: `ev-000007` · `ref:f4d4fb4d6c`

### 6. Exfiltrate data to Discord

`T1567` · Confidence **High** · Static

The string hxxps://discord[.]com/api/webhooks/960954050583613549/... is referenced at 0x6b41ce, 0x6b9989, 0x6bdfca, 0x6be13d, 0x6be44d, and 0x6be5bd; the associated functions assemble HTTP requests, forming an exfiltration/status-reporting channel.

> **Evidence**: 6 RIP-relative references to the Discord webhook string (0x6b41ce etc.); Go net/http request construction
> 
> **Source**: `ev-000007` · `ref:f4d4fb4d6c`

### 7. Query public IP and host information

`T1016, T1082` · Confidence **High** · Static

0x6bb9dd references hxxps://api[.]ipify[.]org, 0x6bba7f references hxxp://ipinfo[.]io/ip; the file also contains ip[.]seeip[.]org, inet-ip[.]info, and checkip[.]amazonaws[.]com. The gopsutil cpu/net/process packages are used to collect CPU, network-interface, and process information, forming a host fingerprint.

> **Evidence**: 0x6bb9dd hxxps://api[.]ipify[.]org; 0x6bba7f hxxp://ipinfo[.]io/ip; gopsutil cpu/net/process types and package paths
> 
> **Source**: `ev-000008` · `ev-000007`

### 8. Manage miner configuration

`T1496` · Confidence **High** · Static

Go struct JSON tags include xmrig_enabled/xmrig_nicehash/xmrig_algo/xmrig_poolAddr/xmrig_poolUser/xmrig_poolPass and same-named nbminer_* fields, loaded by type main._rig_config; globals current_preset_xmrig_* / current_preset_nbminer_* and the rigconfig string exist, indicating deployment/management of mining configuration.

> **Evidence**: type *main._rig_config; json:"xmrig_poolAddr" and 10 other fields; current_preset_xmrig_enabled/nbminer_enabled; 'rigconfig' @0x347fec
> 
> **Source**: `ev-000008` · `ref:f4d4fb4d6c`

### 9. Lateral spread via SFTP

`T1021.004, T1105` · Confidence **Medium** · Static

The type table includes *sftp.clientConn (github[.]com/pkg/sftp client), and 0x6bccd1 references known_hosts; the program has both SSH client and server capability and reads the local SSH host keys, giving it the conditions to authenticate to other hosts and transfer files.

> **Evidence**: type *sftp.clientConn; 0x6bccd1 -> 'known_hosts'; github[.]com/pkg/sftp package path; golang[.]org/x/crypto/ssh
> 
> **Source**: `ev-000008` · `ev-000007`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | 443 | exfil | Static | ⏳ Not observed |
| tcp | `0.0.0[.]0:22` | 22 | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `/bin/systemd-worker`
- `/lib/systemd/system/systemd-worker.service`
- `/etc/ssh/ssh_host_rsa_key`
- `/etc/ssh/ssh_host_ecdsa_key`
- `/etc/ssh/ssh_host_ed25519_key`

**Services**

- `systemd-worker`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | No | Static |
| `install_path` | `/bin/systemd-worker` | Yes | Static |
| `service_name` | `systemd-worker` | Yes | Static |
| `service_file` | `/lib/systemd/system/systemd-worker.service` | Yes | Static |
| `ssh_listen` | `0.0.0[.]0:22` | Yes | Static |
| `ssh_host_keys` | `/etc/ssh/ssh_host_rsa_key,/etc/ssh/ssh_host_ecdsa_key,/etc/ssh/ssh_host_ed25519_key` | Yes | Static |
| `miner_families` | `XMRig, NBMiner` | Yes | Static |
| `miner_config_fields` | `xmrig_enabled,xmrig_nicehash,xmrig_algo,xmrig_poolAddr,xmrig_poolUser,xmrig_poolPass;nbminer_enabled,nbminer_algo,nbminer_poolAddr,nbminer_poolUser,nbminer_poolPass` | Yes | Static |
| `external_ip_lookup` | `hxxps://api[.]ipify[.]org;hxxp://ipinfo[.]io/ip;hxxps://ip[.]seeip[.]org;hxxp://inet-ip[.]info/ip;hxxps://checkip[.]amazonaws[.]com/` | No | Static |
| `transport_crypto` | `Go TLS/SSH: chacha20-poly1305, AES-GCM, SHA-256, Ed25519; base64` | No | Static |
| `campaign_signature` | `pan-chan's mining island hi!` | No | Static |
| `rig_config_token` | `rigconfig` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not classify it as ransomware/a wiper: the sample has no file encryption, extension rewriting, or ransom-note logic; the AES/ChaCha20/SHA constants come from Go's TLS/SSH protocol stack.
- Do not classify it as browser-credential theft: no browser database, wallet, or cookie paths were found; the credential targets are system PAM/SSH.
- Do not treat the Discord webhook as the only C2 or download source: the sample has no hardcoded payload-download URL; the webhook is more like an exfiltration/reporting endpoint, and propagation relies on SSH/SFTP.
- Do not claim Windows registry or Windows service persistence: the sample is a Linux ELF and only uses systemd.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | No |

**Limitations and open questions**

1. This was static analysis only; the sample was neither run nor emulated, so actual network connections, PAM logins, and Discord reporting content were not observed.
2. The Discord webhook, the 0.0.0[.]0:22 listener, and the mining parameters are statically recovered with recoverability=static and pending_dynamic_verify=true, and need dynamic verification.
3. The ELF file is incomplete: e_shoff and the dynamic-segment offset exceed the actual file size, and some rodata/functions are unreachable; therefore the full Go function names cannot be enumerated or all configuration items confirmed.
4. Family attribution is based on embedded self-identifying strings and code features without external YARA/multi-engine cross-validation; the name follows the public family Panchan, medium confidence.
5. The actual mining-pool address, wallet address, or campaign_id were not recovered; these may be delivered remotely or stored in rigconfig and did not appear in this file.
6. The string '114514' exists in the data area but is not cross-referenced by any code, so it cannot be asserted to be a default password or backdoor key.

## Evidence index

<details>
<summary>Expand 6 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000003` | String extraction | 6,698 ASCII strings extracted, hitting libpam.so.0, cgo PAM symbols, custom miner fields, etc. |
| `ev-000004` | Crypto constant identification | CRC32 constant hit (Go runtime/hashing use). |
| `ev-000005` | Crypto constant identification | Standard base64 alphabet. |
| `ev-000006` | Crypto constant identification | URL-safe base64 alphabet. |
| `ev-000007` | evidence.record | Disassembly cross-references: SSH listener/host keys, systemd persistence, Discord webhook, public-IP lookups, known_hosts, and family-tag string addresses. |
| `ev-000008` | evidence.record | Go type/module metadata: main._update/credential/_rig_config, pam/sftp/gopsutil/ssh dependencies, XMRig/NBMiner JSON fields, and family tag string. |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
