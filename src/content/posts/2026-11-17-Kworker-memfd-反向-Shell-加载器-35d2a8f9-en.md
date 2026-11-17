---
title: "Malware sample analysis: Kworker memfd reverse shell loader (ELF · elf · 35d2a8f9)"
published: 2026-11-17
draft: false
description: "Malicious (confidence low): Kworker memfd reverse shell loader · backdoor/downloader/loader · difficulty easy · dynamic sandbox + static decompilation"
tags: ["Kworker memfd", "backdoor", "downloader", "loader", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-Kworker-memfd-反向-Shell-加载器-35d2a8f9"
---

> [!WARNING]
> **Verdict: malicious** · family **Kworker memfd reverse shell loader** (uncertain) · confidence **low**
> 
> Aliases: linux_amd64_tcp template reverse shell, memfd/fexecve fileless stager
> 
> Decompiled main reveals a complete reverse shell/fileless loading chain: it first uses access("/tmp/log_de.log") as a single-instance check, then loops connect to the hardcoded 149.30.247[.]60:8080, and on success sends "l64 "+port+a 32-byte host identifier, decrypts each received byte with XOR 0x99 and writes it into a memory file created by memfd_create, and finally executes that in-memory payload via fexecve with "[kworker/0:2]" as argv[0]. Real execution in an isolated environment observed the process repeatedly making TCP connections to 149.30.247[.]60:8080 (ENETUNREACH, retrying every 10 seconds), consistent with the static logic.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Kworker memfd reverse shell loader** · aliases linux_amd64_tcp template reverse shell, memfd/fexecve fileless stager · _uncertain_ |
| Confidence | **Low** |
| Behavior class | backdoor · downloader · loader |
| Difficulty | easy |
| First seen | 2026-11-16 00:11:57 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Check run marker</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Loop-connect to hardcoded C2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Send protocol handshake</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Create anonymous memory file</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">XOR-decrypt and write payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d` |
| MD5 | _not recorded_ |
| Size | 9,800 bytes (9.6 KB) |
| Type | ELF · `elf` |

## Behavior analysis

There are **7** behaviors in total, each backed by evidence, and all are statically obtainable.

### 1. Check run marker

`T1480` · confidence **high** · static

The main entry first calls access("/tmp/log_de.log", F_OK); if the file exists it exits immediately with exit(0), otherwise it continues, which limits repeat runs/avoids repeated analysis.

> **Evidence**: main @0x400950; 0x400967 call access, argument "/tmp/log_de.log" @0x400cd4; 0x400977 branch calls exit
> 
> **Source**: `ev-000001` · `ev-000002` · `ev-000008`

### 2. Loop-connect to hardcoded C2

`T1095` · confidence **high** · static

After resolving the built-in address 149.30.247[.]60 it fills in sockaddr_in (port 8080), sets the TCP SYN retransmission count to 10, loops connect, and on failure sleeps 10 seconds and retries indefinitely.

> **Evidence**: 0x400a1b call connect; 0x400a29 call sleep; socket option (6,7)=10; real run strace: connect(3,{AF_INET,htons(8080),149.30.247[.]60})=-1 ENETUNREACH
> 
> **Source**: `ev-000001` · `ev-000014` · `ev-000016`

### 3. Send protocol handshake

`T1095` · confidence **high** · static

After the connection is established it sends, in order, the 6 bytes "l64 ", the 2-byte port (0x1f90, i.e. 8080) and the 32-byte host identifier (a 32-byte copy of the IP string at 0x400d00), identifying the victim end to the server.

> **Evidence**: 0x400a3e send(...,"l64 ",6,0); 0x400a62 send port 0x901f; 0x400a75 send 32-byte host buffer
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Create anonymous memory file

`T1620` · confidence **high** · static

Through syscall 319 (memfd_create) it creates an anonymous executable memory file named "a" as the receiving vehicle for the remote payload, generating no file on disk.

> **Evidence**: 0x400a88 mov edi,0x13f; 0x400a8f call syscall; name "a" @0x400ceb
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. XOR-decrypt and write payload

`T1140` · confidence **high** · static

Each data block received by recv is XORed byte-by-byte with 0x99 and then written to the memfd, implementing simple streaming obfuscated transfer until the peer closes the connection.

> **Evidence**: 0x400aac call recv; 0x400abd xor byte ptr [rax],0x99; 0x400ad4 call write(memfd)
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Execute payload under a masqueraded process name

`T1036.005` · confidence **high** · static

After the connection ends it closes the socket, writes realpath(argv[0]) into the environment variable CWD, then executes the memfd via fexecve with argv[0] set to "[kworker/0:2]" to masquerade as a kernel worker thread.

> **Evidence**: 0x400af9 call realpath; 0x400b0f call setenv("CWD"); 0x400b37 call fexecve, argv first entry "[kworker/0:2]" @0x400cf1
> 
> **Source**: `ev-000001` · `ev-000002`

### 7. Fall back to literal address resolution

`T1095` · confidence **high** · static

For the built-in address it first calls gethostbyname and falls back to inet_addr when that returns empty, ensuring a connection address is obtained even when domain resolution is unavailable.

> **Evidence**: 0x4009ab call gethostbyname; 0x4009b6 call inet_addr; result written byte-wise into sockaddr_in
> 
> **Source**: `ev-000001`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above address was obtained from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's response and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `149[.]30[.]247[.]60:8080` | 8080 | c2 | static | ⏳ Not observed |

### Host

**Drop paths**

- `/tmp/log_de.log`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `149[.]30[.]247[.]60` | yes | static |
| `c2_port` | `8080` | yes | static |
| `c2_protocol_handshake` | `raw TCP; first packet is "l64 " (6 bytes) + 2-byte big-endian port + 32-byte host identifier` | yes | static |
| `payload_transport_encoding` | `byte-by-byte XOR 0x99` | yes | static |
| `exec_method` | `memfd_create("a") receives the payload, then fexecve executes it without touching disk` | yes | static |
| `argv0_masquerade` | `[kworker/0:2]` | yes | static |
| `single_instance_marker` | `/tmp/log_de.log (only checks whether it exists; continues only if it does not; no creation logic observed)` | yes | static |
| `campaign_id` | `-` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not call it ransomware or a miner: the sample contains no file encryption, key management or mining pool/mining logic; the only encoding operation is single-byte XOR 0x99.
- Do not claim 149.30.247[.]60 is a confirmed live C2: only ENETUNREACH connection attempts were observed in the isolated network, with no successful session or delivered content.
- Do not claim the sample created /tmp/log_de.log: decompilation shows it only checks whether the file exists and continues only when it does not.
- Do not claim the sample has persistence capability: no systemd, cron, rc.local or shell profile write logic was seen.
- Do not treat "[kworker/0:2]" as a real kernel thread: it is a forged argv[0] at fexecve time.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The isolated network was unreachable; only connect attempts (ENETUNREACH) and a 10-second retry loop were observed, with no server handshake response or stage-two payload obtained; the c2 is therefore treated as statically recoverable and marked for dynamic confirmation.
2. The sent content and the decrypted payload could not be captured from real traffic: the protocol fields ("l64 ", port, 32-byte host identifier, XOR 0x99) come from decompilation, not from a successful session.
3. Family attribution lacks vendor engine, signature or YARA corroboration; the current name is a candidate based on behavioral characteristics and is uncertain.
4. Execution was verified only in an x86-64 native environment; whether memfd + fexecve succeeds depends on the target kernel allowing anonymous memory files to be executable, and this was not verified on other kernels/architectures.

## Evidence index

<details>
<summary>Expand 4 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | decompile.function | Decompiled main @0x400950, recovering the full chain of access check, connect/send handshake, syscall(0x13f) memfd_create, XOR 0x99 write and fexecve("[kworker/0:2]") |
| `ev-000002` | String extraction | Extracted 135 ASCII strings, hitting /tmp/log_de.log, "l64 ", CWD, [kworker/0:2], 149.30.247[.]60, linux_amd64_tcp.c |
| `ev-000014` | dyn.trace.strace | strace on the hardened instance: after socket(AF_INET,SOCK_STREAM), connect to 149.30.247[.]60:8080 returns ENETUNREACH, retry loop |
| `ev-000016` | dyn.exec | Hardened WSL real run: process has no stdout, keeps retrying the C2 connection, terminated on timeout (exit=124) |

</details>

---

_The sample in this report is not public; IOCs have been defanged, for security research only._
