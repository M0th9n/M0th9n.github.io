---
title: "Malware Analysis: Chisel (ELF · elf · cca9accd)"
published: 2026-11-15
draft: false
description: "Gray/PUA (high confidence): Chisel · backdoor · difficulty easy · static decompilation (dynamic execution produced no runtime behavior)"
tags: ["Chisel", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-Chisel-cca9accd"
---

> [!CAUTION]
> **Verdict: Gray/PUA** · Family **Chisel** · Confidence **High**
> 
> Aliases: chisel, Hacktool.Chisel, Tunnel/Chisel, Backdoor.Linux.Chisel (vendor naming)
> 
> The sample is an unpacked, unobfuscated Go statically compiled program; its build information explicitly shows the source path github[.]com/jpillora/chisel (vcs.modified=false), and decompilation shows main.client / main.server / main.generatePidFile exactly matching the upstream command-line interface. Its function is a general TCP/UDP tunnel and SOCKS5 proxy (chisel), usable for reverse port forwarding, intranet pivoting and interactive channels, making it a typical dual-use hacking tool/riskware; no hardcoded server, key, persistence or credential-theft logic was found in the binary, so it is classified as a potentially unwanted application (hacking tool) rather than a configured attack payload.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Chisel** · aliases chisel, Hacktool.Chisel, Tunnel/Chisel, Backdoor.Linux.Chisel (vendor naming) |
| Confidence | **High** |
| Behavior class | backdoor |
| Difficulty | easy |
| First seen | 2026-11-14 07:01:26 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/cca9accd3c1554703ab11eb9c10b146d9d8a84ea165450003200de1ebbc2ac4c/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Dispatch by subcommand</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Set up reverse port tunnel</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1572</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Built-in SOCKS5 proxy</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1090</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Encrypted HTTP channel</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Password and key auth</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `cca9accd3c1554703ab11eb9c10b146d9d8a84ea165450003200de1ebbc2ac4c` |
| MD5 | _not recorded_ |
| Size | 8,654,848 bytes (8.3 MB) |
| Type | ELF · `elf` |

## Behavior Analysis

**7** behaviors in total, each backed by evidence, and all are statically available.

### 1. Dispatch by subcommand

`T1059` · Confidence **High** · Static

main.main reads the first command-line argument: "client" enters client mode, "server" enters server mode; with no argument or an unknown subcommand it only prints help and exits, with no hidden automatic-execution branch.

> **Evidence**: main.main @ VA 0x7EA5A0 (RVA 0x3EA5A0) compares 0x65696C63/0x746E and 0x76726573/0x7265 then calls main.client/main.server; otherwise fmt.Fprint help and os.Exit(0)
> 
> **Source**: `ref:2c7b47c6c4`

### 2. Set up reverse port tunnel

`T1572` · Confidence **High** · Static

The client parses <server> and one or more remote specifications, supporting R:<local interface>:<port>:<target host>:<target port>/<protocol> reverse port forwarding, exposing services reachable by the client on the server side.

> **Evidence**: main.client @ VA 0x7EB9A0 writes args[0] into Config.Server and the rest into Config.Remotes; help text contains "which does reverse port forwarding" and the example R:2222:localhost:22
> 
> **Source**: `ref:40c373b9dd` · `ref:37b83a2ad3`

### 3. Built-in SOCKS5 proxy

`T1090` · Confidence **High** · Static

The server enables a SOCKS5 proxy under --socks5, and the client remote can be socks / R:socks, forming a channel usable by an attacker for intranet proxying (default 127.0.0[.]1:1080).

> **Evidence**: main.server @ VA 0x7EA8E0 initializes chserver.Config.Socks5; help text "When the chisel server has --socks5 enabled" and examples "5000:socks", "R:socks"
> 
> **Source**: `ref:3f1f9acb23` · `ref:37b83a2ad3`

### 4. Encrypted HTTP-channel transport

`T1071.001` · Confidence **High** · Static

The tunnel is carried over HTTP/WebSocket and can run encrypted SSH-style sessions inside; the server can use its own certificate or obtain one via ACME (--tls-domain), and the client supports fingerprint verification and a custom Host header.

> **Evidence**: Strings "chisel.http2:", "LetsEncrypt cache directory %s", "acme-v02[.]api[.]letsencrypt[.]org/directory"; main.client sets TLS.ServerName and Header["Host"]; main.server exposes TLS.Cert/TLS.Key/TLS.CA
> 
> **Source**: `ref:7f7ff0961a` · `ref:40c373b9dd` · `ref:3f1f9acb23`

### 5. Password and key authentication

`T1573.002` · Confidence **High** · Static

The client takes a password from --auth or the AUTH environment variable; the server generates or loads an ECDSA private key via --key/--keyfile and verifies the peer by public-key fingerprint, forming an authenticated covert channel.

> **Evidence**: In main.client, os.Getenv("AUTH") is written to Config.Auth; in main.server, CHISEL_KEY / CHISEL_KEY_FILE and ccrypto.GenerateKeyFile; symbol table contains ccrypto.FingerprintKey, verifyLegacyFingerprint
> 
> **Source**: `ref:40c373b9dd` · `ref:3f1f9acb23` · `ref:2411078e7d`

### 6. stdio shell bridging

`T1059.004` · Confidence **High** · Static

remote supports the stdio:<host>:<port> form, connecting local stdin/stdout to the remote end and carrying an interactive shell or arbitrary byte stream (the help explicitly gives stdio:example[.]com:22).

> **Evidence**: Help text "stdio:example[.]com:22" and error string "stdio cannot be reversed"; main.client passes remote as-is to client.NewClient for parsing
> 
> **Source**: `ref:37b83a2ad3` · `ref:40c373b9dd`

### 7. Listen on a port for incoming connections

`T1571` · Confidence **High** · Static

The server binds 0.0.0[.]0:8080 by default (overridable with --host/--port or the HOST/PORT environment variables), waiting for clients to register and establish tunnels; this is the listening surface when deployed as a persistent entry point.

> **Evidence**: main.server reads HOST then falls back to the 7-byte constant 0x8BAF22 ("0.0.0[.]0"), and the port falls back to the 4-byte constant 0x8BA63F ("8080")
> 
> **Source**: `ref:3f1f9acb23`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end for the reason).
:::

### Host

**Dropped paths**

- `chisel.pid (current working directory; created only with --pid, mode 0644)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `no built-in address; the server address is supplied at runtime by the client command-line <server> argument (http/ws/wss forms)` | Yes | Static |
| `c2_port` | `server default listen port 8080 (overridable by PORT env var or --port)` | No | Static |
| `transport` | `SSH-style session over HTTP/WebSocket; TLS variants via --tls-cert/--tls-key/--tls-domain(ACME)` | No | Static |
| `auth_env` | `client AUTH env var (or --auth); server CHISEL_KEY / CHISEL_KEY_FILE (or --key/--keyfile)` | No | Static |
| `encryption_algo` | `session layer uses SSH-style key exchange (ECDSA/Ed25519) and symmetric algorithms such as AES-GCM/ChaCha20-Poly1305; optional TLS 1.2/1.3` | No | Static |
| `proxy_mode` | `SOCKS5 proxy mode (server --socks5, remote 'socks'/'R:socks', default local 127.0.0[.]1:1080)` | No | Static |
| `pid_file` | `chisel.pid (written with the current PID when --pid is used)` | No | Static |
| `campaign_id` | `-` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not say the sample has a built-in C2 or already points at an attacker server: the executable has no hardcoded IP, domain, port or key; my-server[.]com, 192.168.0[.]5 and example[.]com in the help text are all upstream documentation examples.
- Do not say the sample has persistence, privilege escalation or credential-theft capability: no systemd/service/scheduled-task/autostart writes and no code path reading /etc/shadow, SSH private keys or browser data were found.
- Do not treat the AES/SHA-256/base64 constants in the sample as evidence of ransomware or stealer encryption: they come from the Go standard library and TLS/SSH protocol implementations (including forward/inverse S-boxes, SHA-256 round constants and the URL-safe base64 alphabet).
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. The dynamic sandbox channel obtained no valid observation this time: the hardened-instance execution interface returned guest_rc=0 but no stdout/stderr and no event artifacts, so no runtime network behavior can be confirmed; all conclusions therefore rest on static decompilation and structure parsing.
2. The binary contains no built-in configuration; the server address, port, authentication password and forwarding rules must all be supplied through command-line arguments or environment variables, so static analysis cannot determine the C2 and port actually used in this delivery.
3. The ELF section-header table sits at file offset 0x190 (right after the program headers), unlike the usual Go layout that places section headers at the end of the file; section content and buildinfo are self-consistent and no appended payload was found, but this layout suggests the file may have been repackaged.
4. A version string like chisel-v30.0.0-src appears in the string table, inconsistent with upstream release-tag style and possibly a build-time injected version label; no functional impact from this difference was found.
5. The sample's symbol table is stripped and function names rely on .gopclntab recovery; although vcs.modified=false, minor source-level patches of the same version cannot be excluded with absolute certainty.

## Evidence Index

<details>
<summary>Expand 18 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:4b496bf5e9` | ELF structure parsing | ELF64 EXEC / x86-64, entry VA 0x46D340, 3 LOAD segments, no INTERP, empty needed |
| `ref:45c7d80e65` | elf.sections | .text 4,113,876B (entropy 6.145), .rodata 1,648,410B, .gopclntab 2,487,192B, consistent with a Go static binary |
| `ref:14ade7f14c` | elf.imports | No dynamic dependencies and no imported symbols (CGO_ENABLED=0 static linking) |
| `ref:44b50d109d` | script (buildinfo parse) | Go buildinfo: path=github[.]com/jpillora/chisel, go1.21.0, GOOS=linux, GOARCH=amd64, vcs.revision=4eb9e6a…, vcs.modified=false |
| `ref:721b8f49b3` | script (pclntab scan) | main package function table: main.main / main.client / main.server / main.generatePidFile / headerFlags / multiFlag |
| `ref:ffa11e5fda` | script (string scan) | chisel package paths github[.]com/jpillora/chisel/{client,server,share/ccrypto} and version string chisel-v30.0.0-src |
| `ref:2c7b47c6c4` | decompile.function | main.main @ VA 0x7EA5A0: dispatches on argv[1] client/server comparison, otherwise prints help and exits |
| `ref:40c373b9dd` | decompile.function | main.client @ VA 0x7EB9A0: Config.Server/Remotes, AUTH env var, fingerprint/auth/proxy/header/TLS, NewClient and optional pid file |
| `ref:3f1f9acb23` | decompile.function | main.server @ VA 0x7EA8E0: Key/KeyFile/Auth/AuthFile/KeepAlive/Proxy/Socks5/Reverse/TLS, HOST defaults to 0.0.0[.]0, PORT defaults to 8080 |
| `ref:0edb169b3a` | decompile.function | main.generatePidFile @ VA 0x7EA820: os.WriteFile("chisel.pid", pid, 0644) |
| `ref:b2a1ac8600` | script (VA to offset) | 10 bytes at VA 0x8BC0FC are "chisel.pid", corresponding to the generatePidFile write path |
| `ref:37b83a2ad3` | script (help text) | Upstream CLI help: R: reverse port forwarding, socks, stdio:example[.]com:22, UDP-forwarding examples |
| `ref:7f7ff0961a` | script (URL scan) | Strings include the chisel documentation examples hxxp://admin:password@my-server[.]com:8081, the ACME directory and the project URL; no hardcoded C2 |
| `ref:4bd764c096` | Cryptographic constant identification | AES forward/inverse S-boxes (0x7EAAC0/0x7EABC0), SHA-256 round constants (0x5792F0), CRC32, standard and URL-safe base64 alphabets |
| `ref:a456cfc32c` | Hash and fingerprint | md5 ed8b9d38fe272f2692b47292e74a0352 / sha1 a1f2a3f401ad3d18a14030353a2975afaf8dac4d / sha256 matches the filename |
| `ref:3fd6fded36` | script (ELF header) | e_shoff=0x190 (400), 14 section headers, 2,448 bytes of zero padding at file end; section-header position differs from the usual Go layout |
| `ref:2411078e7d` | decompile.symbols | 9,948 functions in total, including chisel/client, chisel/server, ccrypto.NewClient/GenerateKeyFile/FingerprintKey and others |
| `ref:acd6b7a6a9` | String extraction | Extracted 23,922 ASCII / 133 UTF-16 strings; no real C2 or flag found, hits are Go string-table concatenation false positives |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
