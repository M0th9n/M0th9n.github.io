---
title: "Malware sample analysis: Go RPC Backdoor (rpc/cmd/client) (PE · exe · bb0e4bb5)"
published: 2026-11-21
draft: false
description: "Malicious (medium confidence): Go RPC Backdoor (rpc/cmd/client) · backdoor/rat · difficulty hard · dynamic sandbox + static decompilation"
tags: ["RPC", "backdoor", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-Go-RPC-Backdoor-rpc-cmd-client-bb0e4bb5"
---

> [!WARNING]
> **Verdict: malicious** · family **Go RPC Backdoor (rpc/cmd/client)** (uncertain) · confidence **medium**
> 
> Aliases: AdobeARMservice masquerader, unnamed custom Go remote-control
> 
> The file is a 64-bit Windows GUI backdoor compiled with Go 1.27.1. Static decompilation confirms capabilities including self-installation into the user directory, masquerading as an Adobe update service, callback over HTTPS (/v2/monitor), HMAC-signed sessions, remote command execution, file upload/download, and a SOCKS5 proxy; in the dynamic sandbox the sample did complete resident self-installation in the user directory and made three connection attempts to 127.0.0[.]1:443, consistent with backdoor/remote-control behavior.

## At a glance

| Item | Value |
|:--|:--|
| Family | **Go RPC Backdoor (rpc/cmd/client)** · aliases AdobeARMservice masquerader, unnamed custom Go remote-control · _uncertain_ |
| Confidence | **medium** |
| Behavior class | backdoor · rat |
| Difficulty | hard |
| First seen | 2026-11-20 14:06:36 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/bb0e4bb5a6f691438a6e60480c700b4fe7195ec4b13b1d6aaa952e3e651db570/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-installs, fakes Adobe service</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Retries local port 443 connection</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Polls HTTPS monitor endpoint</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Executes system commands remotely</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Built-in recon and file commands</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `bb0e4bb5a6f691438a6e60480c700b4fe7195ec4b13b1d6aaa952e3e651db570` |
| MD5 | _not recorded_ |
| Size | 13,441,536 bytes (12.8 MB) |
| Type | PE · `exe` |

## Behavior analysis

**11** behaviors in total, each with evidence attached; **9** of them are statically obtainable and **2** were obtained through dynamic analysis.

### 1. Self-installs, fakes Adobe service

`T1036.005` · confidence **high** · dynamic

It calls os.Executable / os.Rename to move itself to %LOCALAPPDATA%\Programs\AdobeARMservice\AdobeARMservice_x86.exe (creating parent directories if missing), with resource version information masquerading as Adobe Acrobat Update Service / AdobeARMservice_x86.exe 1.182.0[.]1.

> **Evidence**: rpc/internal/client.AutoInstall rva 0x3ae0c0; dynamic memory forensics shows PID 5516 main module path C:\Users\analyst\AppData\Local\Programs\AdobeARMservice\AdobeARMservice_x86.exe
> 
> **Source**: `ev-000030` · `ev-000056` · `ref:d317d590fb`

### 2. Retries local port 443 connection

`T1071.001` · confidence **high** · dynamic

About 75 seconds after starting, the sample made three consecutive TCP 127.0.0[.]1:443 connection attempts, all blocked and failing at the local diversion, with no external domain resolution or external connection generated.

> **Evidence**: network monitoring log: pid 5516 requested TCP 127.0.0[.]1:443 three times at 12:02:43/44/45, then loopback send failed
> 
> **Source**: `ref:d317d590fb` · `ev-000056` · `ev-000031`

### 3. Polls HTTPS monitor endpoint

`T1071.001` · confidence **high** · static

It constructs a GET {base}/v2/monitor request with Cookie: connect.sid=<HMAC token> and an X-Metadata header, and parses the response as JSON command frames (cmd/args/cwd/exit_code/data/chunk).

> **Evidence**: rpc/internal/client.(*Client).Sync rva 0x3b4f80: fmt.Sprintf("%s/v2/monitor"), net/http.NewRequestWithContext("GET"), Cookie/X-Metadata, encoding/json Decode
> 
> **Source**: `ev-000046` · `ev-000057`

### 4. Executes system commands remotely

`T1059.003` · confidence **high** · static

For non-built-in commands it uses os/exec CombinedOutput to execute in the controlled working directory with a 30-second context timeout, truncating output to 0x80000 bytes and sending it back.

> **Evidence**: rpc/internal/client.(*Client).builder rva 0x3b7cc0: context.WithTimeout(30s) + os/exec.(*Cmd).CombinedOutput; dispatch string "exec" in (*Client).Run
> 
> **Source**: `ev-000054` · `ev-000038`

### 5. Built-in recon and file commands

`T1082` · confidence **high** · static

It implements built-in commands such as ls/cat/env/pwd/whoami/localip/cd/tree: enumerating directory times and sizes, reading arbitrary files (capped at 0x80000), exporting environment variables, and returning the current user and NIC addresses.

> **Evidence**: (*Client).status rva 0x3b6fc0 compares "ls"/"cat"/"env"/"pwd"/"whoami"/"localip"; (*Client).gender rva 0x3b6200 handles "cd"/"tree"
> 
> **Source**: `ev-000053` · `ev-000051`

### 6. Uploads arbitrary files to disk

`T1105` · confidence **high** · static

On receiving the push command it writes file content to the attacker-specified path: relative paths are joined to the current working directory, MkdirAll creates parent directories, and os.WriteFile uses 0644 permissions, overwriting existing files.

> **Evidence**: (*Client).invite rva 0x3aee80: filepath.IsAbs/path.Join, os.MkdirAll(0755), os.WriteFile(mode 0x1a4=0644)
> 
> **Source**: `ev-000052` · `ev-000038`

### 7. Downloads and exports local files

`T1005` · confidence **medium** · static

The download command reads the corresponding file and returns it in chunks (with filename/orig_size/chunk/is_dir fields), able to exfiltrate host files.

> **Evidence**: (*Client).Run dispatches "download" to (*Client).summary; proto.FileUploadMeta/Frame contains filename, orig_size, chunk, is_dir
> 
> **Source**: `ev-000038` · `ev-000046`

### 8. Opens SOCKS5 intranet proxy

`T1090.003` · confidence **high** · static

On receiving the socks5 command it calls OpenTunnel/OpenTunnelPoll, turning the victim host into a SOCKS5 proxy/tunnel node for the attacker to access the intranet laterally.

> **Evidence**: (*Client).Run rva 0x3aa920 dispatches 6-byte "socks5" → (*Client).OpenTunnel / OpenTunnelPoll; Go types OpenTunnelPoll, fragmentGroups
> 
> **Source**: `ev-000038`

### 9. HMAC-signed disguised session cookie

`T1573` · confidence **high** · static

It computes HMAC-SHA256 over the decimal timestamp with a 32-hex-character built-in key and hex-encodes it, using it as the value of an Express-style connect.sid Cookie and X-Metadata header to disguise traffic as ordinary web sessions.

> **Evidence**: rpc/internal/auth.Compute rva 0x2ca9a0: crypto/hmac + SHA-256, fmt "%d" timestamp, hex encoding; "connect.sid=%s" in (*Client).Sync
> 
> **Source**: `ev-000055` · `ev-000046` · `ev-000057`

### 10. Forges browser TLS fingerprint

`T1573` · confidence **high** · static

It uses refraction-networking/utls to construct a custom TLS ClientHello (including GREASE, ECH, PSK extensions, etc.), making callback traffic closer to a browser than the default Go fingerprint.

> **Evidence**: rpc/internal/client.NewTransport rva 0x3b87c0 uses utls; Go build info dep github[.]com/refraction-networking/utls v1.8.2; strings BuildHandshakeState/ClientHelloID
> 
> **Source**: `ev-000039` · `ev-000028`

### 11. Remote shutdown and exit

`T1529` · confidence **high** · static

After dispatching the shutdown command it calls Shutdown to end the session and exit; a sleep command also adjusts the sleep cadence.

> **Evidence**: (*Client).Run rva 0x3aa920: 8-byte "shutdown" → rpc_internal_client.Shutdown; 5-byte "sleep" branch
> 
> **Source**: `ev-000038`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://localhost` | 443 | c2 | Static | ⏳ not observed |

### Host

**Dropped paths**

- `%LOCALAPPDATA%\Programs\AdobeARMservice\AdobeARMservice_x86.exe`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://localhost` | Yes | Static |
| `c2_uri` | `/v2/monitor` | Yes | Static |
| `c2_method` | `GET` | Yes | Static |
| `hmac_key` | `1564fea2dea4c8806348a2ae01afafe7` | Yes | Static |
| `auth_scheme` | `HMAC-SHA256(decimal timestamp) hex string; Cookie: connect.sid=<token>; X-Metadata: <token>` | Yes | Static |
| `install_path` | `%LOCALAPPDATA%\Programs\AdobeARMservice\AdobeARMservice_x86.exe` | Yes | Dynamic |
| `user_agent` | `uTLS custom ClientHello/browser fingerprint` | No | Static |
| `sleep_min_sec` | `10` | No | Static |
| `sleep_max_sec` | `30` | No | Static |
| `command_set` | `exec,push,download,socks5,sleep,shutdown,nop` | Yes | Static |
| `window_class` | `DDE Server Window` | No | Static |
| `env_override` | `NRLAGNT (candidate)` | No | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not assert that the C2 or files use AES encryption just because an AES S-box exists in the binary: the Go standard library crypto/aes unconditionally brings in that constant table, and this run obtained no plaintext/ciphertext pair of encrypted traffic.
- Do not treat localhost/127.0.0[.]1 in the default configuration as the real external C2 and conclude that a callback succeeded; this run only observed failed loopback connection attempts.
- Do not claim that the sample established registry/service/scheduled-task persistence: no such writes were observed in the dynamic window, and the static code only reflects file self-installation in the user directory.
- Do not classify it as a generic proxy tool or downloader because of the built-in SOCKS5 and file upload; its core is a remote-control backdoor with command dispatch.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The dynamic window observed only three 127.0.0[.]1:443 connection attempts, all failing due to loopback diversion, and no C2 request/response was obtained; the C2 and related config items are handled as static and marked pending_dynamic_verify.
2. The default base URL hxxps://localhost may be overridden by an environment variable or deployment parameter (a 7-character candidate name NRLAGNT was found); the real external C2 did not appear in this environment, so the actual backend cannot be confirmed.
3. No registry, service, or scheduled-task writes were seen; the persistence conclusion is limited to file self-installation, and whether it autostarts after reboot was not verified.
4. Go function names and filenames are replaced with random English words (anti-analysis), preventing symbol-level comparison with public family intelligence, so family attribution is uncertain.
5. The static anti-debugging hits (GetThreadContext, rdtsc, cpuid, int 2Dh) mostly come from Go runtime/crypto routines, and deliberate anti-debugging was not confirmed on the call chain.
6. The HMAC key, request header format, and command dispatch all come from static decompilation and could not be checked against real traffic; the remote shell/file upload/SOCKS5 were not actually triggered.

## Evidence index

<details>
<summary>Expand 17 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash & fingerprint | sha256/md5/imphash and sample identifier check |
| `ev-000028` | String extraction | Go build ID and string statistics |
| `ev-000029` | decompile.function | main.main: AutoInstall → DefaultConfig → post → Client.Run |
| `ev-000030` | decompile.function | AutoInstall: LOCALAPPDATA\Programs self-install and suffix stripping |
| `ev-000031` | decompile.function | DefaultConfig: default base/sleep/VERBOSE handling |
| `ev-000038` | decompile.function | (*Client).Run: exec/push/download/socks5/sleep/shutdown/nop dispatch |
| `ev-000039` | decompile.function | NewTransport: utls transport layer and timeouts |
| `ev-000042` | decompile.function | Hidden-window DDE Server Window and message loop |
| `ev-000046` | decompile.function | Sync: GET /v2/monitor + Cookie/X-Metadata + JSON decoding |
| `ev-000052` | decompile.function | invite: path joining/MkdirAll/WriteFile upload to disk |
| `ev-000054` | decompile.function | builder: os/exec CombinedOutput remote command execution |
| `ev-000055` | decompile.function | auth.Compute: HMAC-SHA256 timestamp token |
| `ev-000057` | evidence.record | Static extraction of .data string header: default base/HMAC key/install name/NRLAGNT |
| `ev-000056` | evidence.record | Dynamic artifact parsing: self-install path, 127.0.0[.]1:443 attempts, no child processes |
| `ref:d317d590fb` | Dynamic analysis platform | Isolated environment real detonation with timeline/memory dump/network logs |
| `telemetry:bb0e4bb5` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 107; ETW short-lived process events 1; filtered tool/system noise 18 |
| `etw:bb0e4bb5:5516` | Process event monitoring | Short-lived process event: bb0e4bb5a6f691438a6e60480c700b4fe7195ec4b13b1d6aaa952e3e651db570.exe (pid 5516; MD5=B372D12CB536D14F60FEB0BDCD7AFEF4,SHA256=BB0E4BB5A6F691438A6E60480C700B4FE7195EC4B13B1D6AAA952E3E651DB570,IMPHASH=ED8B780A3CE7CA4ABA78A21F6BC3D4E0) |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
