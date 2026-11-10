---
title: "Malware Analysis: OSA Stealer (other · zsh · cd86aee4)"
published: 2026-11-09
draft: false
description: "Malicious (medium confidence): OSA Stealer · stealer/downloader/implant · difficulty easy · Pure static analysis"
tags: ["OSA", "stealer", "downloader", "implant", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-OSA-Stealer-cd86aee4"
---

> [!WARNING]
> **Verdict: Malicious** · Family **OSA Stealer** (uncertain) · Confidence **medium**
> 
> Aliases: AppleScript-based macOS stealer, osascript downloader/loader
> 
> The outer zsh layer is plaintext, so the complete malicious chain is directly readable: it embeds a base64+gzip stage2 and evals it; stage2 periodically requests content from a hard-coded domain and pipes it into osascript for execution (remote AppleScript code execution); it then uploads /tmp/osalogging.zip in chunks via HTTP PUT and deletes the local file. Every step has string/offset evidence.

## Overview

| Item | Content |
|:--|:--|
| Family | **OSA Stealer** · aliases AppleScript-based macOS stealer, osascript downloader/loader · _uncertain_ |
| Confidence | **medium** |
| Behavior class | stealer · downloader · implant |
| Difficulty | easy |
| First seen | 2026-11-06 18:24:31 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/cd86aee4882b93ccd3e993b9d8f12bd372640ed765893fcab27c5919d2f154d1/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decode embedded payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Call back to C2 for remote script</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Remote execution via osascript</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Exfiltrate password argument</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Chunked archive exfiltration</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `cd86aee4882b93ccd3e993b9d8f12bd372640ed765893fcab27c5919d2f154d1` |
| MD5 | _not recorded_ |
| Size | 1,442 bytes (1.4 KB) |
| Type | other · `zsh` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all are statically available.

### 1. Decodes embedded payload

`T1140` · Confidence **high** · static

The outer script decodes PAYLOAD_m296222728618692 from the heredoc with base64 -D, gunzips it into a 2,641-byte zsh script, and finally evals it, keeping the plaintext out of sight.

> **Evidence**: outer script off 11: d2229=$(base64 -D <<'PAYLOAD_m296222728618692' | gunzip; final line eval "$d2229"; gzip header 1f8b08
> 
> **Source**: `ev-000001` · `ev-000003`

### 2. Calls back to C2 for remote script

`T1071.001` · Confidence **high** · static

It issues a GET to hxxp://seohumanoid[.]com/dynamic?txd=<hard-coded token> and treats the response body as executable script content; the token is fixed in the script.

> **Evidence**: stage2 off 496/742: "hxxp://$domain/dynamic?txd=$token"; off 127 token=42403afd...; off 92 domain=seohumanoid[.]com
> 
> **Source**: `ev-000002` · `ev-000003`

### 3. Remote execution via osascript

`T1059.002` · Confidence **high** · static

The curl output is not written to disk; it is piped directly into osascript for interpretation and execution — equivalent to the C2 delivering and running arbitrary AppleScript, forming a remote code execution channel.

> **Evidence**: stage2 off 496 and off 742 both end with " | osascript"
> 
> **Source**: `ev-000002` · `ev-000003`

### 4. Exfiltrates password argument

`T1041` · Confidence **medium** · static

If launched with arguments, it appends the first argument to the /dynamic request as pwd=$1, sending it along with the token, apparently receiving/exfiltrating a password.

> **Evidence**: stage2 off 496: ".../dynamic?txd=$token&pwd=$1"; off 300 if [ $# -gt 0 ]
> 
> **Source**: `ev-000002`

### 5. Chunked archive exfiltration

`T1041` · Confidence **high** · static

After checking that /tmp/osalogging.zip exists and is non-empty, it uploads it in 10MB chunks via HTTP PUT to /gate, with buildtxd, upload_id, chunk_index and total_chunks parameters.

> **Evidence**: stage2 off 929 CHUNK_SIZE=$((10*1024*1024)); off 1750 curl -X PUT; off 2064 /gate?buildtxd=$token&upload_id=...
> 
> **Source**: `ev-000002` · `ev-000003`

### 6. Masquerades as browser UA

`T1036.005` · Confidence **high** · static

All HTTP requests consistently use the macOS Safari Mozilla/5.0 User-Agent and add an api-key request header, blending into normal browser traffic.

> **Evidence**: stage2 off 361/1821: User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36; off 459/1923 api-key
> 
> **Source**: `ev-000002`

### 7. Silent background execution

`T1564` · Confidence **high** · static

The entry point redirects stdin/stdout/stderr all to /dev/null and invokes daemon_function in the background with &, so the run produces no terminal output.

> **Evidence**: stage2 off 31/51/71: exec </dev/null / exec >/dev/null / exec 2>/dev/null; off 2581: daemon_function "$@" &
> 
> **Source**: `ev-000002`

### 8. Deletes staged archive after upload

`T1070.004` · Confidence **high** · static

After all chunks upload successfully it runs rm -f /tmp/osalogging.zip, deleting the local stolen archive to clean up traces.

> **Evidence**: stage2 off 2548: rm -f "$file"; file defined at off 263
> 
> **Source**: `ev-000002`

### 9. Retry backoff on failure

`T1041` · Confidence **high** · static

Each chunk upload retries up to 8 times with an increasing wait of 3+attempt*2 seconds, improving exfiltration success on disrupted networks.

> **Evidence**: stage2 off 972 MAX_RETRIES=8; off 1597 retry loop; off 2384 sleep $((3 + attempt * 2))
> 
> **Source**: `ev-000002`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://seohumanoid[.]com/dynamic?txd=42403afd2906a8f3062e3ddb19b28572d88db9ae74b147319383bd280c6bec0a` | 80 | c2 | static | ⏳ not observed |
| http | `hxxp://seohumanoid[.]com/gate?buildtxd=42403afd2906a8f3062e3ddb19b28572d88db9ae74b147319383bd280c6bec0a` | 80 | exfil | static | ⏳ not observed |

### Host

**Dropped paths**

- `/tmp/osalogging.zip`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `seohumanoid[.]com` | yes | static |
| `c2_port` | `80` | yes | static |
| `c2_uri` | `/dynamic (task delivery) ; /gate (chunked upload)` | yes | static |
| `campaign_id` | `42403afd2906a8f3062e3ddb19b28572d88db9ae74b147319383bd280c6bec0a (txd/buildtxd)` | yes | static |
| `api_key` | `5190ef1733183a0dc63fb623357f56d6` | yes | static |
| `exfil_path` | `/tmp/osalogging.zip` | yes | static |
| `encoding_algo` | `base64 + gzip (embedded stage2)` | yes | static |
| `chunk_size` | `10485760` | no | static |
| `user_agent` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not describe this script as a complete keylogger or banking trojan: it only retrieves and executes remote AppleScript and uploads a predefined /tmp/osalogging.zip; the collection actions are not in this file.
- Do not assert persistence (LaunchAgent/LaunchDaemon/login item): the script creates no persistence item and only runs once in the background.
- Do not assert that the C2 came online or that data was exfiltrated: this was pure static analysis, no network callback was made and no real session was observed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This run was static only; the sample was not executed in a dynamic sandbox or a real macOS environment, and neither the C2 session nor the exfiltration result was observed.
2. The actual theft/collection logic is performed by AppleScript delivered by the C2; that remote script's content is unknown, so the exact data types collected (browser credentials, Keychain, wallets, etc.) cannot be confirmed.
3. Family attribution is inferred from behavior and naming, without vendor naming, YARA rules or multi-engine results.
4. All C2 entries are marked static with pending_dynamic_verify=true and need a real network session to be upgraded to dynamic.
5. The gzip-embedded data's modification time is 2026-11-02, used only as a build-time reference and not as a conclusion.

## Evidence index

<details>
<summary>Expand 3 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | outer .zsh string extraction: 22 ASCII strings, including the heredoc marker PAYLOAD_m296222728618692 and eval "$d2229" |
| `ev-000002` | string extraction | stage2 string extraction: 71 ASCII strings, including domain/token/api_key, curl\|osascript, /tmp/osalogging.zip, /gate chunked upload and rm -f |
| `ev-000003` | evidence.record | static decoding script: heredoc→base64→gzip→2,641-byte stage2, sha256 206c96b...82acd; extracted domain, token, api-key and staging path |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
