---
title: "Malicious sample analysis: Phantom Stealer (PE · exe · 9e1621bd)"
published: 2026-11-24
draft: false
description: "Malicious (confidence: high): Phantom Stealer · stealer/spyware · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Phantom", "stealer", "spyware", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-24-Phantom-Stealer-9e1621bd"
---

> [!WARNING]
> **Verdict: malicious** · Family **Phantom Stealer** · Confidence **high**
> 
> Aliases: PhantomStealer, Phantom
> 
> The outer layer is a .NET program disguised as a fishing simulation game; at startup it reconstructs a .NET DLL from its embedded bitmap resource via the pixel RGB channels, then activates it through reflective Load/Activator. In a real dynamic sandbox the process uploaded a desktop screenshot, a browser password report, a cookie report, and a credit-card report to a fixed Bot on api[.]telegram[.]org, and self-identified as Phantom Stealer v4.0.0 in the report titles, constituting complete data theft and exfiltration behavior.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **Phantom Stealer** · Aliases PhantomStealer, Phantom |
| Confidence | **high** |
| Behavior class | stealer · spyware |
| Difficulty | medium |
| First seen | 2026-11-23 08:10:50 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9e1621bde6fe02497bd1dfb21036111e38ca10efde31e3af2cf0eecbc77e54a4/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Bitmap steganography hides DLL</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load embedded DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Disguised as fishing simulator</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Capture and exfiltrate desktop screenshot</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1113</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `9e1621bde6fe02497bd1dfb21036111e38ca10efde31e3af2cf0eecbc77e54a4` |
| MD5 | _Not recorded_ |
| Size | 2,562,560 bytes (2.4 MB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **9** behaviors in total, each backed by evidence; **4** are statically available and **5** were obtained through dynamic analysis.

### 1. Bitmap steganography hides DLL

`T1027.003` · Confidence **high** · Static

The embedded resource 'Credit' is a 153x152 32bpp bitmap; after its pixel R/G/B channels are concatenated in column-major order, the first 69632 bytes are exactly the PE header MZ, forming a 32-bit .NET DLL.

> **Evidence**: resource stream offset 0x157E0, BMP at 0x159D0; decoded artifact sha256=073eaa…31dd; pe_parse shows machine=I386, imports mscoree!_CorDllMain
> 
> **Source**: `ref:32b2a7f7a9` · `ref:d07e86589b`

### 2. Reflectively load embedded DLL

`T1620` · Confidence **high** · Static

BayForm.InitializeComponent uses LateBinding.LateGet(...,"Load", [decoded bytes]) to obtain an Assembly, takes GetExportedTypes[1], then calls Activator.CreateInstance with split string arguments to activate the payload.

> **Evidence**: IL_48C3–IL_4933: Thread.GetDomain → LateGet("Load") → GetExportedTypes → Regex.Split(intConn,"72D71DAD9") → Activator.CreateInstance
> 
> **Source**: `ref:32b2a7f7a9`

### 3. Disguised as fishing simulation program

`T1036.005` · Confidence **high** · Static

The outer program contains complete Baduk/fishing-season ordering, XSD validation, and XML reporting features plus many Korean romanization UI strings, serving as a cover interface for the stealing payload.

> **Evidence**: the #US stream contains UI text such as 'Cornish Pilchard Seine', 'XSD Geomjeung'; Program.Main only does new BayForm then Application.Run
> 
> **Source**: `ref:0151deea7b` · `ref:32b2a7f7a9`

### 4. Steal browser credentials

`T1555.003` · Confidence **high** · Dynamic

After running, it generates a browser password report HTML, a cookie report JSON, and a credit-card report HTML, and when there is no browser data it returns 'No recovery data found' / a structured report with statistics at 0.

> **Evidence**: network monitoring captured PW_*.html, CO_*.json (with ChromiumBrowsers/GeckoBrowsers statistics fields), CC_*.html ('Credit Card Recovery Results')
> 
> **Source**: `ref:68ae1e8b0c`

### 5. Capture and exfiltrate desktop screenshot

`T1113` · Confidence **high** · Dynamic

Uploads a 1371x727 PNG desktop screenshot to Telegram with a filename like SC_<user>_<host>_<time>.png, along with a system-information caption.

> **Evidence**: network monitoring POST multipart filename=SC_analyst_DESKTOP-7QK4M2P_20261125_022117.png, body starts with the PNG magic number
> 
> **Source**: `ref:68ae1e8b0c`

### 6. Telegram Bot exfiltration

`T1567` · Confidence **high** · Dynamic

Uploads the screenshot, passwords, cookies, and credit-card report in four separate requests to chat_id=8318921728 via hxxps://api[.]telegram[.]org/bot<token>/sendDocument.

> **Evidence**: 4 POSTs to /bot8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY/sendDocument, multipart field chat_id=8318921728
> 
> **Source**: `ref:68ae1e8b0c`

### 7. Public IP lookup

`T1016` · Confidence **high** · Dynamic

After startup it first resolves and GETs hxxp://icanhazip[.]com/ to obtain the victim's public address, then sends back internal, gateway, and external IPs with the report.

> **Evidence**: network monitoring: DNS 'icanhazip[.]com' → GET / Host: icanhazip[.]com; caption contains Gateway IP/Internal IP/External IP
> 
> **Source**: `ref:68ae1e8b0c`

### 8. Send back host and antivirus information

`T1082` · Confidence **high** · Dynamic

The report caption collects username, computer name, OS version, language, antivirus name, and network location and sends them with the attachments.

> **Evidence**: caption lines: Username: analyst / CompName: DESKTOP-7QK4M2P / Antivirus: Windows Defender / System: Windows 10
> 
> **Source**: `ref:68ae1e8b0c`

### 9. String encryption and obfuscation

`T1027` · Confidence **high** · Static

The payload assembly uses Georgian-letter type/method names, SuppressIldasm, runtime string decryption, and method invocation through reflection, clearly the output of a .NET obfuscator.

> **Evidence**: type names ႤႨ/ႳႤ, methods ႠႤ/ႭႷ; MemberRef includes SuppressIldasmAttribute, Type.GetMethods, MethodBase.Invoke
> 
> **Source**: `ref:f7dfed3514` · `ref:504f6a8a38`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above address comes from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY` | 443 | exfil | Static | ⏳ Not observed |

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/bot8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY/sendDocument` | Yes | Static |
| `bot_token` | `8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY` | Yes | Dynamic |
| `chat_id` | `8318921728` | Yes | Dynamic |
| `ip_check_url` | `hxxp://icanhazip[.]com/` | No | Dynamic |
| `exfil_types` | `screenshot(PNG), passwords(HTML), cookies(JSON), credit cards(HTML)` | Yes | Dynamic |
| `embedded_payload_sha256` | `073eaa28846bed6b2702b3cc9ce3d4c63669293d16714b8e07f5da0a59aa31dd` | Yes | Static |
| `assembly_name` | `ISLC Edited` | No | Static |
| `activation_args` | `646A6B44,726467,CornishPilchardSeine` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- This is not ransomware: no file encryption/ransom note was observed; the core behavior is theft and exfiltration.
- The outer fishing-simulation interface is not a harmless game: its real purpose is to load a hidden stealing DLL.
- No keylogging, registry persistence, or service creation was observed, and such capabilities should not be claimed.
- The browsers in this sandbox had no credential data and the returned content was 0 records, so this is no basis to claim that real user passwords were actually stolen.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `073eaa28846bed6b2702b3cc9ce3d4c63669293d16714b8e07f5da0a59aa31dd`) |

**Limitations and pending verification**

1. The dynamic sandbox submission stage saw infrastructure congestion, and ultimately only a single successful run window could be cited; the other failures are unrelated to the sample.
2. The sandbox guest had no browser installed, so the password/cookie/credit-card reports were empty, and its parsing details for real browser databases could not be verified.
3. Payload strings are .NET-obfuscated and encrypted, and not all functionality was fully enumerated; features such as wallet/IM theft cannot be ruled out.
4. The Telegram and icanhazip requests were caught by the sandbox's fake network; returned values such as the external IP are fabricated, proving only the request shape and target.
5. No persistence, privilege escalation, or lateral movement behavior was observed.

## Evidence Index

<details>
<summary>Expand 7 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:fbad56068c` | Sample triage | Outer PE triage: .text entropy 7.951, 0 imports, packing score 0.6 |
| `ref:32b2a7f7a9` | PE structure parsing | AMD64 .NET program, EP=0, only .text/.rsrc, COR20 metadata + resource directory |
| `ref:0151deea7b` | String extraction | Outer layer contains UI strings such as 'Cornish Pilchard Seine'; no URL/process/network API strings |
| `ref:d07e86589b` | PE structure parsing | Decoded stage1 is a PE32 DLL, I386, imports mscoree!_CorDllMain |
| `ref:504f6a8a38` | Import table parsing | stage1 imports only mscoree.dll!_CorDllMain (.NET DLL) |
| `ref:f7dfed3514` | String extraction | stage1 assembly name 'ISLC Edited', types GamePanel/Form1, Georgian-script obfuscated identifiers |
| `ref:68ae1e8b0c` | Dynamic analysis platform | win10 dynamic guest runtime; the network monitoring log for this run is at live/fakenet_divert.log in the corresponding sample directory under dynamic-runs, capturing Telegram exfiltration sessions |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
