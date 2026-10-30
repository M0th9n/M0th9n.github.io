---
title: "Malware Analysis: ScreenConnect (ConnectWise Control) client dropper (PE · exe · 32256065)"
published: 2026-10-29
draft: false
description: "Malicious (medium confidence): ScreenConnect (ConnectWise Control) client dropper · loader/downloader/rat · difficulty medium · dynamic sandbox + static decompilation"
tags: ["ScreenConnect", "loader", "downloader", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-29-ScreenConnect-ConnectWise-Control-客户端投递器-32256065"
---

> [!WARNING]
> **Verdict: Malicious** · Family **ScreenConnect (ConnectWise Control) client dropper** (uncertain) · Confidence **medium**
> 
> Aliases: ConnectWise ScreenConnect, ScreenConnect RAT, ConnectWise Control, ScreenConnect.Client.application loader
> 
> The sample is a 32-bit GUI-subsystem ClickOnce bootstrapper: it writes the certificate from its own digital signature into the current user's "Trusted Publishers" store, then extracts the deployment address hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041 from the signature attribute OID 1.3.6[.]1.4.1[.]311[.]4.1.1, launches a ClickOnce deployment via dfshim!ShOpenVerbApplicationW and installs the ConnectWise ScreenConnect client, thereby obtaining a remote-control channel that points to a single external IP. Decompilation (0x401000) and dynamic sandbox memory forensics (the dfshim.dll→dfdll.dll→urlmon.dll load chain) corroborate each other.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **ScreenConnect (ConnectWise Control) client dropper** · aliases ConnectWise ScreenConnect, ScreenConnect RAT, ConnectWise Control, ScreenConnect.Client.application loader · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | loader · downloader · rat |
| Difficulty | medium |
| First seen | 2026-10-29 09:05:34 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/32256065004e7e816afd12baa39caaacdcc185fa5f3202055b8c65e81727402f/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Parse own signature</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Write Trusted Publisher store</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.004</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">URL from signature attr</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">ClickOnce via dfshim</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1218</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Fetch remote-control client</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `32256065004e7e816afd12baa39caaacdcc185fa5f3202055b8c65e81727402f` |
| MD5 | _not recorded_ |
| Size | 312,528 bytes (305.2 KB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence; **6** are obtainable statically and **1** was obtained through dynamic analysis.

### 1. Parse own digital signature

`T1553.002` · Confidence **High** · Static

Calls CryptQueryObject(CERT_QUERY_OBJECT_FILE) with its own executable path to parse the embedded PKCS#7, obtaining the certificate count and all certificate entities.

> **Evidence**: 0x401000 FUN_00401000:GetModuleFileNameW → CryptQueryObject(1,lpFilename,0x400,2,...) → CryptMsgGetParam(11/12)
> 
> **Source**: `ev-000013`

### 2. Write to Trusted Publisher certificate store

`T1553.004` · Confidence **High** · Static

Opens the current user's TrustedPublisher certificate store and writes each certificate from the signature with CertAddCertificateContextToStore, so that this file's publisher appears as a trusted publisher in the system.

> **Evidence**: 0x401000:CertOpenSystemStoreA(0,"TrustedPublisher") → CertAddCertificateContextToStore(...)
> 
> **Source**: `ev-000013`

### 3. Get deployment address from signature attribute

`T1027` · Confidence **High** · Static

Looks up OID 1.3.6[.]1.4.1[.]311[.]4.1.1 among the signature's authenticated attributes and extracts the UTF-16 deployment address from it; this address appears neither in .rdata/.data nor in code constants, so static string scanning is nearly blind to it.

> **Evidence**: 0x401000:CertFindAttribute("1.3.6[.]1.4.1[.]311[.]4.1.1",...); the address is located at signature-area file offset 0x4C12C
> 
> **Source**: `ev-000013` · `ev-000017`

### 4. Launch ClickOnce via dfshim

`T1218` · Confidence **High** · Dynamic

After LoadLibraryA("dfshim") it resolves ShOpenVerbApplicationW and hands the URL from the previous step to it, and the system ClickOnce component initiates the deployment; in the dynamic snapshot this process subsequently loads dfshim.dll, dfdll.dll, urlmon.dll and mscoree.dll.

> **Evidence**: 0x401000:LoadLibraryA("dfshim")/GetProcAddress("ShOpenVerbApplicationW") → indirect call; module chain of dynamic PID 1048: dfshim.dll → dfdll.dll → urlmon.dll
> 
> **Source**: `ev-000013` · `ev-000016`

### 5. Fetch remote-control client remotely

`T1105` · Confidence **Medium** · Static

The ClickOnce deployment address points to an external single-IP ScreenConnect instance; at runtime it downloads and installs the corresponding .application manifest and client program; no actual outbound network traffic was observed in this dynamic run, so this stage was not captured.

> **Evidence**: signature attribute URL: hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041
> 
> **Source**: `ev-000017` · `ev-000016`

### 6. Beacon back to port 8041 to establish remote control

`T1219` · Confidence **Medium** · Static

The installed ScreenConnect client beacons back to the relay server using the h=31[.]56[.]209[.]123&p=8041 parameters, forming an interactive remote-desktop/command channel; this connection does not occur inside this sample's process but is performed by the downloaded subprogram.

> **Evidence**: h/p parameters of the deployment URL (31[.]56[.]209[.]123, 8041); the sample's own import table has no network APIs, only 97 symbols from KERNEL32+CRYPT32
> 
> **Source**: `ev-000017` · `ev-000002`

### 7. Erase trusted certificate after 40 seconds

`T1070` · Confidence **High** · Static

After Sleep(40000) it iterates over the previously added certificate handles, deletes each one with CertDeleteCertificateFromStore and closes the certificate store, reducing residual traces in the Trusted Publishers store.

> **Evidence**: 0x401000:Sleep(40000) → CertDeleteCertificateFromStore loop → CertCloseStore
> 
> **Source**: `ev-000013`


## IOC (Defanged)

### Network

:::caution
**The real server side remains unverified**: the above connections/handshakes were completed with a locally controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence Source | Dynamic Observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041&k=<base64 RSA1 public key>` | 443 | download | Static | ⏳ not observed |
| tcp | `31[.]56[.]209[.]123` | 8041 | c2 | Static | ⏳ not observed |

### Host

**Registry**

- `HKCU\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates`

### Configuration

| Key | Value | Required | Evidence Source |
|:--|:--|:--|:--|
| `clickonce_url` | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041&k=<base64>` | Yes | Static |
| `c2_hosts` | `31[.]56[.]209[.]123` | Yes | Static |
| `c2_port` | `8041` | Yes | Static |
| `deployment_key` | `the k parameter base64-decodes to a 276-byte CAPI public key blob containing the RSA1 magic (ScreenConnect client deployment key)` | Yes | Static |
| `config_location` | `the configuration is not in code/resources but stored in the value of the Authenticode signature attribute OID 1.3.6[.]1.4.1[.]311[.]4.1.1 (file offset 0x1F12C, UTF-16LE)` | Yes | Static |
| `signer_certificate` | `CN=Connectwise, LLC, O=Connectwise, LLC, L=Tampa, ST=Florida, C=US; serial=0xb9360051bccf66642998998d5ba97ce; issuer DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please take note when citing this report.

- Do not conclude that the binary has no C2 merely because it contains no network APIs: downloading and beaconing back are performed by dfshim/ClickOnce and the ScreenConnect client installed afterwards; the sample is only a bootstrapper.
- Do not treat it as a self-developed encrypted-protocol stealer or ransomware: the sample contains no file traversal/encryption, credential reading, or custom C2 protocol implementation, and no file writes were seen dynamically.
- Do not judge it as legitimate software merely because "the signature is valid and the subject is ConnectWise": the deployment address covered by the signature points to a non-enterprise-hosted instance on a single external IP.
- Do not treat the TrustedPublisher write as persistence: the code actively deletes these certificates after about 40 seconds and exits.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and Items to Verify**

1. The remote .application manifest and the ScreenConnect client were not obtained: dynamic network monitoring recorded no connection at all to 31[.]56[.]209[.]123:443/8041, and the sample process exited after a 40-second wait, so stage2 is empty and the C2 parameters come only from static extraction.
2. The code passes the signature attribute blob plus a 4-byte offset to ShOpenVerbApplicationW; dynamically the ClickOnce deployment libraries were indeed loaded but no download request was seen, so it cannot be ruled out that the offset truncates the URL and the deployment fails already at the parsing stage.
3. The write/delete to the Trusted Publisher certificate store has only decompilation evidence; the dynamic profile had no registry or certificate store monitoring, so that write could not be directly proven.
4. The family naming is based on ScreenConnect deployment characteristics and the signature subject, lacking vendor naming or YARA corroboration, hence it is marked uncertain.

## Evidence Index

<details>
<summary>Expand 10 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size 312528 |
| `ev-000002` | scan.imphash | imphash=c2fe6927e1db8cf00400dbef9e5d35be |
| `ev-000003` | scan.rich | Rich header, 11 toolchain records, richhash=02ef09fc7c85d790ac1d32f483d193df |
| `ev-000004` | scan.entropy | .text entropy 6.608 (below packing threshold) |
| `ev-000009` | String extraction | String scan: ascii 1144 / utf16 464 entries, no plaintext C2; matched alphabets are runtime library data |
| `ev-000013` | decompile.function | 0x401000 main function: certificate store write + URL from signature attribute + dfshim ClickOnce + Sleep(40000) cleanup |
| `ev-000014` | decompile.function | find_pe_section is an MSVC runtime library function (not malicious logic) |
| `ev-000015` | Scripted forensics | Recomputed Authenticode digest matches the digest inside the signature; signature subject CN=Connectwise, LLC |
| `ev-000016` | Scripted forensics | Dynamic sandbox: process 1048 loads dfshim.dll→dfdll.dll→urlmon.dll, with no outbound connections |
| `ev-000017` | Scripted forensics | Extracted the ScreenConnect ClickOnce deployment URL and RSA1 deployment key from signature attribute OID 1.3.6[.]1.4.1[.]311[.]4.1.1 |

</details>

---

_This report's sample is not public; IOCs are defanged and intended for security research only._
