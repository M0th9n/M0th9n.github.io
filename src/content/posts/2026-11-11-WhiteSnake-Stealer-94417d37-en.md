---
title: "Malware sample analysis: WhiteSnake Stealer (PE · exe · 94417d37)"
published: 2026-11-11
draft: false
description: "Malicious (confidence high): WhiteSnake Stealer · stealer · difficulty medium · static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["WhiteSnake", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-11-WhiteSnake-Stealer-94417d37"
---

> [!WARNING]
> **Verdict: malicious** · Family **WhiteSnake Stealer** · Confidence **high**
> 
> Aliases: WhiteSnake, WhiteSnake Grabber, WSR Stealer
> 
> Static decompilation and built-in string decryption fully reconstructed a .NET information-stealing chain: after decrypting the built-in configuration the sample obtains the Telegram bot token and chat ID, traverses sensitive data such as browsers, messaging software, wallets, Steam/FileZilla, captures the screen and aggregates host information, packages everything into a WSR report using GZip+RC4+RSA, and uploads it via the Telegram Bot API. There is also WMI virtual-machine detection and a single-instance mutex. All key strings, API calls and algorithms were recovered from the sample's own bytes; the dynamic sandbox could not establish an execution session due to the abnormal PE structure.

## At a glance

| Item | Content |
|:--|:--|
| Family | **WhiteSnake Stealer** · Aliases WhiteSnake, WhiteSnake Grabber, WSR Stealer |
| Confidence | **high** |
| Behavior classes | stealer |
| Difficulty | medium |
| First seen | 2026-11-10 12:12:24 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/94417d37bc60731b37a8c8c713bb2c132f90eef3551bc9c331d42c8203bce35f/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt built-in config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create single-instance mutex</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Detect VM and exit</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Collect browser data</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Grab wallet and chat data</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1657</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `94417d37bc60731b37a8c8c713bb2c132f90eef3551bc9c331d42c8203bce35f` |
| MD5 | _not recorded_ |
| Size | 57,344 bytes (56.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each with attached evidence, and all of them are available statically.

### 1. Decrypt built-in configuration

`T1027` · Confidence **high** · Static

In the type's static constructor it calls the string XOR decryption routine in sequence, recovering the Telegram token, chat ID, RSA public key, tags and the grab-command XML, and writes them into static fields.

> **Evidence**: 0x224c is the out[i]=(char)(data[i]^key[i%key.Length]) loop; 0x322c performs stsfld on Field#22-#27 consecutively
> 
> **Source**: `ev-000008`

### 2. Create single-instance mutex

`T1480` · Confidence **high** · Static

Creates a Mutex named bckvtsynto with initial ownership; if ownership is not obtained it calls Environment.Exit(5) to exit, preventing duplicate runs.

> **Evidence**: 0x2218 new Mutex(true,name,out createdNew) + Exit(5); 0x37b8 Main calls this routine first
> 
> **Source**: `ev-000008` · `ev-000007`

### 3. Detect virtual machine and exit

`T1497.001` · Confidence **high** · Static

Queries SELECT * FROM Win32_ComputerSystem via WMI, lowercases Manufacturer/Model and matches 12 keywords such as virtual, vmware, vbox, kvm, qemu; on a hit the process exits.

> **Evidence**: 0x3598 builds a 12-element keyword array and calls ManagementObjectSearcher; 0x37b8 calls Environment.Exit(5) on a hit
> 
> **Source**: `ev-000008`

### 4. Collect browser data

`T1555.003` · Confidence **high** · Static

Follows the built-in commands to traverse Chrome, Edge, Brave, Chromium, Firefox, Thunderbird and other profile directories, reading Login Data, Cookies, logins.json, key4.db, Web Data, Local State and similar files, and decrypts the browser master key with DPAPI.

> **Evidence**: command name=1/2 in the command XML point to the various browsers; 0x2374 ProcessCommand reads files and regex-matches encrypted_key; MR58 ProtectedData.Unprotect
> 
> **Source**: `ev-000008`

### 5. Grab wallet and chat data

`T1657` · Confidence **high** · Static

Collects Discord/Telegram local data, FileZilla site configuration, Steam credentials, Pidgin accounts and Atomic, Guarda, Coinomi, Bitcoin, Electrum, Exodus wallet files, packaging them into relative paths such as Grabber/Wallets.

> **Evidence**: 19 commands in the command XML include Discord leveldb, tdata, sitemanager.xml, ssfn*, *.wallet, exodus.wallet/*.seco
> 
> **Source**: `ev-000008` · `ev-000007`

### 6. Capture the current screen

`T1113` · Confidence **high** · Static

Calls screen bounds and CopyFromScreen to capture the full screen, then encodes it as JPEG and writes it Base64-encoded into the report's Screenshot field.

> **Evidence**: 0x34a8 Screen.GetBounds + Graphics.CopyFromScreen + ImageFormat.Jpeg; 0x2f48 calls MakeScreenshot then ToBase64String
> 
> **Source**: `ev-000008`

### 7. Collect host fingerprint

`T1082` · Confidence **high** · Static

Reads the username, computer name and OS version, and records the execution timestamp and tag as the report's Information field.

> **Evidence**: 0x2f48 generates Username/Compname/OS/Execution timestamp; MR132 Environment.UserName, MR133 MachineName
> 
> **Source**: `ev-000008`

### 8. Query public IP

`T1016` · Confidence **high** · Static

Downloads hxxp://ip-api[.]com/line?fields=query via WebClient to obtain the egress IP; on failure it fills in a fixed fallback string.

> **Evidence**: 0x3428 WebClient.DownloadString + Trim newline, the exception branch returns preset text
> 
> **Source**: `ev-000008`

### 9. Compress and encrypt stolen data

`T1560.001` · Confidence **high** · Static

Serializes the report object to XML, compresses it with GZip, encrypts it with a 32-byte random RC4 key, then encrypts that key with the built-in RSA-2048 public key using OAEP, and concatenates WSR$ + ciphertext + encrypted key into the final container.

> **Evidence**: 0x2f48 XmlSerializer/Compress/RNG 32 bytes/RC4(0x2c28)/RSACryptoServiceProvider.Encrypt(true)/ASCII WSR$
> 
> **Source**: `ev-000008`

### 10. Exfiltrate via Telegram

`T1567` · Confidence **high** · Static

After setting TLS 1.2, POSTs multipart/form-data to the sendDocument endpoint of api[.]telegram[.]org with a filename like user@host_report.wsr, and checks whether the response contains {"ok":true.

> **Evidence**: 0x2d5c assembles hxxps://api[.]telegram[.]org/bot + token + /sendDocument?chat_id= + id, WebHeaderCollection adds POST/Content-Type, WebClient.UploadData
> 
> **Source**: `ev-000008` · `ev-000007`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot5690489105:AAEQZjYHEOdNHOLcf-ksLf347CR9V3wq4ss/sendDocument?chat_id=6195973924` | 443 | exfil | Static | ⏳ Not observed |

### Host

**Mutex**

- `bckvtsynto`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | Yes | Static |
| `telegram_bot_token` | `5690489105:AAEQZjYHEOdNHOLcf-ksLf347CR9V3wq4ss` | Yes | Static |
| `telegram_chat_id` | `6195973924` | Yes | Static |
| `mutex` | `bckvtsynto` | Yes | Static |
| `campaign_id` | `invoice` | No | Static |
| `encryption_algo` | `GZip compression + RC4 (32-byte random key) + RSA-2048/OAEP key wrapping; output starts with WSR$` | Yes | Static |
| `rsa_public_key` | `<RSAKeyValue><Modulus>tuZn8b6ZXNFzbfB7CnOwtcASlIFNuTQSpgx7crefNOdUsDhLHViQPJroWGlSvGbbT5yskoG0S8p1elKnYJglYKpBl1tJWL9K0nQmACLDXGnyItTogvgYIUQEgubKQ42AFYvyThqd76xtiqej/Qo+F8wqsZkU/9hkkny17sM4LjJ6ylDcw6zNRl49UXwcq2FL7UIYNgtyEj4omivkFFj/3azDn5+Dw4W4nkrUFxQw6XaROVRBl0ka50xspE1iCneFIJGqWeGeHq9UP2B9qkB1uherMX5hkuewJBXhPfZ54aItxQEccBtQ3bnrwdE7vHeSSDLBulG/JnYmGM5UoAeijw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>` | Yes | Static |
| `report_name_template` | `{username}@{computername}_report.wsr` | No | Static |
| `ip_lookup_url` | `hxxp://ip-api[.]com/line?fields=query` | No | Static |
| `anti_vm_keywords` | `virtual;vmbox;vmware;thinapp;VMXh;innotek gmbh;tpvcgateway;tpautoconnsvc;vbox;kvm;red hat;qemu` | No | Static |
| `grab_targets` | `Chrome/Edge/Brave/Chromium/Firefox/Thunderbird/Discord/FileZilla/Snowflake SSH/Steam/Pidgin/Telegram; wallets Atomic/Guarda/Coinomi/Bitcoin/Electrum/Exodus` | No | Static |

## Do not misjudge

:::important
The following conclusions **are easy to misjudge**; please note this when citing this report.

- Do not judge it as ransomware: RC4/RSA are only used to package the uploaded report, and no code path encrypting user files or demanding a ransom was found.
- Do not judge it as a persistent backdoor/RAT: no registry Run key, service, scheduled task or remote command channel was found; the built-in command XML is a local grab list, not a C2 command set.
- Do not assert that the sample executed successfully or reached the network in the target environment: the dynamic sandbox did not create a sample process and observed no DNS/TCP session.
- Do not assert that a downloader or second-stage payload exists: no path downloading and executing code from the network was found.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | No |

**Limitations and to be verified**

1. After delivery the dynamic sandbox polled 673 times and found 0 new candidate processes; network monitoring showed no sample-related DNS/TCP session, so no real runtime behavior was obtained; the static structure shows that the declared .text raw offset 0x200 points to a zero-filled area, with the actual content aligned by RVA, so a standard loader cannot map the CLR header, which explains the execution failure.
2. The C2 and all configuration come from static decryption; no successful request/response with api[.]telegram[.]org was observed, so they are handled as static and pending_dynamic_verify is retained.
3. Whether the Telegram bot token and chat ID are still valid today has not been verified.
4. No telemetry supporting registry, service, certificate or antivirus behavior was obtained; the related items are all empty.
5. No second-stage payload was extracted from memory or the resource section; the WSR report structure was reconstructed from code, and no real uploaded sample was obtained.
6. Import table parsing is abnormal (the tool parsed 385 empty DLL entries); imphash should not be used for family correlation or similarity searches.

## Evidence index

<details>
<summary>Expand 12 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing & fingerprinting | sha256/md5/sha1 and file size |
| `ev-000002` | scan.imphash | imphash=f39bd897d8a5059590f3ba7e7a7d7b89 |
| `ev-000006` | PE structure parsing | Machine=I386 inconsistent with Optional Magic=0x20b |
| `ev-000007` | String extraction | ASCII 364/UTF-16LE 210, including .NET metadata and residual names such as WhiteSnake.Properties.Resources |
| `ev-000008` | Scripted forensics | Self-written .NET metadata parsing + CIL disassembly + string XOR decryption, recovering all configuration, the exfil chain and the anti-VM list |
| `ev-000009` | evidence.record(manual) | Static inference of the misalignment between PE section table and image layout, used to explain the failed dynamic execution |
| `ref:89a734ac95` | PE structure parsing | Full PE header profile (entry 0x871e, import directory 0x86d0, SizeOfImage 0xe000) |
| `ref:a690bc5023` | Section table parsing | RVA and raw offset of the three sections .text/.rsrc/.reloc |
| `ref:2b340a4f12` | Import table parsing | Import table parsing abnormal, 385 empty DLL entries (import directory falls at the end of metadata) |
| `ref:b4cdb193e5` | unpack.detect | No known packer signature, packed=false |
| `ref:1794a67c25` | Dynamic analysis platform | After dynamic delivery candidate_count=0, no process dump, no related network session, rolled back |
| `telemetry:94417d37` | Dynamic telemetry | Dynamic telemetry recorded: 97 monitoring component process/file events; 27 tool/system noise entries filtered |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
