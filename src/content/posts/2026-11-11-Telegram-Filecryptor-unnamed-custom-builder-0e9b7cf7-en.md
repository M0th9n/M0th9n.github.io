---
title: "Malware sample analysis: Telegram Filecryptor (unnamed/custom builder) (PE · exe · 0e9b7cf7)"
published: 2026-11-11
draft: false
description: "Malicious (confidence medium): Telegram Filecryptor (unnamed/custom builder) · ransomware/stealer · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Telegram Filecryptor", "ransomware", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-11-Telegram-Filecryptor-unnamed-custom-builder-0e9b7cf7"
---

> [!WARNING]
> **Verdict: malicious** · Family **Telegram Filecryptor (unnamed/custom builder)** (uncertain) · Confidence **medium**
> 
> Aliases: Filecryptor, Trojan.Stealer/FileCryptor
> 
> Static decompilation and real dynamic detonation corroborate each other: the program uses BCrypt to generate a 32-byte random key and encrypts user files with AES-256-GCM, appends the .locked suffix and deletes the originals, and drops RESTORE_FILES.txt ransom notes into each user directory; it also reads MachineGuid, queries the public IP, invokes PowerShell to archive user files, and through the Telegram Bot API first sends back victim information and the AES key, then uploads the loot archive. All three behavior classes — encryption, exfiltration and ransom note — were actually observed in the isolated sandbox.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Telegram Filecryptor (unnamed/custom builder)** · Aliases Filecryptor, Trojan.Stealer/FileCryptor · _uncertain_ |
| Confidence | **medium** |
| Behavior classes | ransomware · stealer |
| Difficulty | medium |
| First seen | 2026-11-10 12:11:46 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/0e9b7cf7b38ec7d33278e3b5c883636871b53ce987ebcc298acdc26a0fd44268/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">AES-GCM encrypts user files</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Append .locked, delete original</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drop ransom note files</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Read MachineGuid</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Query egress public IP</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `0e9b7cf7b38ec7d33278e3b5c883636871b53ce987ebcc298acdc26a0fd44268` |
| MD5 | _not recorded_ |
| Size | 357,888 bytes (349.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**11** behaviors in total, each with attached evidence; **3** of them are available statically and **8** were obtained through dynamic analysis.

### 1. AES-GCM encrypts user files

`T1486` · Confidence **high** · Dynamic

Reads target files one by one and writes them out encrypted with BCrypt AES-256-GCM (32-byte random key, 12-byte random nonce per file, 16-byte tag).

> **Evidence**: 0x1400074c0 BCryptOpenAlgorithmProvider(L"AES") + BCryptSetProperty(ChainingModeGCM) + BCryptGenerateSymmetricKey(0x20 bytes); dynamically generated readme.txt.locked (119 bytes, containing 12B nonce + 16B tag)
> 
> **Source**: `ref:34bcadd392` · `ref:426064d3d6` · `ref:447836ca34`

### 2. Append .locked and delete the original

`T1486` · Confidence **high** · Dynamic

After successful encryption it appends .locked to the target path as the new filename and writes it out, then deletes the original file.

> **Evidence**: FUN_1400082b0 @0x1400082b0 builds path+".locked"; 0x14000a8e6 call DeleteFileW; dynamically creates readme.txt.locked and desktop.ini.locked
> 
> **Source**: `ref:426064d3d6` · `ref:2aefb8e8b6` · `ref:25f931dd21`

### 3. Drop ransom note files

`T1486` · Confidence **high** · Dynamic

Writes RESTORE_FILES.txt into user directories such as Desktop/Documents/Downloads/Pictures, stating that the files have been encrypted with AES-256-GCM, giving a unique victim ID, and requiring the victim to contact the operator with that ID to obtain the key.

> **Evidence**: 0x14003bc10 onward is the ransom text ("YOUR FILES HAVE BEEN ENCRYPTED"/"Unique ID : %s"); dynamic notes 01-05 are all 390-byte RESTORE_FILES.txt, and the monitoring component recorded File created
> 
> **Source**: `ref:4d563570d9` · `ref:447836ca34` · `ref:25f931dd21`

### 4. Read MachineGuid

`T1082` · Confidence **high** · Dynamic

Opens HKLM\SOFTWARE\Microsoft\Cryptography and reads MachineGuid as the victim HWID; falls back to HWID_ERROR if the read fails.

> **Evidence**: 0x140009cf9 RegOpenKeyExA, 0x140009d54 RegQueryValueExA("MachineGuid"); dynamic exfil message contains HWID : 77d8973f-8f36-43c7-9edf-d99185783224
> 
> **Source**: `ref:42db61fe74` · `ref:c1c1afa599`

### 5. Query egress public IP

`T1016` · Confidence **high** · Dynamic

Uses WinHTTP to GET hxxps://api[.]ipify[.]org for the egress public IP, with request UA Mozilla/5.0; falls back to IP_ERROR on failure.

> **Evidence**: 0x1400092b4 WinHttpConnect(L"api[.]ipify[.]org", 443) + WinHttpOpenRequest("GET"); dynamic DNS query and GET / request with Host: api[.]ipify[.]org
> 
> **Source**: `ref:569f9a8f45` · `ref:c1c1afa599`

### 6. PowerShell archives user files

`T1560.001` · Confidence **high** · Dynamic

Calls CreateProcessW to run a hidden-window powershell -NoProfile -WindowStyle Hidden -Command "Compress-Archive ...", archiving the contents of Desktop/Documents/Downloads and other directories into loot_<id>.zip.

> **Evidence**: 0x140007fea call CreateProcessW; 0x14003c4f0 onward is the wide-character Compress-Archive template; the dynamic monitoring component recorded the powershell Compress-Archive process
> 
> **Source**: `ref:f166ef27ab` · `ref:7574a78609` · `ref:f1fed79be3`

### 7. Telegram key callback

`T1041` · Confidence **high** · Dynamic

Combines the victim ID, HWID, IP, hostname and 32-byte AES key into JSON and POSTs it to api[.]telegram[.]org/bot<token>/sendMessage, completing key exfiltration (which leaves the attacker holding decryption capability).

> **Evidence**: dynamic POST /bot9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g/sendMessage, body contains "chat_id":"8931808726" and "Key : d0866707..."
> 
> **Source**: `ref:c1c1afa599` · `ref:bb35413b54` · `ref:42db61fe74`

### 8. Telegram loot upload

`T1567` · Confidence **high** · Dynamic

POSTs multipart/form-data to /bot<token>/sendDocument, uploading loot_<victim_id>.zip with the caption "Loot - ID <id>"; the archive contains user files under Desktop/Documents.

> **Evidence**: dynamic request filename="loot_732e5a567793aa1ada5f.zip", the zip contains Desktop\to-do.txt, Documents\work-notes.txt, Documents\contacts.csv and others
> 
> **Source**: `ref:c1c1afa599` · `ref:30cd423271`

### 9. Enumerate fixed drives and directories

`T1083` · Confidence **high** · Static

Uses GetDriveTypeW to identify DRIVE_FIXED(3) drive letters and appends <drive>:\; also uses SHGetFolderPathW to locate the six directory classes Desktop/Documents/Downloads/Pictures/Videos/Music as the encryption scope.

> **Evidence**: 0x14000afac call GetDriveTypeW followed by cmp eax,3; 0x1400079a6/0x14000a93f SHGetFolderPathW; 0x14003caa8 onward is the wide-character directory-name strings
> 
> **Source**: `ref:06059cfea5` · `ref:f166ef27ab` · `ref:65fdb4eaa5`

### 10. Recursively traverse user files

`T1083` · Confidence **medium** · Static

Uses std::filesystem recursive_directory_iterator to traverse the target directories recursively, calling the single-file encryption routine on each file to achieve bulk encryption.

> **Evidence**: 0x14003db48/0x14003db88 recursive_directory_iterator-related strings; FUN_1400082b0 @0x1400082b0 is the single-file encryption implementation
> 
> **Source**: `ref:2a82d1a73f` · `ref:426064d3d6`

### 11. Obfuscated hardcoded C2 credentials

`T1027` · Confidence **high** · Static

The Bot Token and chat_id are base64-encoded and then hardcoded with each character incremented by 1; at startup each byte is decremented by 1 and base64-decoded to recover the plaintext, evading simple string searches.

> **Evidence**: 0x140001000/0x1400010f0 static initializers write the constants; FUN_140008de0 @0x140008de0 performs c-1 followed by base64 decoding; constants are at 0x14003bb70/0x14003bbb8
> 
> **Source**: `ref:f41d2c932d` · `ref:a9055f531b` · `ref:ae66f0e235` · `ref:bb35413b54`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connections/handshakes were completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g/sendMessage` | 443 | c2 | Dynamic | Observed |
| telegram | `hxxps://api[.]telegram[.]org/bot9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g/sendDocument` | 443 | exfil | Dynamic | Observed |
| http | `hxxps://api[.]ipify[.]org/` | 443 | other | Dynamic | Observed |

### Host

**Dropped paths**

- `%USERPROFILE%\Desktop\RESTORE_FILES.txt`
- `%USERPROFILE%\Documents\RESTORE_FILES.txt`
- `%USERPROFILE%\Downloads\RESTORE_FILES.txt`
- `%USERPROFILE%\Pictures\RESTORE_FILES.txt`
- `%USERPROFILE%\Videos\RESTORE_FILES.txt`
- `%USERPROFILE%\Music\RESTORE_FILES.txt`
- `%USERPROFILE%\Downloads\*.locked`
- `%TEMP%\loot_<victim_id>.zip`

**Registry**

- `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid (read only)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | Yes | Dynamic |
| `bot_token` | `9071041436:AAFixB0iY_3HenM0N9P-aJ8izhd6Owoos7g` | Yes | Dynamic |
| `chat_id` | `8931808726` | Yes | Dynamic |
| `ip_lookup_url` | `hxxps://api[.]ipify[.]org/` | No | Dynamic |
| `encryption_algo` | `AES-256-GCM (BCrypt, 32-byte key, 12-byte nonce, 16-byte tag per file)` | Yes | Static |
| `file_extension` | `.locked` | Yes | Dynamic |
| `ransom_note_filename` | `RESTORE_FILES.txt` | Yes | Dynamic |
| `target_dirs` | `Desktop;Documents;Downloads;Pictures;Videos;Music` | Yes | Dynamic |
| `exfil_archive` | `loot_<victim_id>.zip (PowerShell Compress-Archive)` | Yes | Dynamic |
| `victim_id` | `10-byte random number (20 hex digits), used for filenames/identification` | No | Dynamic |
| `hwid_source` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | No | Dynamic |

## Do not misjudge

:::important
The following conclusions **are easy to misjudge**; please note this when citing this report.

- Do not assert that a decryption solution can be provided merely because AES/BCrypt and the .locked suffix are used: the key is randomly generated on every run and only sent out via Telegram; no local material capable of recovering the key was found in the sample.
- Do not treat the VT stealer label as the sole characterization: the sample also performs local file encryption and drops ransom notes, making it a composite of information theft and crypto-ransomware.
- Do not claim persistence (Run key/service/scheduled task) or backup destruction (vssadmin/wbadmin/shadow copy deletion): no such capability was observed in the import table, strings or dynamic telemetry.
- Do not assert anti-debugging/anti-VM merely from the IsDebuggerPresent import and a single cpuid: both lie on the CRT initialization path, and no VM-detection strings or effective check branches were found.
- Do not claim a ransom wallet address or specific payment method was found: the ransom note contains no wallet address, amount or payment instructions.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and to be verified**

1. In the dynamic environment api[.]ipify[.]org was answered by a locally simulated network, so the IP field in the exfil body is simulated page content rather than a real public IP; this only proves that the query behavior exists.
2. Ransom notes and .locked files were dynamically observed in Desktop/Documents/Downloads/Pictures; the Videos/Music directories were empty in the test environment, and no encryption instances were obtained for those two directories.
3. The key was only sent out via Telegram, never written to local disk, and is randomly generated on each run; without the attacker-side key the encrypted files cannot be decrypted.
4. The command-line field of the monitoring component stored in telemetry was truncated by length, so the full target path of PowerShell Compress-Archive could not be read verbatim; however, the content of the uploaded zip itself corroborates the archiving behavior.
5. No strict ordering between file encryption and exfiltration was observed: the two completed within seconds of each other, and the zip contains both plaintext and already-encrypted files, so no fixed execution order is claimed.

## Evidence index

<details>
<summary>Expand 24 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing & fingerprinting | sha256/md5/sha1 and file size 357888 |
| `ev-000002` | scan.imphash | imphash=eeb986cd0ff24630aafa5ccb56369c8a |
| `ev-000003` | scan.rich | MSVC Rich header, 10 records, richhash=5414cd1a94a9b105bc1777089ef2ab37 |
| `ev-000004` | scan.entropy | Per-section entropy 0–6.43, .text=6.432, no high-entropy encrypted section |
| `ev-000010` | String extraction | String scan: ASCII 1042 / UTF-16 218, including the base64 alphabet etc. |
| `ev-000014` | Cryptographic constant identification | Standard base64 alphabet @0x3bb20 |
| `ev-000015` | decompile.ghidra | FUN_140001000 initializes the obfuscated Token constant |
| `ev-000016` | decompile.ghidra | FUN_1400010f0 initializes the obfuscated chat_id constant |
| `ev-000017` | decompile.ghidra | FUN_140008de0 implements byte-wise -1 + base64 decoding |
| `ev-000018` | decompile.ghidra | FUN_140009220 queries api[.]ipify[.]org via WinHTTP |
| `ev-000019` | decompile.ghidra | FUN_140009be0 main flow: random key/ID, MachineGuid, IP, Telegram message and file-encryption scheduling |
| `ev-000020` | decompile.ghidra | FUN_1400074c0 AES-256-GCM encryption implementation |
| `ev-000021` | decompile.ghidra | FUN_1400076d0 bytes-to-hex (ID/key formatting) |
| `ev-000022` | decompile.ghidra | FUN_1400082b0 single-file encryption and .locked/RESTORE_FILES path construction |
| `ev-000023` | decompile.ghidra | FUN_140014570 virtual-call forwarding (non-core) |
| `ev-000024` | evidence.record | Script decoded the obfuscated constants to obtain the Bot Token and chat_id, matching the dynamically captured values |
| `ref:35c54b9e37` | Dynamic analysis platform | Real detonation completed: sample process pid 6624 alive, producing a memory dump and network/file telemetry; environment rolled back |
| `ref:30cd423271` | sandbox.watch(live) | notes_manifest: 5 ransom notes in Desktop/Documents/Downloads/Pictures plus readme.txt.locked |
| `ref:c1c1afa599` | sandbox.watch(fakenet) | Captured GET api[.]ipify[.]org, POST /sendMessage (with Key/HWID/IP), POST /sendDocument (loot_<id>.zip) |
| `ref:25f931dd21` | sandbox.watch(sysmon) | Monitoring component: sample process creation, DNS query, .locked and RESTORE_FILES.txt file creation |
| `ref:7574a78609` | sandbox.watch(telemetry) | Telemetry contains the Compress-Archive command line and .locked/RESTORE_FILES creation events |
| `c2_evidence:0e9b7cf7` | Connection evidence extraction | Dynamic network monitoring recorded 3 connection attempts to api[.]ipify[.]org:443, api[.]telegram[.]org:443; no complete session captured |
| `telemetry:0e9b7cf7` | Dynamic telemetry | Dynamic telemetry recorded: 118 monitoring component process/file events; 1 ETW short-lived process event; 27 tool/system noise entries filtered |
| `etw:0e9b7cf7:6624` | Process event monitoring | Short-lived process event: 0e9b7cf7b38ec7d33278e3b5c883636871b53ce987ebcc298acdc26a0fd44268.exe (pid 6624; MD5=2F46DB8D75D3A610A45ADA6153D098F1,SHA256=0E9B7CF7B38EC7D33278E3B5C883636871B53CE987EBCC298ACDC26A0FD44268,IMPHASH=EEB986CD0FF24630AAFA5CCB56369C8A) |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
