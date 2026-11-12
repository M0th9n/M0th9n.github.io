---
title: "Malware sample analysis: PlikanLocker (PE · exe · 5bac59b3)"
published: 2026-11-11
draft: false
description: "Malicious (confidence medium): PlikanLocker · ransomware · difficulty medium · static decompilation (dynamic execution produced no runtime behavior)"
tags: ["PlikanLocker", "ransomware", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-11-PlikanLocker-5bac59b3"
---

> [!WARNING]
> **Verdict: malicious** · Family **PlikanLocker** (doubtful) · Confidence **medium**
> 
> Aliases: BXBD Locker, BIOS Lock, EuxHacks2024 builder
> 
> By restoring the .NET metadata and disassembling every IL method, the program is confirmed to enumerate all local fixed drives, encrypt 212 kinds of document/data files with AES-256-CBC and rename them to .locked, then delete the plaintext originals; it also writes multiple autostart entries, creates services and scheduled tasks, deletes shadow copies and the recovery environment, terminates 74 kinds of security/forensic processes, blocks the keyboard and mouse, and displays fake full-screen BIOS/blue-screen/Windows Update interfaces. Its functionality matches a ransomware locker, so it is judged malicious.

## At a glance

| Item | Content |
|:--|:--|
| Family | **PlikanLocker** · aliases BXBD Locker, BIOS Lock, EuxHacks2024 builder · _doubtful_ |
| Confidence | **Medium** |
| Behavior class | ransomware |
| Difficulty | medium |
| First seen | 2026-11-10 12:15:38 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/5bac59b36cfcc8415207d273611584239473f43e612d6a61a9f43ca320bf5477/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake system update screen</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1491.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Full-drive file encryption</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486, T1485</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Spawn as system processes</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Multiple autostart entries</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001, T1546.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Services and scheduled tasks</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003, T1053.005</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `5bac59b36cfcc8415207d273611584239473f43e612d6a61a9f43ca320bf5477` |
| MD5 | _Not recorded_ |
| Size | 114,688 bytes (112.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**12** behaviors in total, each backed by evidence, all obtained statically.

### 1. Fake system update screen

`T1491.001` · confidence **high** · static

After startup it first shows a fake Windows Update progress window, switches to a full-screen BIOS POST/blue-screen interface during encryption, hides the taskbar and desktop icons, and shows the user a Russian ransom note demanding contact via Telegram.

> **Evidence**: Program.Main -> updateForm.Show -> ShowLockerUI/BIOSLoadingForm/BSODForm; hides Shell_TrayWnd/Progman
> 
> **Source**: `ev-000009` · `ev-000008`

### 2. Full-drive file encryption

`T1486, T1485` · confidence **high** · static

Enumerates all local fixed/removable drives (skipping network paths that begin with \\), recursively collects files of 212 extensions, and encrypts them concurrently into AES-256-CBC ciphertext according to CPU count; after each file is written it sets the original file attributes to normal and deletes the plaintext with File.Delete, leaving only the .locked ciphertext.

> **Evidence**: FileEncryptor.EncryptAllFiles / CollectFiles / EncryptFileFast; Aes::Create + Mode=CBC + Padding=PKCS7; finally File.SetAttributes(0x80) + File.Delete
> 
> **Source**: `ev-000009`

### 3. Spawn copies as system processes

`T1036.005` · confidence **high** · static

Copies itself under names such as hosts.exe/svchost.exe/winlogon.exe/services.exe/spoolsv.exe/lsass.exe/csrss.exe, randomly drops them into directories such as System32\drivers\etc, Temp, Prefetch, Common Files, IE and Windows Mail, and sets hidden + system attributes.

> **Evidence**: AdvancedPersistence.CopyToSystemFolders; 7 target directories × 7 disguised file names, selected with new Random
> 
> **Source**: `ev-000009` · `ev-000007`

### 4. Write multiple autostart entries

`T1547.001, T1546.003` · confidence **high** · static

Writes HKCU/HKLM Run and RunOnce entries, appends to Winlogon Userinit, and modifies SafeBoot AlternateShell/Minimal/Network so that both normal and safe mode start this program.

> **Evidence**: Form1.Install: multiple Registry.SetValue calls; HKLM\...\Winlogon\Userinit concatenation; SafeBoot\AlternateShell
> 
> **Source**: `ev-000009`

### 5. Register services and scheduled tasks

`T1543.003, T1053.005` · confidence **high** · static

Deletes and recreates autostart services named SystemUpdate/WindowsUpdateService/SystemUpdateService/SecurityUpdateService (binPath points to itself), creates a WindowsUpdate logon scheduled task (SYSTEM privileges), and registers __EventFilter and CommandLineEventConsumer via WMIC to achieve WMI persistence.

> **Evidence**: Form1.Install: sc delete/create/config, schtasks /create /tn WindowsUpdate /sc onlogon /ru SYSTEM, wmic __EventFilter/CommandLineEventConsumer
> 
> **Source**: `ev-000009` · `ev-000007`

### 6. Delete shadow copies and recovery environment

`T1490` · confidence **high** · static

Calls vssadmin delete shadows /all /quiet, wmic shadowcopy delete and reagentc /disable, disables the advanced boot menu with bcdedit, and writes DisableSR to turn off System Restore.

> **Evidence**: Form1.Install from IL_0747: vssadmin/shadowcopy/reagentc/bcdedit command strings; CreateRestorePoint instead first creates a "Windows Update" restore point
> 
> **Source**: `ev-000009`

### 7. Terminate security software processes

`T1562.001` · confidence **high** · static

A form timer enumerates and kills 74 process names every 500 milliseconds, covering Defender (msmpeng/mssense/windefend), Malwarebytes, mainstream AV products, and disk forensics and data recovery tools (testdisk/photorec/recuva etc.), skipping its own PID.

> **Evidence**: <Form1_Load>b__36_2: 74-entry string array + Process.GetProcessesByName + Kill
> 
> **Source**: `ev-000009` · `ev-000007`

### 8. Block system management tools

`T1112` · confidence **high** · static

Writes policy registry values that disable Task Manager, Command Prompt, Registry Editor, Control Panel, task schedule modification and System Restore, and blocks the USB storage driver from starting.

> **Evidence**: Form1.Install: DisableTaskMgr/DisableCMD/DisableRegistryTools/NoControlPanel/DisableSR writes; AntiBypass.BlockUSBDevices sets USBSTOR\Start to 4
> 
> **Source**: `ev-000009`

### 9. Hook keyboard to restrict interaction

`T1562.001` · confidence **high** · static

Installs a WH_KEYBOARD_LL global hook that intercepts the vast majority of key presses (including F5/F7 alone, Alt+Tab, the Win key and Ctrl+Alt+Del combinations) and locks the mouse with ClipCursor/ShowCursor; only the F5+F7 combination still pops up the unlock window.

> **Evidence**: Form1.SetHook + HookCallback (SetWindowsHookEx(13,...), Marshal.ReadInt32 tests the key code, returns 1 to swallow the key); Form1_Shown ClipCursor/ShowCursor(0)
> 
> **Source**: `ev-000009`

### 10. Poll Telegram for commands

`T1071.001, T1102` · confidence **high** · static

A background thread requests Telegram getUpdates every 5 seconds and parses the "text" field to execute /info (report host information), /status and /unlock; after encryption finishes it uploads host information and a desktop screenshot through sendMessage/sendPhoto.

> **Evidence**: NetworkManager.SendTelegramMessage/CheckForCommands/ProcessCommand/SendTelegramPhoto; api[.]telegram[.]org + WebClient.UploadValues/DownloadString
> 
> **Source**: `ev-000009` · `ev-000007`

### 11. Hardcoded passphrase unlocks

`T1552.001` · confidence **high** · static

The unlock window accepts the fixed passphrase 1234 (KeyForm) or unlock (UnlockForm); after validation it only closes the full-screen interface and restarts explorer.exe, and does not decrypt any file.

> **Evidence**: KeyForm.CheckKey compares "1234"; UnlockForm.CheckUnlock compares "unlock"; DecryptFile/DecryptData have no call sites
> 
> **Source**: `ev-000009`

### 12. Detect debugging and virtual machines

`T1497.001, T1622` · confidence **high** · static

A background thread calls IsDebuggerPresent/CheckRemoteDebuggerPresent every second and calls Environment.Exit when a debugger is found; it also identifies the virtualization platform/VirtualBox/Xen/QEMU through WMI Manufacturer/Model, the Disk\Enum registry and process names such as vmtoolsd/vboxservice.

> **Evidence**: AntiBypass.<Initialize>b__4_0 (debug detection loop), IsVirtualMachine (result discarded by pop)
> 
> **Source**: `ev-000009` · `ev-000008`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, so the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot1/sendMessage` | 443 | c2 | static | ⏳ Not observed |
| telegram | `hxxps://api[.]telegram[.]org/bot1/getUpdates?offset=` | 443 | c2 | static | ⏳ Not observed |

### Host

**Mutex**

- `BXBD_Locker_SingleInstance_Mutex`

**Drop paths**

- `%LOCALAPPDATA%\Microsoft\Windows\Update\WindowsUpdate.exe`
- `%WINDIR%\System32\drivers\etc\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%WINDIR%\Temp\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%WINDIR%\Prefetch\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%PROGRAMFILES%\Common Files\Microsoft Shared\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `%PROGRAMFILES%\Common Files\System\{hosts|svchost|winlogon|services|spoolsv|lsass|csrss}.exe`
- `*.locked`

**Registry**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\AlternateShell`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\AlternateShell`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr`
- `HKCU\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\DisableRegistryTools`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoControlPanel`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0\Task Creation`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Task Scheduler5.0\Task Deletion`
- `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore\DisableSR`
- `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start`

**Services**

- `SystemUpdate`
- `WindowsUpdateService`
- `SystemUpdateService`
- `SecurityUpdateService`

**Scheduled tasks**

- `WindowsUpdate`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | Yes | static |
| `c2_uri` | `/bot<token>/sendMessage, /bot<token>/getUpdates?offset=<id>&timeout=5` | Yes | static |
| `bot_token` | `1 (hardcoded placeholder, not a valid token)` | Yes | static |
| `chat_id` | `1 (hardcoded placeholder)` | Yes | static |
| `encryption_algo` | `AES-256-CBC / PKCS7` | Yes | static |
| `key_derivation` | `key=SHA512(UTF8(SHA512(UTF8(SHA512(UTF8(machine_fingerprint))+"EuxHacksSalt2024"))+"FinalKey2024"))[0:32]` | Yes | static |
| `key_fingerprint_inputs` | `MachineName+UserName+OSVersion+ProcessorCount+TotalSize/VolumeLabel of each disk+Win32_Processor ProcessorId/Name` | Yes | static |
| `encrypted_file_format` | `magic "LOCK" + 16-byte random IV + AES-CBC ciphertext, extension .locked` | Yes | static |
| `target_extensions_count` | `212` | Yes | static |
| `install_path` | `%LOCALAPPDATA%\Microsoft\Windows\Update\WindowsUpdate.exe` | Yes | static |
| `mutex` | `BXBD_Locker_SingleInstance_Mutex` | Yes | static |
| `unlock_code` | `1234 (KeyForm) / unlock (UnlockForm, case-insensitive)` | Yes | static |

## Do not misjudge

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- Do not claim the sample rewrote the MBR: WriteToMBR only calls CreateFile("\\.\PhysicalDrive0"), allocates a 512-byte buffer and immediately calls CloseHandle without calling WriteFile, and has no call sites anywhere in the file.
- Do not claim a usable Telegram C2 session exists: both botToken and chatId are hardcoded to the string "1", which is not a valid token, and dynamic analysis observed no requests to api[.]telegram[.]org.
- Do not treat it as a Qilin/Agenda family sample: the internal naming, .NET implementation and Telegram bot logic all point to a self-developed ransomware locker (BXBD/PlikanLocker); the qilin labels from public engines lack in-sample evidence.
- Do not claim that "unlocking restores data": although DecryptFile/DecryptData implement AES decryption, there are no call sites anywhere in the file, and unlocking only closes the interface.
- Do not claim it exits when a virtual machine is detected: the return value of IsVirtualMachine is discarded directly (pop) with no branching.
- Do not report it as a stealer or wiper: no browser credential/wallet file collection or data exfiltration was seen; only a desktop screenshot and host information are uploaded via Telegram.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. After submission to the dynamic sandbox, no sample process, registry change or service creation was observed, so no behavior can be corroborated by real execution; the malformed PE header is the most likely reason.
2. Pure user-mode emulation also produced no API calls, indicating the sample is not a native PE that a generic emulator can load.
3. The Telegram C2 uses the placeholder token "1", so there is no valid session and the request/response format cannot be verified; all C2 conclusions are static.
4. The encryption key is bound to host fingerprints such as MachineName/UserName/OSVersion/ProcessorId/disk volume label and is not saved to disk, so decryption cannot be reproduced in the analysis environment.
5. The file encryption scope, excluded directories and concurrency level come from IL analysis and were not measured in a real run.
6. The corrupted PE header may also have been caused by the isolation/transfer stage, so it cannot be used to infer the original delivery form.

## Evidence index

<details>
<summary>Show 10 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprinting | sha256/md5/sha1 baseline hashes |
| `ev-000002` | scan.imphash | imphash=42bd7b2eb905ea58f31607b0e955efe3 (import table is unreliable, used as an identifier only) |
| `ev-000003` | scan.entropy | .text entropy 5.129, not a packed/encrypted layer |
| `ev-000006` | PE structure parsing | Machine type I386 inconsistent with Optional Magic 0x20b bitness; import directory RVA falls inside .text |
| `ev-000007` | String extraction | strings/UTF16 hits screenshot_{0}, PlikanLocker, and AES/Telegram/persistence-related identifiers |
| `ev-000008` | String extraction | Overall string counts (ASCII 776 / UTF16 426) |
| `ev-000009` | evidence.record | Encryption/persistence/remote control/unlock evidence from manual .NET metadata parsing + dncil disassembly of 234 IL methods |
| `80d4dead54` | Dynamic analysis platform | Real sandbox submission and polling: 0 new processes, 0 dumps, 0 ransom notes, rollback completed |
| `b7011dfbd0` | dyn.run | Emulation produced no API/file/network events |
| `telemetry:5bac59b3` | Dynamic telemetry | Dynamic telemetry recorded: 100 process/file events from the monitoring component; 27 tool/system noise events were filtered out |

</details>

---

_The sample in this report is not public; IOCs have been defanged and are provided for security research only._
