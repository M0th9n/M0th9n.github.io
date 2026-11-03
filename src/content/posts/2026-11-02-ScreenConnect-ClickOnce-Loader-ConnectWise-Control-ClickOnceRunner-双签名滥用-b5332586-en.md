---
title: "Malware Analysis: ScreenConnect ClickOnce Loader (ConnectWise Control ClickOnceRunner dual-signature abuse) (PE · exe · b5332586)"
published: 2026-11-02
draft: false
description: "Malicious (medium confidence): ScreenConnect ClickOnce Loader (ConnectWise Control ClickOnceRunner dual-signature abuse) · loader/downloader/rat · difficulty medium · dynamic sandbox + static decompilation"
tags: ["ScreenConnect ClickOnce", "loader", "downloader", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-02-ScreenConnect-ClickOnce-Loader-ConnectWise-Control-ClickOnceRunner-双签名滥用-b5332586"
---

> [!WARNING]
> **Verdict: malicious** · Family **ScreenConnect ClickOnce Loader (ConnectWise Control ClickOnceRunner dual-signature abuse)** (doubtful) · Confidence **medium**
> 
> Aliases: ClickOnceRunner abuse, ScreenConnect click-once stager, dfshim ClickOnce loader
> 
> The program's main logic was fully reconstructed by decompilation: it opens the current user's TrustedPublisher certificate store and writes the certificate from its own Authenticode signature into that store; it then extracts a UTF-16 ClickOnce deployment manifest URL from the signing authenticated attribute OID 1.3.6[.]1.4.1[.]311[.]4.1.1 and launches it through dfshim!ShOpenVerbApplicationW, then sleeps 40 seconds and deletes the certificate it just wrote. The manifest points to hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application, an attacker-controlled ScreenConnect (ConnectWise Control) remote-control client. The signature at the end of the sample carries both a self-signed certificate signature and a nested ConnectWise code signature — signature injection/dual-signature masquerade.

## At a glance

| Item | Content |
|:--|:--|
| Family | **ScreenConnect ClickOnce Loader (ConnectWise Control ClickOnceRunner dual-signature abuse)** · Aliases ClickOnceRunner abuse, ScreenConnect click-once stager, dfshim ClickOnce loader · _doubtful_ |
| Confidence | **Medium** |
| Behavior classes | loader · downloader · rat |
| Difficulty | medium |
| First seen | 2026-10-31 08:12:46 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/b5332586088042aaef4fe1cb73931c9a125dc0f0ab8135912fd446818a019417/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Inject cert into trust store</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.004</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Read URL from signature</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">ClickOnce launches remote</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Install remote-control tool</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Abuse vendor signature</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `b5332586088042aaef4fe1cb73931c9a125dc0f0ab8135912fd446818a019417` |
| MD5 | _not recorded_ |
| Size | 313,912 bytes (306.6 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence, and all are obtainable statically.

### 1. Inject forged cert into trust store

`T1553.004` · Confidence **High** · Static

Opens the current user's TrustedPublisher certificate store and writes the certificate in its own signature message with CERT_STORE_ADD_ALWAYS, so that payloads subsequently installed through ClickOnce are treated as from a "trusted publisher" and skip the publisher prompt.

> **Evidence**: 0x401052 call CertOpenSystemStoreA(0,"TrustedPublisher"); 0x401102 call CertAddCertificateContextToStore(store,ctx,1,..)
> 
> **Source**: `ref:2e21dbdcc8` · `ref:8ce631e474` · `ref:065d412192`

### 2. Read payload URL from signature attributes

`T1027` · Confidence **High** · Static

Passes its own file path to CryptQueryObject to extract the PKCS#7 signature, reads the signer authenticated attribute OID 1.3.6[.]1.4.1[.]311[.]4.1.1, skips the DER header, and obtains a UTF-16LE ClickOnce manifest URL; the URL is not in the code or resources, only in the signature attributes.

> **Evidence**: 0x401076 call CryptQueryObject(1,self,0x400,2,..); 0x40118f call CertFindAttribute("1.3.6[.]1.4.1[.]311[.]4.1.1",...); string 0x446484
> 
> **Source**: `ref:2e21dbdcc8` · `ref:8ce631e474` · `ref:756f6cf38f` · `ref:c2ed1de018`

### 3. ClickOnce launches remote payload

`T1105` · Confidence **High** · Static

Dynamically loads dfshim.dll and resolves ShOpenVerbApplicationW, calling it with the URL obtained in the previous step (the Unicode string pointed to by pbData+4) as the application address; the ClickOnce runtime then downloads and starts the deployment manifest.

> **Evidence**: 0x4011e2 LoadLibraryA("dfshim"); 0x4011f4 GetProcAddress(ShOpenVerbApplicationW); 0x4011f7 call eax (argument is the attribute value+4)
> 
> **Source**: `ref:2e21dbdcc8` · `ref:8ce631e474` · `ref:756f6cf38f`

### 4. Install remote-control tool

`T1219` · Confidence **High** · Static

The embedded manifest address is hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application?...&p=8041&k=…, the ScreenConnect client deployment manifest on the attacker's relay; once installed, the client establishes an interactive remote-control channel.

> **Evidence**: UTF-16 string inside the signature attributes (from file offset 0x49C58); h=31.56.209[.]123&p=8041&k=BgIAAACkAABSU0Ex…
> 
> **Source**: `ref:756f6cf38f` · `ref:0a0482cc2c`

### 5. Abuse legitimate vendor signature

`T1553.002` · Confidence **High** · Static

The PKCS#7 in the PE security directory contains the unauthenticated attribute OID 1.3.6[.]1.4.1[.]311[.]2.4.1 (nested signature); the inner signer is Connectwise, LLC (DigiCert code-signing CA) and the outer is a self-signed paperlesinvite certificate. Windows signature APIs display the ConnectWise certificate as the signer, creating the illusion that the legitimate vendor signed it.

> **Evidence**: security directory RVA 0x497C0/size 0x3238; asn1: 1.3.6[.]1.4.1[.]311[.]2.4.1 nested signature, inner subject=CN=Connectwise, LLC; Get-AuthenticodeSignature Signer=Connectwise, LLC
> 
> **Source**: `ref:38d9e8442e` · `ref:b6f6f1a345` · `ref:3b208eb51d` · `ref:a3e4e3abfa`

### 6. Delete certificate after 40 seconds

`T1070` · Confidence **High** · Static

After calling Sleep(40000) it iterates over the previously returned certificate contexts, calls CertDeleteCertificateFromStore on each, and closes the store, so the trusted forged certificate exists only for a brief window, reducing the chance of forensic discovery.

> **Evidence**: 0x4011f9 push 0x9c40; call [Sleep]; cleanup loop calls CertDeleteCertificateFromStore / CertCloseStore
> 
> **Source**: `ref:2e21dbdcc8` · `ref:8ce631e474`

### 7. Code body unmodified

`T1553.002` · Confidence **High** · Static

The image digest computed per the PE Authenticode rules is 6386A686AD2206DCC31EA1D75BF87E54CAA396019D310B0B71219B5D9FBCF71E, matching the digest embedded in the signature, which shows the code section was not modified; the threat comes from the appended signature (signature injection), not a code patch.

> **Evidence**: self-implemented Authenticode digest calculation matches the sha256 digest in SPC_INDIRECT_DATA byte for byte; PDB path points to cwcontrol\Product\ClickOnceRunner
> 
> **Source**: `ref:71f432f4f0` · `ref:c2ed1de018` · `ref:0af020d952`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application?h=31[.]56[.]209[.]123&p=8041&k=BgIAAACkAABSU0ExAAgAAAEAAQAVCr...(manifest contains a Base64 client key, truncated)` | 443 | download | Static | ⏳ Not observed |
| tcp | `31[.]56[.]209[.]123:8041` | 8041 | c2 | Static | ⏳ Not observed |

### Host

**Registry**

- `HKCU\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates\4D78D1933270944FB476EFF1BB6D0E8FFA3EE5C2`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `clickonce_manifest_url` | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application?h=31[.]56[.]209[.]123&p=8041&k=BgIAAACkAABSU0ExAAgAAAEAAQAVCr...(truncated)` | Yes | Static |
| `relay_host` | `31[.]56[.]209[.]123` | Yes | Static |
| `relay_port` | `8041` | Yes | Static |
| `trust_store` | `TrustedPublisher (current user, CertOpenSystemStoreA with NULL provider)` | Yes | Static |
| `signing_attr_oid` | `1.3.6[.]1.4.1[.]311[.]4.1.1 (authenticated attribute; value is a DER OCTET STRING wrapping the UTF-16LE manifest address)` | Yes | Static |
| `injected_cert_subject` | `CN=CN=paperlesinvite.sbs` | Yes | Static |
| `injected_cert_issuer` | `CN=CN=paperlesinvite.sbs Root (self-signed root, not shipped with the signature)` | No | Static |
| `injected_cert_sha1` | `4D78D1933270944FB476EFF1BB6D0E8FFA3EE5C2` | Yes | Static |
| `nested_signer_subject` | `CN=Connectwise, LLC, O=Connectwise, LLC, L=Tampa, S=Florida, C=US (serial 0B9360051BCCF66642998998D5BA97CE)` | No | Static |
| `build_pdb_path` | `C:\builds\cc\cwcontrol\Product\ClickOnceRunner\Release\ClickOnceRunner.pdb` | No | Static |
| `cert_cleanup_delay_seconds` | `40` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not treat it as a standalone backdoor/trojan with built-in remote-control capability: its code matches the genuine ConnectWise Control ClickOnceRunner, and the remote-control capability comes from the ScreenConnect client it pulls via ClickOnce.
- Do not assume the file was legitimately issued and trusted by ConnectWise just because the signature embeds DigiCert and ConnectWise certificates: that certificate has been revoked by its issuer, and the outer self-signed signature carries the attacker's payload address; the signature status is not valid.
- Do not claim in the report that actual outbound connections or second-stage drops were observed in the sandbox: no connection to 31.56.209[.]123 or dfsvc child process appeared during the observation window; this conclusion is only statically reconstructed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. Second stage not dropped: no dfshim/dfsvc child process or outbound connection to 31.56.209[.]123 was observed during sandbox execution; the ClickOnce manifest content and the final installed ScreenConnect client were not obtained, and all C2 configuration is marked as statically recovered and pending dynamic confirmation.
2. The sandbox did not provide direct registry/certificate-store snapshots; the TrustedPublisher write and the deletion 40 seconds later are confirmed only by the decompiled call chain, without dynamic comparison.
3. The root certificate of the outer self-signed signature was not shipped with the signature (the signature message contains only the leaf certificate), so the full trust path of the forged chain can only be inferred.
4. The family name is based on component fingerprints, signature structure, and payload address, without vendor naming or YARA corroboration, and is marked uncertain.
5. The k parameter in the ScreenConnect manifest URL is a long Base64 client key; it is truncated in this report and the JSON, and the full value can be read at sample offset 0x49C58.

## Evidence index

<details>
<summary>Expand 10 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=b5332586088042aaef4fe1cb73931c9a125dc0f0ab8135912fd446818a019417, imphash=c2fe6927e1db8cf00400dbef9e5d35be |
| `ev-000013` | decompile.ghidra | FUN_00401000 decompilation: TrustedPublisher certificate write + URL from signature attribute + dfshim!ShOpenVerbApplicationW + Sleep(40000) + certificate deletion |
| `ref:8ce631e474` | disasm.function | Call sites in the 190 instructions from 0x401000: CertOpenSystemStoreA@0x401052, CryptQueryObject@0x401076, CertAddCertificateContextToStore@0x401102, CertFindAttribute@0x40118f, LoadLibraryA(dfshim)@0x4011e2, GetProcAddress@0x4011f4, indirect call@0x4011f7 |
| `ref:756f6cf38f` | script | Extract the UTF-16LE ClickOnce manifest URL from signing authenticated attribute OID 1.3.6[.]1.4.1[.]311[.]4.1.1 (offset 0x49C58) |
| `ref:38d9e8442e` | script | ASN.1 structure parsing: outer self-signed signature + nested signature OID 1.3.6[.]1.4.1[.]311[.]2.4.1 + Connectwise, LLC certificate chain and timestamp |
| `ref:9342ec2b1b` | script | Forged certificate thumbprint SHA1=4D78D1933270944FB476EFF1BB6D0E8FFA3EE5C2, subject=CN=CN=paperlesinvite.sbs, issuer=CN=CN=paperlesinvite.sbs Root, EKU=timestamp |
| `ref:71f432f4f0` | script | Authenticode digest 6386A686… matches the SPC_INDIRECT_DATA digest in the signature (algorithm validated on a signed VM executable) |
| `ref:0af020d952` | script | Debug directory PDB path C:\builds\cc\cwcontrol\Product\ClickOnceRunner\Release\ClickOnceRunner.pdb |
| `ref:3b208eb51d` | script | System signature API: Signer=CN=Connectwise, LLC (DigiCert CA), status abnormal, certificate revoked by issuer |
| `ref:d4c9fdbb20` | Dynamic analysis platform | Sandbox really dropped and executed it, the sample process kept running and was memory-dumped; no new child processes, and no network connections to 31.56.209[.]123 |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
