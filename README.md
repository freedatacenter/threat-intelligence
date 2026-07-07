# Threat Intelligence Reports

Public threat intelligence reports and indicators of compromise (IOCs) from real-world incident investigations.

[//]: # (feed-validator: https://metrics.freedatacenter.org/v1/telemetry?src=ti-url)

## Reports

### 2026-07-07 — Honeypot Fleet: Monthly Threat Report, June 2026

Over June 2026 our distributed honeypot sensors (Germany, the United States and Russia) recorded roughly 870,000 attack sessions/requests across SSH, multi-protocol exploitation, Docker, LLM, MikroTik and Kubernetes surfaces. The headline development is a self-propagating Docker-API worm performing container-escape to the host: Docker-surface volume grew ~28× month-over-month (~4,300 → ~119,000 events), driven by a single operator. Captured malware also shifted — May's WannaCry/SMB (PE32 DLL) dominance gave way to almost entirely ELF SSH-worms (Panchan, Go SSH-worm, Discord-C2, Mirai/Gafgyt). Solana validator targeting and LLM-endpoint abuse continue, and an IEC-104 (ICS/OT) decoy saw steady reconnaissance but zero external control commands.

**Key findings:**
- **Docker-API worm with host escape** (headline): one operator `45[.]198[.]224[.]5` (AS215925 VPSVAULT.HOST) drove 104,299 of 118,909 Docker requests; the worm creates containers that mount the host filesystem and escape via `chroot /host sh` (T1611), then fetches a second-stage payload. A dedicated technical report follows separately.
- **Malware stream shifted to ELF SSH-worms**: 70 unique samples, almost all ELF (Panchan, Go SSH-worm, Discord-C2, Mirai/Gafgyt) vs May's WannaCry PE32 DLLs; exactly one PE32+ sample; ClamAV detected zero of 70.
- **SSH brute-force up to 497,929 sessions**; Solana-validator credential targeting continues (`sol`/`solana`/`solv` in dictionaries).
- **LLM-endpoint abuse persists** (16,729 events): scanning, inference/compute theft, and attempts to proxy paid cloud models through the decoy; scanning tool shifted to `node-fetch`.
- **IEC-104 (ICS/OT) reconnaissance is routine but hands-off**: 758 connects + 67 General Interrogations from 267 unique cloud-scanner IPs, zero external control commands.

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-07-07-honeypot-monthly-june/Incident_Report_2026-07-07_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-07-07-honeypot-monthly-june/Incident_Report_2026-07-07_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-07-07-honeypot-monthly-june/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-07-07-honeypot-monthly-june/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Docker-worm operator | `45[.]198[.]224[.]5` (AS215925 VPSVAULT.HOST LTD) |
| Dropper | `45[.]142[.]142[.]140` (`:8443/dropper_x86`) |
| Dropper | `192[.]142[.]28[.]77` (`/bachekuni/ohshit.*`, multi-arch) |
| Dropper | `51[.]158[.]248[.]122` (`:8517/*`, multi-arch + loader) |
| Dropper | `89[.]19[.]209[.]214` (secondary wget-ping) |
| Domain | `202604157[.]xyz` (`/snh5ye.sh` loader) |
| LLM-abuse source | `141[.]11[.]1[.]183` |
| SSH bruteforce | `45[.]148[.]10[.]183`, `45[.]156[.]87[.]254`, `45[.]148[.]10[.]240`, `2[.]57[.]122[.]177` |
| Botnet C2 | `217[.]60[.]195[.]113` (AE), `14[.]46[.]136[.]77` (KR), `213[.]108[.]21[.]95` (NL, Aeza) |
| SHA256 | `f9ec1b33dfc61dad616223f2eef5a80d3b9b9165e9035b574eb436b34a78ee8e` (Mirai ELF32) |
| SHA256 | `21811956167f72dcde22d8c16857cb63e0026c949dd1fcbb1f42d3943f5997dd` (Panchan SSH-worm ELF64) |
| SHA256 | `4a75c5d3fade1815d3f14d4da775111370d769cc48284ea78a6314c1f717b903` (MAL_ELF_Xlogin) |
| User-Agent | `node-fetch/1.0 (+https://github.com/bitinn/node-fetch)` (LLM scanner) |
| Cmd pattern | `chroot /host sh -c` (Docker escape-to-host) |

**MITRE ATT&CK:** T1595.002, T1110, T1046, T1190, T1610, T1611, T1496, T1552.005, T0846, T0888

---

### 2026-07-06 — XWorm V7.1 — Spoofed-FESCO "Signed Contract" Logistics Phishing Campaign

An inbound email honeypot gateway we operate captured a phishing email that spoofed the Russian sea carrier FESCO (PJSC VMTP, Vladivostok Commercial Sea Port), subject "Подписанный договор" ("signed contract"). The attachment `Contract9021_06_07_26.r11` is named as a RAR volume but is in fact a ZIP archive (magic `PK`) containing a single PE, `Contract9021_06_07_26.exe`, posing as the contract. The message failed SPF (real sender `89.108.121[.]15`, HELO `rpnmail.fmf.ru`; envelope-from `abersenyov@fesco.com` forged). Sandbox detonation extracted an XWorm V7.1 configuration: C2 `109.248.150[.]234:443`, AES traffic key, and mutex. A C2 pivot revealed an active campaign — 34 samples, all XWorm, all sharing one mutex and one AES key (a single operator/build), themed around maritime freight (bills of lading HBL/MBL, "pre-alert" shipping notices, contracts), with waves from 2026-06-18 onward.

**Key findings:**
- XWorm V7.1 .NET RAT delivered as a ZIP archive disguised with a `.r11` (fake RAR-volume) extension — evades naive extension- and archive-based filtering.
- C2 `109.248.150[.]234:443` hosted on AS203557 (SIA RixHost / DATACLUB-NL, Netherlands); the box is a Windows Server 2019 with RDP/WinRM exposed. Tracked as an XWorm C2 in ThreatFox since 2026-06-18, yet AbuseIPDB reputation is 0/100 (under-reported).
- Dedicated, single-tenant C2: all 34 pivoted samples are XWorm with an identical mutex (`70vLmgcqMEnUJOeL`) and AES key — one operator, no other malware families or web hosting on the IP.
- Capabilities: process injection, AMSI enumeration, Windows Defender tampering via PowerShell, autorun persistence, Outlook/email/browser credential and cookie theft, USB propagation, and hardware-ID anti-sandbox checks.
- Delivery evasion mirrored in a `.vbs`-in-ZIP variant that pulls a stager from `185.27.134[.]124`.

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-07-06-xworm-fesco-logistics/Incident_Report_2026-07-06_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-07-06-xworm-fesco-logistics/Incident_Report_2026-07-06_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-07-06-xworm-fesco-logistics/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-07-06-xworm-fesco-logistics/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| C2 IP | `109.248.150[.]234` (XWorm, port 443; AS203557 SIA RixHost / DATACLUB-NL, NL) |
| Stager IP | `185.27.134[.]124` (.vbs variant) |
| Sender IP | `89.108.121[.]15` (spoofed-FESCO MTA, SPF Fail) |
| ASN | `AS203557` (SIA RixHost / DATACLUB-NL) |
| Email | `ABersenyov@fesco[.]com` (spoofed From) |
| SHA256 | `37f7127bcae8388c61432dc2d46b0df36cb33690ebbc5b725b28b33dfb145d4b` (dropper EXE) |
| MD5 | `5053320a66a5c4989c44a932a8720b7d` (dropper EXE) |
| SHA256 | `e8e901194d86b29166d6028cc97d3b7559ecff413f20cd7b7f84601c2d9f2709` (ZIP-as-.r11 attachment) |
| SHA256 | `f9183d461a9ef71e1a0a97ddef54f5a785c3d4fa1ac6cb979a82206a52037928` (config/payload) |
| SHA256 | `7776706d26fb2dfd7cb96910810bb4c3a02b343a228035a0ca4db3ccf8e4d26a` (related, same C2) |
| SHA256 | `d4bc7db58a0b6207d2d24336833ae73a8cac77bf9f6bfe68ad1c33b52f990d0d` (related, same C2) |
| SHA256 | `6bdd98cecb7ecf8240b8fd57497a952dd2850075339b3932f4e2c2285dda00c6` (related, same C2) |
| SHA256 | `c8c385c10b1586728318f43b9dcafecfd46d8d6000984fe489bb1d219ea8b4f9` (related, same C2) |
| SHA256 | `70c2fe27f67d5bd45f18c826a1dc1f852fa86b2de8271151a7b8c4d6d58f34d7` (related, same C2) |
| SHA256 | `fe126b87922ff8049c4b19d6588324a3bb4874020b943e86de176445ebe7c7b9` (related, same C2) |
| Mutex | `70vLmgcqMEnUJOeL` |
| AES key | `bK5bLIZIB9durXZWd5PDkvR0hpNHk04+uqD7mNo2KtY=` (C2 traffic) |
| Install | `%AppData%\bin.exe` (autorun persistence) |

**MITRE ATT&CK:** T1566.001, T1204.002, T1036.008, T1055, T1547.001, T1053.005, T1562.001, T1059.001, T1091, T1539, T1497, T1573

---

### 2026-06-09 — Honeypot Fleet: Monthly Threat Report, May 2026

Over May 2026 our distributed honeypot sensors (Germany, the United States and Russia) recorded roughly 911,000 attack events across SSH, multi-protocol exploitation, Docker, LLM, MikroTik and Kubernetes surfaces. The headline development is the continued maturation of attacks against self-hosted LLM inference endpoints (Ollama, llama.cpp) — now extending beyond compute theft into SSRF-based theft of cloud credentials. Other notable activity includes ongoing SSH targeting of Solana validators, multi-architecture Mirai/Gafgyt droppers, a dominant WannaCry/SMB stream in captured malware, and the first IEC-104 (ICS/OT) reconnaissance against a newly deployed protocol decoy.

**Key findings:**
- Attacks on LLM inference endpoints (~75,300 requests): ~95% scanning, ~3.7% inference/compute theft, and — new this month — ~0.5% SSRF pivots toward cloud metadata (`169.254.169.254`) for IAM credential theft. Persistent operator `203[.]159[.]90[.]152` (AS210558, Stark-linked per open sources) active across March–May.
- Solana validator targeting via SSH: dictionaries carry `sol`/`solana`/`solv` usernames and matching passwords.
- Multi-architecture Mirai/Gafgyt droppers: 85 downloads, 33 unique SHA-256 from four primary dropper servers; arch-selection fingerprint `/bin/./uname -s -v -n -r -m` (578×).
- Captured malware (126 unique samples, all malicious): ~85 are PE32 WannaCry/EternalBlue DLLs; ClamAV produced zero detections — current stream caught only by YARA/imphash.
- IEC-104 (ICS/OT) protocol decoy, preliminary: external activity was reconnaissance only (connects and general interrogations); no attacker-issued control commands were observed.

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-06-09-honeypot-monthly-may/Incident_Report_2026-06-09_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-06-09-honeypot-monthly-may/Incident_Report_2026-06-09_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-06-09-honeypot-monthly-may/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-06-09-honeypot-monthly-may/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| IP | `203[.]159[.]90[.]152` (LLM-abuse, AS210558 1337 Services GmbH, Stark-linked per open sources) |
| IP | `37[.]19[.]210[.]21` (LLM-abuse top source, AS212238 Datacamp/CDN77, likely VPN exit) |
| IP | `103[.]77[.]246[.]174` (Mirai/Gafgyt dropper, AS140810 Megacore, VN) |
| IP | `45[.]81[.]234[.]64` (Mirai/Gafgyt dropper `/10Gbins.sh`, AS44486 synlinq.de, DE) |
| IP | `202[.]71[.]14[.]246` (Mirai/Gafgyt dropper `proto.*`, AS43641 Sollutium EU, NL) |
| IP | `209[.]92[.]170[.]225` (Mirai/Gafgyt dropper `lmkjn.*`, AS212238 Datacamp, MY) |
| IP | `14[.]46[.]136[.]77` (Botnet C2, AS4766, KR) |
| IP | `151[.]242[.]125[.]187` (Botnet C2, HK) |
| IP | `87[.]121[.]79[.]73` (Botnet C2, AS199428, BG) |
| IP | `45[.]70[.]90[.]106` (Top SSH bruteforce, AS52477 ApInter, AR) |
| IP | `185[.]156[.]74[.]10` (Top SSH bruteforce, AS210848 Telkom Internet, NL) |
| IP | `45[.]153[.]34[.]149` (Top SSH bruteforce, AS51396 Pfcloud UG, NL) |
| SHA-256 | `a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2` (Mirai/Gafgyt ELF) |
| SHA-256 | `0a731d26eeb377a3f101bd4941e700ab87076cc7a50a0bb99f2b683b6266d351` (dropper `wget.sh`) |
| UA | `ollama/0.0.0 (amd64 linux) Go/go1.26.3` (LLM scanner, official Ollama Go client) |
| UA | `EchelonGraph-ShadowAIRadar-Verifier/1.0` (commercial AI-asset scanner) |
| URL-path | `/props` (llama.cpp inference probe) |
| URL-path | `/rest/oauth2-credential/callback` (n8n credential probe) |

**MITRE ATT&CK:** T1595.002, T1110, T1046, T1190, T1610, T1496, T1552.005, T1078.004, T0855, T0836

---

### 2026-05-27 — MSSQL Brute-force Farm and RDP Bruteforcer — zerolimit-servers.cool / AS205997

A coordinated brute-force farm operating from 194.113.39.0/24 was identified targeting MSSQL servers (TCP/1433) globally. The infrastructure consists of exactly 10 Windows VPS nodes deployed with a uniform automated profile and a centralised Go-based control panel at 194.113.39.2:8443 with a self-signed TLS certificate bearing Subject O=MSSQL Panel — the only instance of this certificate observable across the entire internet at time of analysis. The farm is operated by Vlad Cojuhari (Moldova/Ukraine), owner of AS205997 (zerolimit-servers.cool), announced via AS206378 (FOP Dmytro Nedilskyi, UA/PL) with bulletproof upstream AS202425 (IP Volume inc.). A related subnet 185.218.138.0/24 (AS205997) hosts five nodes running an "Ultimate RDP bruteforcer" panel; the same tool was identified on two externally-operated hosts in Bulgaria (AS209702) and Poland (AS201814), suggesting the tool is being sold or shared.

**Key findings:**
- C2 panel at `194[.]113[.]39[.]2:8443`: self-signed TLS cert `O=MSSQL Panel`, SHA-256 `fb3aa028...e131a` — globally unique (Shodan `ssl:"MSSQL Panel"` returns exactly 1 result); Go HTTP server with Basic-auth; deployed 2026-05-16
- MSSQL farm: 10 Windows VPS at 4-address intervals (.2/.6/.10/.14/.18/.22/.26/.30/.34/.38), all sharing RDP JARM `14d14d16...f532` and JA3S `ba1b42ef...c1b` — typical default Windows Server without domain membership; independent SSH host keys indicate scripted provisioning
- Operator attribution: Vlad Cojuhari (ORG-ZA297-RIPE, Constantin Brancusi St 3, MD); RIPE abuse contact `ban-me-please@zerolimit-servers[.]cool` is an explicit bulletproof indicator; network created 2026-01-30
- Infrastructure chain: AS205997 (Cojuhari direct) → announced via AS206378 (FOP Dmytro Nedilskyi, linked to CleanTalk-listed AS211736) → upstream AS202425 (IP Volume inc., successor to Ecatel/Quasi Networks)
- RDP bruteforcer: "Ultimate RDP bruteforcer" panel (port 9090, Last-Modified 2026-05-08) found on 5 nodes in 185.218.138.0/24 and 2 external hosts — tool is being distributed beyond the primary operator
- All 10 MSSQL farm IPs appear in global honeypot feeds (OTX 50 pulses on .2 alone, active from 2026-04-22), zero malware payload hosting — purely credential-access infrastructure

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-05-27-mssql-botnet-zerolimit/Incident_Report_2026-05-27_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-05-27-mssql-botnet-zerolimit/Incident_Report_2026-05-27_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-05-27-mssql-botnet-zerolimit/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-05-27-mssql-botnet-zerolimit/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| IP | `194[.]113[.]39[.]2` (C2 panel + bot, AS206378) |
| IP | `194[.]113[.]39[.]6` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]10` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]14` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]18` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]22` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]26` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]30` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]34` (MSSQL bot, AS206378) |
| IP | `194[.]113[.]39[.]38` (MSSQL bot, AS206378) |
| Subnet | `194[.]113[.]39[.]0/24` (MSSQL farm, AS206378 / Vlad Cojuhari) |
| IP | `185[.]218[.]138[.]3`, `185[.]218[.]138[.]5`, `185[.]218[.]138[.]16`, `185[.]218[.]138[.]17`, `185[.]218[.]138[.]29` (RDP bruteforcer, AS205997) |
| IP | `80[.]66[.]66[.]68` (RDP bruteforcer external user, AS209702, BG) |
| IP | `109[.]205[.]211[.]4` (RDP bruteforcer external user, AS201814 Mevspace, PL) |
| Domain | `zerolimit-servers[.]cool` (operator brand / ASN website) |
| TLS SHA-256 | `fb3aa028387ecc371879ac10e123064050e766e6174fe4d1ddd1011db15e131a` (MSSQL Panel cert, unique globally) |
| ASN | AS205997 (Vlad Cojuhari — operator) |
| ASN | AS206378 (FOP Dmytro Nedilskyi — announces 194.113.39.0/24) |

**MITRE ATT&CK:** T1583.003, T1583.005, T1110.001, T1595.001, T1595.002, T1071.001

---

### 2026-05-12 — BEC via Compromised NGO Mailbox + Tycoon 2FA AiTM Phishing Kit

A phishing email was delivered from a legitimate Microsoft 365 mailbox belonging to a French non-profit organisation, using three evasion layers: genuine M365 account compromise (bypassing SPF/DKIM/DMARC), thread hijacking with a real French-language medical conversation as context, and a Microsoft Customer Voice (nam.dcv.ms) short-link that resolves through a trusted Microsoft service. The final destination is a Tycoon 2FA / Mamba 2FA class Phishing-as-a-Service (PaaS) kit on a RackNerd VPS, equipped with a fake Gmail CAPTCHA, an XOR-obfuscated cloud-IP filter, and an AiTM mechanism that harvests session cookies to bypass MFA. Seven parallel phishing domains were identified on the same infrastructure cluster, all provisioned on April 17, 2026.

**Key findings:**
- Account compromise (not spoofing): email transited genuine Exchange Online EU servers (`DB9PR08MB6809.eurprd08.prod.outlook.com`); Message-ID format confirms real M365 mailbox send
- Thread hijacking: attacker embedded a real March 2026 French-language medical exchange from the victim's mailbox as contextual camouflage; forged signature presents a psychologist as "Chief Financial Officer"
- Microsoft Customer Voice (`nam.dcv.ms`) abused as a trusted intermediary stage — this scheme has run for 12+ months with 100+ observed campaign scans across English, German, Spanish, and Indonesian targets
- Tycoon 2FA / Mamba 2FA kit: CAPTCHA gate + XOR-obfuscated `api.ipapi.is` sandbox-IP filter + AiTM session-cookie harvester (Laravel backend, `samesite=none`) on Cloudflare-fronted RackNerd VPS
- Kit fingerprint: XOR key `3HO3y7Soso1HgJPsnDn2pg==`, decoy redirect to `www[.]meituan[.]com`, URL pattern `/u@<token>/`, recurring typo "FILED" instead of "FILE" in form title
- Seven disposable domains on `198[.]23[.]210[.]61` (AS36352 RackNerd, Chicago), all using Tencent DNSPod NS, all with Let's Encrypt certificates issued 2026-04-17

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-05-12-bec-thread-hijacking-tycoon2fa/Incident_Report_2026-05-12_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-05-12-bec-thread-hijacking-tycoon2fa/Incident_Report_2026-05-12_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-05-12-bec-thread-hijacking-tycoon2fa/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-05-12-bec-thread-hijacking-tycoon2fa/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| IP | `198[.]23[.]210[.]61` (RackNerd/ColoCrossing AS36352 — PaaS phishing VPS) |
| Domain | `stiofidri[.]company` (Tycoon 2FA kit — primary domain) |
| Domain | `giochogio[.]company` (cluster) |
| Domain | `crepeawi[.]business` (cluster) |
| Domain | `crivesha[.]company` (cluster) |
| Domain | `driocriodio[.]app` (cluster) |
| Domain | `beawoushoo[.]digital` (cluster) |
| Domain | `shodiothai[.]enterprises` (cluster) |
| URL | `hxxps://stiofidri[.]company/u@xTBw1Q9qK4Qb0ZS9gxFUS/` (payload URL) |
| URL | `hxxps://nam[.]dcv[.]ms/o9XDteis3W` (Microsoft Customer Voice short-link used as lure, form now 404) |
| Kit artifact | XOR key `3HO3y7Soso1HgJPsnDn2pg==` (anti-sandbox JS) |

**MITRE ATT&CK:** T1583.001, T1583.004, T1586.002, T1078.004, T1566.002, T1566.003, T1656, T1036.005, T1027.013, T1497.001, T1480, T1539, T1056.003, T1114.002

---

### 2026-05-07 — Honeypot Threat Intelligence: Monthly Report, April 2026

A distributed honeypot network spanning nodes in Germany (DE/Hetzner), the United States (US/HOSTKEY), and Russia (RU/SelectEl) — with a new ICS/OT node launched in Poland on April 28 — recorded 578,657 SSH login attempts, 654 unique malware samples (100% confirmed malicious), and over 236,000 SIP/VoIP scanning events during April 2026. WannaCry-matching PE32 binaries remain in active distribution (884 YARA hits). A coordinated SSH campaign specifically targeted Solana validator usernames (`sol`, `solana`, `solv`) with 37,000+ combined attempts. Attackers are increasingly targeting AI inference infrastructure: 54,032 unauthorized requests were logged against the Ollama API honeypot and 1,049 Docker API sessions were classified as LLM-abuse. A Go-based SSH worm matching Panchan was observed using Discord as a secondary C2 channel. TLS analysis identified 3,383 sessions to `api[.]telegram[.]org`, consistent with Telegram Bot API used as C2 transport.

**Key findings:**
- WannaCry YARA rule triggered on 884 PE32 samples — legacy ransomware propagation mechanisms remain a live threat in 2026
- Coordinated Solana validator targeting: 37,000+ SSH attempts against `sol`, `solana`, `solv` usernames — deliberate blockchain infrastructure focus
- 54,032 unauthorized Ollama API inference requests + 1,049 Docker API LLM-abuse sessions — growing attacker interest in hijacking AI compute
- 3,383 TLS sessions to `api[.]telegram[.]org` from honeypot nodes — malware families using Telegram Bot API as C2 channel
- Panchan Go SSH worm detected with Discord as secondary C2; Mirai variant using XOR-obfuscated C2 domains (keys `0x22355627`, `0x544f4e49`)
- Attack-correlated events traced to Aeza International (21 hits, EU/US sanctioned hoster) and Proton66 OOO (8 hits, known bulletproof hosting)
- New ICS/OT honeypot (PL node) emulating Modbus, IEC 61850, DNP3, S7 launched April 28; attracted traffic within hours
- 184 abuse reports generated; 35 submitted to ISPs; top sources: DigitalOcean (1,835 hits), OVH (436), Amazon AWS (430)

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-05-07-honeypot-monthly-april/Incident_Report_2026-05-07_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-05-07-honeypot-monthly-april/Incident_Report_2026-05-07_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-05-07-honeypot-monthly-april/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-05-07-honeypot-monthly-april/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| C2 domain | `api[.]telegram[.]org` (Telegram Bot API used as malware C2 transport) |
| Cryptominer URL | `xmrig[.]com` (XMRig miner delivery) |
| Mining pool | `nicehash[.]com` (NiceHash pool endpoint) |
| C2 platform | Discord (secondary C2 for Panchan/Discord_C2_ELF family) |
| IP lookup | `api[.]ipify[.]org` (anti-GeoFencing recon by malware) |
| Attacker ASN | AS204603 — Aeza International (EU/US sanctioned) |
| Attacker ASN | AS197695 — Proton66 OOO (bulletproof hosting) |
| YARA | `WannaCry_Ransomware` — 884 hits on PE32 samples |
| YARA | `Panchan_SSHWorm_Go` — 6 hits on Go ELF binaries |
| YARA | `Discord_C2_ELF` — 7 hits on Linux ELF samples |
| YARA | `MAL_ARM_LNX_Mirai_Mar13_2022` — 2 hits (XOR C2 keys `0x22355627`, `0x544f4e49`) |

**MITRE ATT&CK:** T1110.001, T1190, T1496, T1071.001, T1059.004, T1027, T1583.003, T1102.002

---

### 2026-05-03 — Phishing via Compromised PSL Mailbox: Lovable.app Front + .ru Credential Harvester

A targeted phishing email was delivered through a compromised Microsoft 365 mailbox in the Université Paris Sciences & Lettres (PSL, France) tenant. All authentication checks (DKIM, SPF, DMARC) pass for `psl.eu` — this is end-to-end authenticated delivery from a hijacked account, not spoofing. The attack is two-stage: the email leads to a purpose-built landing page on Lovable.app (an AI no-code site builder that hands out free wildcard TLS), and a single button on that page forwards the victim to the real target — `dotiojea[.]ru`, a credential harvester in the .ru zone with a per-victim token in the URL path.

**Key findings:**
- Genuine M365 outbound (`PR0P264CU014.outbound.protection.outlook.com`) from PSL tenant `4f8fd695-b3b5-4082-8005-610e9453e6d0` — DKIM/SPF/DMARC all pass for `psl.eu`
- Stage 1 landing on `amendment-gateway[.]lovable[.]app` — React SPA on Lovable AI no-code builder (project ID `bb952617-8387-4712-a353-768d866d428a`), wildcard TLS by Google Trust Services, Cloudflare front (AS13335)
- Stage 2 final target `hxxps://dotiojea[.]ru/{per-victim-token}/`, registered 2026-03-24 at R01-RU as a "Private Person", status REGISTERED, DELEGATED, **UNVERIFIED**, NS on Tencent DNSPod
- DNS zone of `dotiojea[.]ru` removed at analysis time (DNSPod NXDOMAIN sentinel) — campaign infrastructure already taken down or self-removed
- Per-victim path tokens (`/ojEyxTnj@JqGnH/`, `/z58!zTjKI/`) — pattern of modern AiTM kits (EvilProxy / Tycoon / Caffeine class)
- Systemic abuse of Lovable.app: urlscan.io shows 230+ phishing-tagged scans on `*.lovable.app` since late 2025 (AT&T, betting fraud, crypto-drainers, brand impersonation)

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-05-03-phishing-amendment-gateway/Incident_Report_2026-05-03_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-05-03-phishing-amendment-gateway/Incident_Report_2026-05-03_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-05-03-phishing-amendment-gateway/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-05-03-phishing-amendment-gateway/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Email subject | `2026 Amend Proposal YF-W-SW89537` |
| Compromised sender | `aissata-keltoum.drame@psl[.]eu` |
| M365 tenant ID | `4f8fd695-b3b5-4082-8005-610e9453e6d0` (Université PSL) |
| Outbound MX | `PR0P264CU014.outbound.protection.outlook.com` (`2a01:111:f403:c20a::4`, MS France-Central) |
| EML SHA-256 | `2d0536dfbbce46c92f588a97da471322bf501111a3eb04d835ffe8e3b84fb70d` |
| Landing URL | `hxxps://amendment-gateway[.]lovable[.]app/` |
| Lovable project ID | `bb952617-8387-4712-a353-768d866d428a` |
| Landing IP | `185[.]41[.]148[.]1`, `185[.]41[.]148[.]2` (AS13335 Cloudflare) |
| Landing JS SHA-256 | `6462db810635dcd49271a491e49af9b481b8acc13be3562341abda7b377200b8` |
| Final URL #1 | `hxxps://dotiojea[.]ru/ojEyxTnj@JqGnH/` |
| Final URL #2 (related) | `hxxps://dotiojea[.]ru/z58!zTjKI/` |
| Final domain | `dotiojea[.]ru` (R01-RU, registered 2026-03-24, UNVERIFIED) |
| Final NS | `a.dnspod.com`, `c.dnspod.com` (Tencent DNSPod) |

**MITRE ATT&CK:** T1583.001, T1583.006, T1586.002, T1078.004, T1566.002, T1564.011, T1539, T1606

---

### 2026-04-05 — Telegram Account Hijacking via Phishing VPN Bot Mini App

An active phishing campaign targeting Telegram account hijacking was identified, disguised as a free VPN service for bypassing Telegram restrictions in Russia. The attack uses the channel @vpnztelegram as a lure, the bot @Aimashbot ("Mash VPN Bot") as a funnel, and a Telegram Mini App (WebApp) hosted on bulletproof infrastructure as the phishing page. Source code analysis of the Mini App revealed a full account hijacking operation: phone number collection via `requestContact()`, authorization code interception (5-digit code), and cloud password (2FA) theft. After successful hijacking, victims are redirected to a legitimate VPN bot to mask the compromise.

**Key findings:**
- Full Telegram account hijacking via Mini App: phone → auth code → 2FA password
- Phishing Mini App hosted on `aerobot20[.]sbs`, content proxied via Telegram MTProto (invisible in client DNS)
- Homoglyph text obfuscation: mixed Cyrillic/Latin characters to evade automated detection
- Post-hijack redirect to legitimate @DureVpnBot (291K MAU) via referral link for dual monetization
- Campaign matches F6-documented mass wave (Feb 2026, ~4,800 incidents in 2 months)
- Channel @vpnztelegram: 1,650 subscribers, 24,300 views on single post — aggressive spam distribution

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-04-05-telegram-vpn-hijacking/Incident_Report_2026-04-05_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-04-05-telegram-vpn-hijacking/Incident_Report_2026-04-05_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-04-05-telegram-vpn-hijacking/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-04-05-telegram-vpn-hijacking/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `aerobot20[.]sbs` |
| Domain | `qqeki982.aerobot20[.]sbs` |
| IP | `104[.]21[.]8[.]168` (Cloudflare CDN) |
| IP | `172[.]67[.]139[.]203` (Cloudflare CDN) |
| URL | `hxxps://qqeki982.aerobot20[.]sbs/checkstatus.php` |
| Telegram Channel | `@vpnztelegram` |
| Telegram Bot | `@Aimashbot` ("Mash VPN Bot") |
| Telegram User | `@aimash` (probable operator) |

**MITRE ATT&CK:** T1566.003, T1598.003, T1078, T1539, T1656

---

### 2026-04-04 — Instagram Credential Phishing via Compromised Telegram Accounts

A cross-platform phishing campaign targeting Ukrainian-speaking users was identified. Attackers compromise Telegram accounts and mass-message all contacts with a "vote for a child in a drawing contest" lure. The link leads to a reverse-proxied Instagram login page hosted on bulletproof infrastructure. The server proxies the real Instagram login, loading resources from static.cdninstagram.com, while intercepting submitted credentials server-side. The phishing kit supports full 2FA flow and uses Cloudflare Turnstile as an anti-bot gate.

**Key findings:**
- Cross-platform attack: Telegram as delivery channel, Instagram credentials as the target
- Reverse proxy phishing: real Instagram login page proxied through nginx, POST to /accounts/login/ajax/ intercepted server-side
- Full 2FA interception support (PolarisLoginActionGoToTwoFactorLogin modules)
- Wildcard DNS: any subdomain of va-kt[.]bayern resolves to the phishing server
- Only /ua/ and /uk/ routes active (Ukrainian audience targeting); all other prefixes return empty stubs
- Numeric path ID (1–1000+) used as victim/campaign tracking parameter
- Hosted on AS214351 (FEMO IT SOLUTIONS LIMITED) — Censys-classified BULLETPROOF hosting with 514 domains
- Same ASN hosts phishing domains impersonating BlaBlaCar, Stripe, Mercado Pago, Wise, SoFi, and others

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-04-04-instagram-phishing/Incident_Report_2026-04-04_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-04-04-instagram-phishing/Incident_Report_2026-04-04_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-04-04-instagram-phishing/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-04-04-instagram-phishing/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `va-kt[.]bayern` (wildcard DNS) |
| Domain | `friend[.]va-kt[.]bayern` |
| URL | `hxxp://friend[.]va-kt[.]bayern/ua/6` |
| IP | `62[.]60[.]226[.]50` (AS214351, Frankfurt DE) |
| ASN | AS214351 (FEMO IT SOLUTIONS LIMITED) |
| SSH HASSH | `41ff3ecd1458b0bf86e1b4891636213e` |

**MITRE ATT&CK:** T1586.002, T1566.002, T1598.003, T1036.005, T1583.001, T1583.003, T1557

---

### 2026-03-31 — Mass Credential Phishing Campaign Impersonating Google Workspace

A large-scale credential phishing operation was identified targeting organizations across five countries. Phishing emails impersonate Google Workspace storage notifications and are delivered via a compromised Amazon SES account, spoofing a corporate domain with DMARC p=NONE. The phishing link traverses four redirect levels — Sophos Email Protection, bit.ly, Google redirect, and a compromised Brazilian website — before reaching a credential harvesting page disguised as a Cloudflare protection check. The page extracts the victim's email from the URL fragment (base64-encoded) and redirects to a C2 server running a Laravel application on a VDSina VPS in the Netherlands.

**Key findings:**
- Four-level redirect chain abusing legitimate services (Sophos, Google, bit.ly) to evade URL filtering
- Phishing kit with anti-analysis: blocks DevTools, right-click, keyboard shortcuts; emergency redirect on detection
- C2 infrastructure: 62 DGA-like .ru domains on a single IP (89[.]124[.]98[.]199), all using DNSPod (Tencent Cloud) nameservers
- Three parallel campaigns (gbe, sey, 5ppp) with a single MongoDB-based campaign panel active since August 2025
- Victims span NGOs, financial services, government (Ministry of Trade Malaysia), IT outsourcing, and healthcare
- Laravel backend with Cloudflare reverse proxy, but origin IP exposed through direct DNS resolution
- Compromised Amazon SES account (eu-west-1) with unique Feedback-ID fingerprint for detection

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-31-gworkspace-phishing/Incident_Report_2026-03-31_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-31-gworkspace-phishing/Incident_Report_2026-03-31_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-31-gworkspace-phishing/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-31-gworkspace-phishing/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| C2 Domain | `crooveazoo[.]ru` |
| C2 IP | `89[.]124[.]98[.]199` (AS216071, VDSina NL) |
| C2 Path | `/HeJK!UMT/$` |
| Phishing Host | `lasys[.]com[.]br` (compromised, 69[.]6[.]213[.]189) |
| Phishing Paths | `/teste/gbe/ccc/`, `/teste/sey/ccc/`, `/teste/5ppp/ccc/` |
| Sender Domain | `ejm[.]org` (spoofed, DMARC p=NONE) |
| SES IP | `54[.]240[.]4[.]15` (Amazon SES eu-west-1) |
| bit.ly | `bit[.]ly/4rVLObb`, `bit[.]ly/41muSA5`, `bit[.]ly/4bGmwcs` |
| SSH Host Key | `23c5cfe5298cc99c7f7a02e236d6cc9c4fc22e8f85c0d064f45a93c8b92b30b0` |
| Reserve Domains | 61 additional .ru DGA domains on same IP (full list in report) |

**MITRE ATT&CK:** T1566.002, T1583.001, T1583.006, T1584.004, T1078, T1608.005, T1027, T1497.001

---

### 2026-03-27 — ClickFix Social Engineering Campaign Delivering Vidar Stealer via Fake Cloudflare CAPTCHA

A social engineering attack using the "ClickFix" technique was observed targeting users through a compromised Hebrew language school website (oulpansheli[.]org). The page displayed a fake Cloudflare "Verify you are human" dialog instructing victims to open PowerShell as administrator and paste a "verification code." The clipboard payload was an XOR-obfuscated PowerShell command (key: PuHNJs) that downloaded and executed a Go-based crypter ("blindcousin") from productionmaza[.]cyou. The crypter decrypted an embedded Vidar Stealer v1.0 payload using a custom 5-round XOR/SUB algorithm. The stealer exfiltrated browser credentials, cookies, Outlook profiles, and system information to a Hetzner-hosted C2 server, with Telegram and Steam Community profiles serving as dead drop resolvers for backup C2 addresses.

**Key findings:**
- Three-stage attack chain: ClickFix social engineering → Go crypter with custom encryption → Vidar Stealer
- Go loader "blindcousin" uses garble obfuscator with 5-round decryption (XOR, SUB, byte-swap, reverse)
- Vidar v1.0 with botnet ID 4c0a49bed86cb25165c2f64c7c27c48a confirmed by Recorded Future Triage (score 10/10)
- C2 at 78[.]46[.]199[.]184 (Hetzner DE) with self-signed TLS certificate, domain neugepower[.]net
- Dead drop resolvers: Telegram channel t[.]me/v2ts23m contains backup C2 domain skfilmsint[.]com
- Steam profile 76561198724155486 used as additional dead drop resolver
- Process injection into Chrome and Edge browsers for credential theft
- Targets: Chrome/Edge cookies and credentials, Outlook email profiles (v14.0-16.0), system hardware fingerprinting

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-27-clickfix-vidar/Incident_Report_2026-03-27_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-27-clickfix-vidar/Incident_Report_2026-03-27_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-27-clickfix-vidar/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-27-clickfix-vidar/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `oulpansheli[.]org` (compromised landing page, OVH FR) |
| Domain | `productionmaza[.]cyou` (payload delivery, Cloudflare) |
| Domain | `neugepower[.]net` (C2 domain, Hetzner) |
| Domain | `skfilmsint[.]com` (backup C2, NameCheap/Cloudflare) |
| IP | `78[.]46[.]199[.]184` (Vidar C2, Hetzner DE) |
| IP | `213[.]186[.]33[.]16` (landing page, OVH FR) |
| IP | `172[.]67[.]148[.]28` (Cloudflare proxy, productionmaza) |
| IP | `104[.]21[.]55[.]125` (Cloudflare proxy, productionmaza) |
| URL | `hxxps://oulpansheli[.]org/ru/` |
| URL | `hxxps://productionmaza[.]cyou/api/index.php?a=dl&token=fcdd5b796fbf5cb5614da7aaa4773fb404771c4821e4b8d30305ed8df58a2188&src=cloudflare&mode=cloudflare` |
| URL | `hxxps://telegram[.]me/v2ts23m` (dead drop) |
| URL | `hxxps://steamcommunity[.]com/profiles/76561198724155486` (dead drop) |
| SHA256 | `e2f6f791dd32b18fd7a002efce17fdd039f69809f7ddabeda9d0de1035da82d9` (Go loader) |
| SHA256 | `4a788d7009f7cd13fda4291461e67191bc4b9c34e16761796e0457810fe5bba8` (Vidar payload) |
| SHA256 | `4d4cd6ee9165a7b5e1bb8c7e91e2d62cb9db662b415900959785d24a59188a42` (ZIP archive) |
| Botnet | `4c0a49bed86cb25165c2f64c7c27c48a` |
| Mutex | `ChromeBuildTools` |

**MITRE ATT&CK:** T1204.002, T1059.001, T1027.013, T1140, T1105, T1036.005, T1584.001, T1071.001, T1070.004, T1564.003, T1555, T1555.003, T1552.001, T1005, T1114, T1217, T1012, T1082, T1124

---

### 2026-03-09 — Gmail Workspace Credential Phishing via Commercial PhaaS Platform

A phishing email impersonating a Gmail Workspace system notification ("Release Incoming Messages from pooled storage") was delivered to a public-facing email address of a human rights organization. The email was sent through a legitimate SendGrid account (SPF/DKIM pass), using a compromised Indian company's domain as the sender identity. The phishing link led to a commercial Phishing-as-a-Service platform with a two-stage architecture: a browser fingerprinting framework (collector.js) screens visitors before showing the credential harvesting form. The fingerprinting includes WebGL GPU identification, WebRTC STUN requests to reveal real IPs behind VPNs, anti-bot prototype patching detection, and DevTools detection. The platform uses wildcard DNS on Cloudflare, generating unique subdomains per campaign. A licensing system was confirmed when the operator's subscription expired — the backend returned "Your license has expired."

**Key findings:**
- Two-stage phishing: landing page runs collector.js fingerprinting framework before redirecting to backend — bots, sandboxes, and researchers are filtered before the phishing form is shown
- Browser fingerprinting includes WebRTC STUN (stun.l.google.com:19302) to deanonymize VPN users, WebGL GPU fingerprint to detect VMs (SwiftShader/llvmpipe), and anti-automation checks
- Commercial PhaaS with licensing: expired license returns "Your license has expired. Please renew to continue using the service."
- Wildcard DNS on bitnest[.]za[.]com: any subdomain resolves to Cloudflare CDN, enabling instant campaign subdomain generation
- SendGrid abuse: account user_id=60417945, SPF/DKIM pass, inbox delivery guaranteed
- Infrastructure link: Reply-To domain (sevensounds[.]ae) and exquisite[.]za[.]com share the same IP (91[.]193[.]42[.]16) via hostingww.com — connecting the Reply-To infrastructure to the za.com phishing namespace
- Sender domain (oesplindia[.]com) is a legitimate Indian company with open FTP, MySQL, SNMP ports — likely compromised

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-09-gmail-phishing-phaas/Incident_Report_2026-03-09_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-09-gmail-phishing-phaas/Incident_Report_2026-03-09_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-09-gmail-phishing-phaas/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-09-gmail-phishing-phaas/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| URL | `hxxps://maxillae890[.]bitnest[.]za[.]com/testatrix449/` |
| URL | `hxxps://demo[.]bitnest[.]za[.]com/testatrix449/` |
| Domain | `bitnest[.]za[.]com` (PhaaS platform, wildcard DNS, Cloudflare) |
| Domain | `oesplindia[.]com` (compromised sender) |
| Domain | `sevensounds[.]ae` (Reply-To) |
| IP | `188[.]114[.]96[.]11` (Cloudflare CDN) |
| IP | `188[.]114[.]97[.]11` (Cloudflare CDN) |
| IP | `170[.]10[.]163[.]134` (LiquidNet US, AS14555) |
| IP | `91[.]193[.]42[.]16` (AMANKA SARL / AWS, AS16509) |
| IP | `149[.]72[.]123[.]24` (SendGrid) |
| Email | `sandeep@oesplindia[.]com` (From, compromised) |
| Email | `td@sevensounds[.]ae` (Reply-To) |
| SendGrid | User ID `60417945`, tracking: `u60417945[.]ct[.]sendgrid[.]net` |
| Script | `collector.js?v=21e981d0` (fingerprinting framework) |

**MITRE ATT&CK:** T1566.002, T1598.003, T1589.001, T1583.001, T1583.006, T1585.002, T1036.005, T1071.001, T1217

---

### 2026-03-15 — Mamont Banking Trojan: Telegram Phishing Disguised as "Accident Photos"

Distribution of the Mamont banking trojan via Telegram, observed on March 12, 2026. A victim received a message from a compromised contact — "Hey, remember him? He crashed" — with an attached HTML file that redirected to a Telegram channel hosting a malicious APK. The malware requests default SMS app permissions, exfiltrates banking SMS codes, and automatically forwards phishing messages to all contacts on the device. C2 is conducted entirely via Telegram Bot API. Mamont is the most prevalent Android banking trojan in Russia — Kaspersky reported a 36x increase in attacked users in 2025.

**Key findings:**
- Viral delivery: phishing message from a compromised real contact with emotional trigger ("He crashed"), HTML redirect to Telegram channel (376 subscribers)
- Default SMS app takeover: once granted, the trojan reads, sends, and hides SMS — enabling interception of bank OTP codes
- Telegram Bot API C2: operators control devices via bot commands (/getallsms, /send, /ussd, /spamallcontact, /hidemsg)
- Obfuscation: hidden DEX in assets/ with fake zlib header, renamed Android SDK packages, password-protected AndroidManifest.xml
- Targets 30+ Russian apps: 19 banks (Sberbank, Tinkoff, Alfa-Bank, etc.), payment systems (MIR Pay, QIWI), marketplaces (Wildberries, Ozon)
- SaaS model: control panel sold/rented (~$300/month), APKs auto-generated by builder — explains numerous independent operator groups
- Self-propagation: /spamallcontact command turns each victim into a new attack vector

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-15-telegram-dtp-mamont/Incident_Report_2026-03-15_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-15-telegram-dtp-mamont/Incident_Report_2026-03-15_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-15-telegram-dtp-mamont/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-15-telegram-dtp-mamont/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| SHA256 | `cc08aa94ad0a58c81ac6d7922db970271cce3c064e9e561157d2794bb80b7e79` |
| MD5 | `b787fff066ef4a03360cc3822289f9aa` |
| Package Name | `org.net.framework` |
| Telegram Channel | `hxxps://t[.]me/+XEAhWyIorixlODVl` ("Accident Photos 10.03") |
| Domain | `amuvvoafs[.]com`, `amuvvoafs[.]me`, `amuvvoafs[.]su` |
| Domain | `tlydtdl[.]me` |
| Lure File | `Запись происшествия.html` (Accident Record.html) |
| APK | `Фото_ДТП.apk` (Accident_Photos.apk) |

**MITRE ATT&CK:** T1660, T1204.002, T1398, T1406, T1407, T1417, T1636.004, T1636.003, T1418, T1481.002, T1646, T1582

---

### 2026-03-14 — Telegram Account Hijacking via Fake Voting Phishing Campaign

A phishing campaign targeting Russian-speaking Muslim communities was observed distributing fake "regional voting" links via Telegram. Victims clicking the link on a mobile device were shown a fake voting page with two candidates, then prompted to "authorize via Telegram to prevent fraud." The authorization step hijacked the victim's Telegram session, giving the attacker full account access. The campaign uses a professional Phishing-as-a-Service kit with polymorphic CSS obfuscation, anti-replay tokens, and User-Agent filtering (desktop users redirected to Google, Telegram bot previews suppressed). Infrastructure is hosted on Pitline Ltd (Kharkiv, Ukraine) bulletproof hosting — Censys labels the IP as BULLETPROOF (confidence 0.75). The same server hosts 11 co-located domains including 4 "vybory" (elections) domains. F6 (formerly Group-IB) documented this kit across 290+ domains since 2022.

**Key findings:**
- Professional phishing kit (PhaaS): polymorphic CSS class prefixes regenerated per request, anti-replay URL tokens, hidden junk HTML content for anti-detection
- 3-stage User-Agent filtering: mobile → phishing page, desktop → Google redirect, TelegramBot → 204 No Content (suppresses link preview)
- Server rebuilt from Windows (RDP/SMB) to Debian Linux specifically for this campaign (Censys Service History: Feb 12 → Mar 7, 2026)
- SSL certificate issued same day as attack (Let's Encrypt E7, 2026-03-14 11:16 UTC)
- 12 domains on single IP across 2 registrar clusters (Namecheap + Global Domain Group) with separate Cloudflare accounts — OPSEC compartmentalization
- Part of a documented mass campaign: F6 tracked 290+ domains using this template since 2022, peak activity February 2026 (39 domains/month)
- Viral distribution model: victims instructed to "forward to contacts," turning each compromise into a new attack vector

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-14-telegram-vote-phishing/Incident_Report_2026-03-14_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-14-telegram-vote-phishing/Incident_Report_2026-03-14_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-14-telegram-vote-phishing/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-14-telegram-vote-phishing/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `beaminkjet[.]com` |
| IP | `77[.]83[.]39[.]62` (Pitline Ltd, Kharkiv, UA — BULLETPROOF) |
| ASN | AS214940 (KPRONET) / AS215693 (PalmaHost) |
| Network | `77[.]83[.]36[.]0/22` (Pitline Ltd) |
| Email | `syimono1488@gmail[.]com` (WHOIS registrant) |
| URL | `hxxps://beaminkjet[.]com/umarashab` |
| Domain | `vybory[.]cyou`, `vybory[.]bond`, `vybory[.]sbs`, `vybory[.]cfd` |
| Domain | `vesna2026[.]cyou`, `vesna2026[.]cfd`, `vesna2026[.]sbs` |
| Domain | `onetop[.]sbs`, `onetop[.]cfd`, `onetop[.]bond`, `onetop[.]click` |
| Hash (MD5) | `8d1c6e9b6c08132c9bddf5128515ebcc` (phishing kit identifier in HTML comments) |
| SSL Serial | `06:f1:d4:14:46:8b:2d:48:b9:40:cb:a9:42:d2:24:6a:b9:e5` |

**MITRE ATT&CK:** T1566.002, T1204.001, T1036.005, T1027, T1539, T1056.003, T1556, T1583.001, T1583.003, T1588.002, T1608.002, T1550.004, T1589.001, T1070.004, T1213

---

### 2026-03-10 — Multi-Protocol Scanner with MCP Module Detected in Honeypot

A multi-service honeypot recorded a systematic reconnaissance campaign from a single IP address that probed 8 services in 10 minutes, including a JSON-RPC initialization request for the Model Context Protocol (MCP). This is the first documented observation of MCP scanning integrated into a multi-protocol scanner alongside traditional services such as SSH, MySQL, Docker API, and Winbox. The scanner identified itself as "gitmc-org-mcp-scanner v1.0.0" — a tool not found in any public repository.

**Key findings:**
- MCP `initialize` handshake (protocol version 2025-06-18) sent as part of a multi-service scan covering SSH, Telnet, HTTP/S, MySQL, Docker API, Memcached, and Winbox
- Full set of client capabilities requested: `sampling`, `elicitation`, `roots` — maximizing server response
- Scanner self-identifies as `gitmc-org-mcp-scanner v1.0.0` — no public references found
- Same IP attempted Docker API exploitation: `POST /v1.43/containers/create` with Image: alpine, Cmd: `cat /etc/shadow`
- SSH fingerprint: OpenSSH 10.2 with post-quantum KEX algorithms (mlkem768x25519-sha256)
- Source: residential DSL (Orange Polska, Warsaw) — likely purpose-built scanning system or residential proxy
- Context: GreyNoise saw no MCP payloads on honeypots in November 2025; by March 2026, MCP scanning is part of commodity scanners

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-10-mcp-scanner/Incident_Report_2026-03-10_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-10-mcp-scanner/Incident_Report_2026-03-10_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-10-mcp-scanner/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-10-mcp-scanner/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| IP | `95[.]51[.]243[.]130` (Orange Polska, Warsaw, PL) |
| rDNS | `ojl130[.]internetdsl[.]tpnet[.]pl` |
| User-Agent | `curl/8.7.1` |
| HASSH | `eeca2460550b9ded084ecf2f70a75356` (OpenSSH 10.2) |
| MCP client | `gitmc-org-mcp-scanner` v1.0.0 |
| MCP proto | `2025-06-18` |
| Docker path | `/v1.43/containers/create` (Image: alpine, Cmd: cat /etc/shadow) |

**MITRE ATT&CK:** T1595.002, T1046, T1190, T1610, T1613, T1552.001

---

### 2026-03-05 — WhatsApp Account Takeover via "Defisher" Phishing Kit

A phishing link distributed via Signal led to a WhatsApp account compromise through the device linking feature. The phishing site impersonated WhatsApp Web, tricking the victim into entering their phone number and then a device linking code. The attack was powered by a commercial phishing kit called "Defisher" — a Next.js application with an admin panel, WebSocket-based C2, and optional CIS country filtering.

**Key findings:**
- Phishing kit "Defisher": Next.js-based commercial tool with admin panel at `panel-my-test[.]online/auth`
- Two attack modes: QR code scanning and phone number-based device linking (phone mode used in this incident)
- WebSocket C2: phishing page communicates with backend via Socket.IO (`panel-my-test[.]online/api/socket`)
- CIS geo-filtering code present but **not active** in this campaign: source code contains `"Извините, ваш номер в зоне СНГ, ошибка"` handler, but active testing confirmed CIS numbers (RU, UA, KZ, BY) were accepted and received valid linking codes
- Infrastructure: AEZA Group (AS210644) — bulletproof hosting provider, FSB raid (Apr 2025), US OFAC sanctions (Jul 2025)
- Both domains registered 8 seconds apart (batch registration) via PDR Ltd., NS: timeweb.ru
- API endpoint exposed campaign stats: 210 views, 73 phone number inputs, campaign #8 on the server (at least 7 prior campaigns)
- Open Nginx Proxy Manager admin panel on port 81

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-05-whatsapp-defisher/Incident_Report_2026-03-05_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-05-whatsapp-defisher/Incident_Report_2026-03-05_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-05-whatsapp-defisher/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-05-whatsapp-defisher/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `trust-authorization[.]tech` (phishing page) |
| Domain | `panel-my-test[.]online` (C2 panel / WebSocket API) |
| IP | `147[.]45[.]43[.]133` (AEZA Group, AS210644, Frankfurt) |
| URL | `hxxps://trust-authorization[.]tech/pUsl9nuZo649dKua0HL7uG5npbYAq1bn` |
| URL | `hxxps://panel-my-test[.]online/api/socket` (WebSocket endpoint) |
| URL | `hxxps://panel-my-test[.]online/auth` (Defisher admin panel) |
| ASN | `AS210644` (AEZA-AS, bulletproof hosting) |
| Netblock | `147[.]45[.]43[.]0/24` (Aeza-Network) |
| SSH HASSH | `e42184b06d45385a906f0803d04c83da` |
| SSH Host Key SHA256 | `67e1fe70de94c56a515ae423ac6eded53e98a20cc7732114f661b372de82f934` |
| TLS Serial | `0571f6a08d8bad9c5aaad12c3a22a3012108` (trust-authorization[.]tech, LE E7) |
| TLS Serial | `06390e30192e8789eb02220f86d45db74a46` (panel-my-test[.]online, LE E8) |

**MITRE ATT&CK:** T1566.002, T1078, T1583.001, T1583.003, T1588.002, T1036.005, T1071.001, T1530

---

### 2026-03-02 — Targeted Phishing Impersonating Meta/Facebook Against a Human Rights NGO

A spear-phishing email impersonating Meta/Facebook was delivered to a Russian human rights NGO. The attackers chained legitimate services (Resend.com → Amazon SES) to achieve SPF pass, DKIM pass, and ARC pass, ensuring inbox delivery in Gmail. The phishing link led to a likely compromised legitimate British recruitment website, bypassing URL reputation filters.

**Key findings:**
- SPF, DKIM (×2), and ARC all passed — delivered to Gmail inbox, not spam
- Sending infrastructure: Resend.com email API → Amazon SES (ap-northeast-1, Tokyo) via domain registered at Sav.com (documented abuse issues)
- Phishing host: `skillbaseltd[.]co[.]uk` — confirmed domain hijacking after expiry (company in liquidation, cert evidence via crt.sh); bypasses URL reputation filters
- Broader infrastructure: cluster of 14 re-registered expired .co.uk domains on shared Cloudflare/cPanel hosting; 3 additional domains (`restorewellbeing[.]co[.]uk`, `rubyandginger[.]co[.]uk`, `senditmyway[.]co[.]uk`) have Resend+Amazon SES sending infrastructure pre-configured — staged for follow-on campaigns
- Display Name "M e t a" with spaces — evades brand-name filters matching exact string "Meta"
- Meta logo loaded directly from `facebook[.]com` — adds credibility and enables open tracking
- Targeted attack: recipient address associated with a specific organizational program, not publicly listed; email in Russian adapted to target profile

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-02-meta-phishing/Incident_Report_2026-03-02_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-02-meta-phishing/Incident_Report_2026-03-02_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-03-02-meta-phishing/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-03-02-meta-phishing/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Email | `identity-policy@readlundy[.]com` |
| Domain | `readlundy[.]com` (sending domain, registered Aug 15, 2025) |
| Domain | `send.readlundy[.]com` (Resend SPF domain) |
| Domain | `skillbaseltd[.]co[.]uk` (phishing host) |
| URL | `hxxps://skillbaseltd[.]co[.]uk/` |
| IP | `23[.]251[.]234[.]52` (Amazon SES, ap-northeast-1, Tokyo) |
| IP | `104[.]21[.]15[.]116` (Cloudflare CDN) |
| Message-ID | `0106019caf15ae50-9ddecc03-8e54-4d63-b110-5cf354fbf092-000000@ap-northeast-1.amazonses.com` |
| Domain | `restorewellbeing[.]co[.]uk` (related infra: Resend+SES staged) |
| Domain | `rubyandginger[.]co[.]uk` (related infra: Resend+SES staged) |
| Domain | `senditmyway[.]co[.]uk` (related infra: Resend+SES staged) |

**MITRE ATT&CK:** T1583.001, T1583.006, T1584.001, T1585.002, T1566.002, T1056.003, T1656, T1036

---

### 2026-02-18 — Targeted Phishing Impersonating National Endowment for Democracy

A spear-phishing campaign impersonating the National Endowment for Democracy (NED), targeting individuals in the NGO sector with fabricated grant opportunities. The email was sent from a compromised Zambian real estate domain via Russian VPS infrastructure.

**Key findings:**
- Highly targeted: victim addressed by full name with fabricated reference to a prior NED grant application
- Sender impersonated a fictitious NED employee "Daniel Knaus" (real employee John Knaus exists)
- Infrastructure: SmartApe VPS (Moscow, DataPro datacenter) → StableServer relay → AntiSpamCloud → Gmail
- SPF/DKIM passed for the sending domain, bypassing basic email authentication
- Phantom attachment technique: email references an attached document that doesn't exist in MIME structure
- Likely multi-stage attack: initial email establishes trust, malicious payload delivered in follow-up

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-02-18-ned-phishing/Incident_Report_2026-02-18_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-02-18-ned-phishing/Incident_Report_2026-02-18_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-02-18-ned-phishing/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-02-18-ned-phishing/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Email | `daniel.knaus@hunterspropertyzm[.]com` |
| Domain | `hunterspropertyzm[.]com` |
| IP | `188.127.227[.]111` (SmartApe VPS, Moscow) |
| Hostname | `s1277447.smartape-vps.com` |
| IP | `192.250.227[.]159` (stableserver.net relay) |
| IP | `185.201.18[.]54` (antispamcloud.com) |
| Message-ID | `177141183849.635335.*@s1277447.smartape-vps.com` |

**MITRE ATT&CK:** T1566.001, T1036.005, T1598, T1589, T1591, T1583.003, T1586.002, T1204.001, T1585

---

### 2026-02-13 — Phishing Campaign via Google Drive with Browser Fingerprinting

A phishing campaign abusing Google's legitimate infrastructure (Drive, Cloud Storage, Gmail) to deliver a browser fingerprinting payload hosted on bulletproof infrastructure (PROSPERO OOO, AS200593).

**Key findings:**
- Multi-hop delivery chain through trusted Google domains bypassing email filters
- FingerprintJS v4.2.1 + BotD for victim profiling and scanner evasion
- Advanced cloaking: automated scanners redirected to msn.com, real users fingerprinted
- Reconnaissance operation — fingerprint harvesting linked to email tracking IDs, not credential theft
- Infrastructure hosted on PROSPERO OOO (AS200593), a notorious bulletproof hosting provider labeled "BULLETPROOF" by Censys
- Same IP hosts multiple phishing campaigns: DocuSign impersonation (`docusign.notifyentryflow[.]com`) and additional domains active through late February 2026

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-02-13-google-drive-fingerprinting/Incident_Report_2026-02-13_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-02-13-google-drive-fingerprinting/Incident_Report_2026-02-13_RU.pdf)
- [IOCs (STIX 2.1)](reports/2026-02-13-google-drive-fingerprinting/iocs.stix2.json)
- [IOCs (MISP JSON)](reports/2026-02-13-google-drive-fingerprinting/iocs.misp.json)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `online.accessinformnotice[.]com` |
| Domain | `accessinformnotice[.]com` |
| Domain | `accessinformattention[.]com` |
| Domain | `docusign.notifyentryflow[.]com` (related: DocuSign impersonation, same IP) |
| Domain | `notifyentryflow[.]com` (related: parent domain) |
| Domain | `warningentrypath[.]com` (related: same IP, active Feb 26, 2026) |
| IP | `91.202.233[.]71` (PROSPERO OOO, St. Petersburg) |
| ASN | `AS200593` (PROSPERO OOO, bulletproof hosting) |
| Netblock | `91.202.233[.]0/24` |
| URL | `hxxps://online.accessinformnotice[.]com/secure/index_newest.html` |
| URL | `hxxps://online.accessinformnotice[.]com/secure/secure.php` |
| GCS | `hxxps://storage.googleapis[.]com/persontwelve/online/offer.html` |
| Google Drive | `hxxps://drive.google[.]com/file/d/18XPn0pHsygsvZcinTivBQ_I225l-xzpC` |
| Email | `neyjardespbeg2002@secure.accessinformattention[.]com` |
| Server | `Apache/2.4.41 (Ubuntu)` |
| FingerprintJS | `v4.2.1` |
| TLS Cert | `50f8484b5501e0132ef7ffc1614590845ccdc9375e53d81d2f7d7119a0387d3c` (SHA-256) |

**MITRE ATT&CK:** T1566.002, T1036.005, T1036.001, T1204.001, T1608.005, T1090, T1583.003, T1217, T1041, T1592.004, T1598

---

## Author

**Aleksei Fokin** — DevOps / Infrastructure Engineer, Warsaw, Poland

Contact: info@afokin.com

## License

All reports are published under [TLP:CLEAR](https://www.first.org/tlp/) — no restrictions on distribution.
