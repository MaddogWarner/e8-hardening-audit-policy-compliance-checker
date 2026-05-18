# Essential Eight Compliance Check

A read-only PowerShell audit script that checks key OS hardening controls on Windows hosts against the [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) maturity model.

## Requirements

- Windows 10 / 11 or Windows Server 2016 / 2019 / 2022
- PowerShell 5.1 or later
- Administrator privileges (script will not run without them)

## Usage

```powershell
.\essential8compliancecheck.ps1
```

The script is audit-only — it makes no changes to system settings.

## What It Checks

### Process & Memory Protection

| Check | What it looks for |
|---|---|
| LSASS Protected Process Light (PPL) | LSASS running as a protected process, blocking memory dumping tools |
| Memory Integrity / HVCI | Hypervisor-Protected Code Integrity active at runtime (Win 10 1709+ / Server 2019+) |
| Credential Guard | VBS-based Credential Guard running, protecting domain credential hashes |

### Audit Logging

| Check | What it looks for |
|---|---|
| Process Creation Command Line Logging | Full command-line arguments captured in Event ID 4688 |

### PowerShell Hardening

| Check | What it looks for |
|---|---|
| Script Block Logging | Full script block content logged to Event ID 4104 |
| Module Logging | Pipeline execution details logged to Event ID 4103 |
| Transcription | Full session transcript written to disk |
| PowerShell v2 Engine Disabled | Legacy PS v2 engine removed (bypasses AMSI and logging if present) |

### Windows Defender

| Check | What it looks for |
|---|---|
| Real-Time Protection | Defender real-time monitoring active |
| Cloud-Delivered Protection | MAPS/cloud protection enabled (basic or advanced) |
| Tamper Protection | Defender settings protected from unauthorised modification |

### Attack Surface Reduction (14 rules)

All 14 E8-relevant ASR rules checked for Block mode. Rules cover:

- Credential theft from LSASS
- Office macro and child process abuse
- Script obfuscation and interpreter abuse
- Executable content from email and USB
- WMI persistence
- Ransomware protection
- Vulnerable signed driver abuse

Each rule reports its current action: `Block`, `Audit`, `Warn`, or `Not Configured`. Only `Block` is considered compliant.

### Network Hardening

| Check | What it looks for |
|---|---|
| SMBv1 Disabled | Legacy SMBv1 protocol disabled (EternalBlue exposure) |
| SMB Signing Required | SMB packet signing enforced to prevent MITM tampering |
| Windows Firewall — Domain Profile | Firewall enabled for domain-joined networks |
| Windows Firewall — Private Profile | Firewall enabled for private networks |
| Windows Firewall — Public Profile | Firewall enabled for public networks |

### Remote Access

| Check | What it looks for |
|---|---|
| RDP Network Level Authentication (NLA) | NLA required before RDP session is established; skipped if RDP is disabled |

### Credential Protection

| Check | What it looks for |
|---|---|
| WDigest Plaintext Credential Caching Disabled | WDigest not caching plaintext credentials in LSASS memory |

### System Security

| Check | What it looks for |
|---|---|
| User Account Control (UAC) | UAC enabled, requiring elevation for privileged operations |
| Secure Boot | Secure Boot active; noted if system is non-UEFI |
| AutoRun Disabled | AutoRun disabled for all drive types (removable media protection) |

## Output

Each check returns an object with at minimum:

- `Check` — human-readable control name
- `Enabled` — `$true` (compliant) / `$false` (non-compliant) / `$null` (indeterminate)
- `RawValue` — the raw registry or API value for verification
- `Supported` — present on version-gated checks; `$false` means the check was skipped on this OS build
- `Note` — present when additional context is relevant (e.g. RDP disabled, non-UEFI system)

ASR rule checks also include `ActionLabel` (human-readable action) and `RuleGUID`.

## References

- [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight)
- [ASD Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model)
- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
