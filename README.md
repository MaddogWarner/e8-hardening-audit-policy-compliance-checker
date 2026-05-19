# ASD Essential Eight Hardening Compliance Tool

A read-only PowerShell and Windows Forms tool that assesses Windows OS and application hardening controls against the [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) maturity model. The GUI runs checks inline, surfaces Microsoft Defender Antivirus exclusion risks, and can export a markdown report.

## Requirements

- Windows 10 / 11 or Windows Server 2016 / 2019 / 2022
- PowerShell 5.1 or later
- Administrator privileges. `starthere.ps1` prompts for elevation if needed.

## Usage

Start the graphical assessment tool:

```powershell
.\starthere.ps1
```

If the tool is not already running as administrator, it prompts for elevation before opening the Windows Forms interface.

The GUI provides:

- `Run Scan` - runs the Essential Eight hardening checks and populates results in the GUI.
- `MDE Exclusions` - inventories Microsoft Defender Antivirus exclusions and highlights obviously risky exclusions.
- `Save Report` - exports the current results to a UTF-8 markdown report.

`essential8compliancecheck.ps1` and `mdeexclusionsassess.ps1` are dot-sourced function libraries used by the GUI. They are not standalone report runners in the current architecture.

The current assessment workflow is audit-only - it makes no changes to system settings. Remediation guidance and remediation execution are planned future workflows and are not implemented yet.

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
| PowerShell Constrained Language Mode | Current session language mode and lockdown policy signal |
| PowerShell Execution Policy | Machine policy or local machine scope set to `AllSigned` or `RemoteSigned`, with no unsafe scope override |

### Windows Defender

| Check | What it looks for |
|---|---|
| Real-Time Protection | Defender real-time monitoring active |
| Cloud-Delivered Protection | MAPS/cloud protection enabled (basic or advanced) |
| Tamper Protection | Defender settings protected from unauthorised modification |
| Microsoft Defender Antivirus Exclusions | Alerts on file, folder, and process exclusions for `C:\Users`, `C:\Temp`, or entire drive roots such as `C:\` or `D:` |

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
| SMB Server Signing Required | SMB packet signing enforced for inbound SMB sessions |
| SMB Client Signing Required | SMB packet signing enforced for outbound SMB sessions |
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

## GUI Output

The GUI displays each check with:

- `Category` - grouping label such as `Defender`, `PowerShell Hardening`, or `Memory Protection`
- `Check` — human-readable control name
- `ML` - mapped Essential Eight maturity level where applicable
- `Status` - `PASS`, `FAIL`, `AUDIT`, `REVIEW`, `N/A`, `NOT SUPPORTED`, or `HIGH RISK`
- `Details` - human-readable evidence summary

Each library check returns an object with at minimum:

- `Category` - grouping label
- `ML` - ASD maturity level where applicable
- `Check` - human-readable control name
- `Enabled` — `$true` (compliant) / `$false` (non-compliant) / `$null` (indeterminate)
- `RawValue` — the raw registry or API value for verification
- `Detail` - human-readable evidence summary
- `Description` - one-sentence explanation of the control
- `Recommendation` - brief recommended target state
- `Supported` — present on version-gated checks; `$false` means the check was skipped on this OS build
- `Note` — present when additional context is relevant (e.g. RDP disabled, non-UEFI system)

ASR rule checks also include `ActionLabel` (human-readable action) and `RuleGUID`.

## References

- [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight)
- [ASD Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model)
- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Defender Antivirus Exclusions](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-antivirus-exclusions)
