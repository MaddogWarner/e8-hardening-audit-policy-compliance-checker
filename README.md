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
- `Audit Policy` - assesses local Windows Advanced Audit Policy and event log size settings against ASD Windows Event Logging and Forwarding guidance.
- `Save Report` - exports the current results to a UTF-8 markdown report.

`essential8compliancecheck.ps1`, `mdeexclusionsassess.ps1`, and `auditpolicyassess.ps1` are dot-sourced function libraries used by the GUI. They are not standalone report runners in the current architecture.

The current assessment workflow is audit-only - it makes no changes to system settings. Remediation guidance and remediation execution are planned future workflows and are not implemented yet.

## Repository Structure

| File | Purpose |
|---|---|
| `starthere.ps1` | Windows Forms GUI, self-elevation entry point, scan orchestration, system information collection, and markdown report generation |
| `essential8compliancecheck.ps1` | Essential Eight hardening control function library |
| `mdeexclusionsassess.ps1` | Microsoft Defender Antivirus exclusion inventory and risk assessment function library |
| `auditpolicyassess.ps1` | ASD Windows Audit Policy and event log configuration assessment function library |
| `README.md` | Usage, requirements, check coverage, and references |
| `CHANGELOG.md` | Notable project changes |
| `ISSUES.md` | Known issues and open investigations |

## What It Checks

### Process & Memory Protection

| Check | What it looks for |
|---|---|
| LSASS Protected Process Light (PPL) | LSASS running as a protected process, blocking memory dumping tools |
| Memory Integrity / HVCI | Hypervisor-Protected Code Integrity active at runtime (Win 10 1709+ / Server 2019+) |
| Credential Guard | VBS-based Credential Guard running, protecting domain credential hashes |

### Encryption

| Check | What it looks for |
|---|---|
| BitLocker OS Drive Encryption | BitLocker enabled, fully encrypted, and actively protecting the OS drive. Suspended or partially encrypted states show as `REVIEW`; fully decrypted drives show as `FAIL`; unavailable BitLocker support shows as `NOT SUPPORTED` |
| BitLocker OS Drive TPM Protector | TPM-backed key protector present for the OS drive. Skipped as `NOT SUPPORTED` if BitLocker is not configured on the drive |

### Audit Logging

| Check | What it looks for |
|---|---|
| Process Creation Command Line Logging | Full command-line arguments captured in Event ID 4688 |

### ASD Audit Policy

The `Audit Policy` button reads Advanced Audit Policy once per run using `auditpol.exe /get /category:* /r`, checks event log maximum sizes with `Get-WinEvent -ListLog`, and checks outgoing NTLM audit posture from the registry. It appends results to the GUI and adds dedicated audit policy sections to saved markdown reports.

| Category | Check | Required setting |
|---|---|---|
| Event Log Configuration | Security Event Log Size | At least 2,097,152 KB |
| Event Log Configuration | Application Event Log Size | At least 65,536 KB |
| Event Log Configuration | System Event Log Size | At least 65,536 KB |
| Logon & Logoff Auditing | Audit Account Lockout | Failure |
| Logon & Logoff Auditing | Audit Logon | Success and Failure |
| Logon & Logoff Auditing | Audit Logoff | Success |
| Logon & Logoff Auditing | Audit Special Logon | Success and Failure |
| Logon & Logoff Auditing | Audit Group Membership | Success |
| Logon & Logoff Auditing | Audit Other Logon/Logoff Events | Success and Failure |
| Account Management Auditing | Audit User Account Management | Success and Failure |
| Account Management Auditing | Audit Security Group Management | Success and Failure |
| Account Management Auditing | Audit Computer Account Management | Success and Failure |
| Account Management Auditing | Audit Other Account Management Events | Success and Failure |
| Policy Change Auditing | Audit Policy Change | Success and Failure |
| Policy Change Auditing | Audit Other Policy Change Events | Success and Failure |
| System Auditing | Audit System Integrity | Success and Failure |
| Process Tracking Auditing | Audit Process Creation | Success |
| Process Tracking Auditing | Audit Process Termination | Success |
| Object Access Auditing | Audit File Share | Success and Failure |
| Object Access Auditing | Audit Other Object Access Events | Success and Failure |
| Object Access Auditing | Audit Kernel Object | Success and Failure |
| Object Access Auditing | Audit Detailed File Share | No Auditing |
| Object Access Auditing | Audit File System | Success and Failure (advisory) |
| Object Access Auditing | Audit Registry | Success and Failure (advisory) |
| Network Auditing | NTLM Outgoing Traffic Auditing | Audit all or Deny all |

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

Audit policy checks also include `RequiredSetting` for report display. Optional or advisory audit policy gaps are shown as `REVIEW` rather than `FAIL`.

## References

- [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight)
- [ASD Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model)
- [ASD Windows Event Logging and Forwarding](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding)
- [ACSC Hardening Microsoft Windows 10 version 21H1 Workstations](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/hardening-microsoft-windows-10-version-21h1-workstations)
- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft BitLocker Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [Microsoft Defender Antivirus Exclusions](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-antivirus-exclusions)
