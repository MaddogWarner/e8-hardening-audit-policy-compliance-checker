# ASD Essential Eight Hardening Compliance Tool

A read-only PowerShell and Windows Forms tool that assesses Windows OS and application hardening controls against the [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) maturity model. The GUI runs checks inline, surfaces Microsoft Defender Antivirus exclusion risks, and can export results as a markdown report or a flat CSV suitable for Power BI and Excel dashboards.

## Use Cases

- **Point-in-time compliance assessment** — run against a live host to get an immediate snapshot of its Essential Eight hardening posture. Useful for periodic reviews or before/after change windows.
- **SOE / Golden Image validation** — run against a workstation or server image before it is committed to production to confirm hardening controls are in place before wide deployment.

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
- `Save Report` - exports the current results. Use the **MD / CSV** radio buttons immediately to the right of the button to choose the output format before saving:
  - **MD** (default) — UTF-8 markdown report, structured for readability and LLM ingestion.
  - **CSV** — flat UTF-8 CSV with one row per check result, structured for Power BI and Excel dashboards. All three assessment types (E8 hardening, MDE exclusions, Audit Policy) are exported into a single file with an `AssessmentType` column as the primary slicer.

`essential8compliancecheck.ps1`, `mdeexclusionsassess.ps1`, and `auditpolicyassess.ps1` are dot-sourced function libraries used by the GUI. They are not standalone report runners in the current architecture.

The current assessment workflow is audit-only - it makes no changes to system settings. Remediation guidance and remediation execution are planned future workflows and are not implemented yet.

## Repository Structure

| File | Purpose |
|---|---|
| `starthere.ps1` | Windows Forms GUI, self-elevation entry point, scan orchestration, system information collection, and markdown and CSV report generation |
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

Subcategory lookups match on the locale-stable `Subcategory GUID` column rather than the localised `Subcategory` display name, so results are consistent on non-English Windows installations. If a subcategory cannot be resolved from `auditpol` output, the check reports an indeterminate result rather than assuming `No Auditing`.

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
| PowerShell Constrained Language Mode | Current session language mode and lockdown policy signal. An elevated session that is not Constrained Language shows as `REVIEW` rather than `FAIL`, because an administrator session is almost always `FullLanguage` even where CLM is enforced for standard users |
| PowerShell Execution Policy | Machine policy or local machine scope set to `AllSigned` or `RemoteSigned`, with no unsafe scope override |

### Windows Defender

| Check | What it looks for |
|---|---|
| Real-Time Protection | Defender real-time monitoring active at runtime (`Get-MpComputerStatus`), with passive mode flagged explicitly |
| Cloud-Delivered Protection | MAPS/cloud protection enabled (basic or advanced) |
| Tamper Protection | Defender settings protected from unauthorised modification at runtime (`Get-MpComputerStatus.IsTamperProtected`), with the registry value retained as evidence only |
| Microsoft Defender Antivirus Exclusions | Alerts on file, folder, process, and extension exclusions for `C:\Users`, `C:\Windows\Temp`, `C:\ProgramData`, `C:\Temp`, entire drive roots such as `C:\` or `D:`, bare executable/script extensions (e.g. `exe`, `ps1`, `js`), and bare process-name exclusions for common LOLBins (e.g. `powershell.exe`, `mshta.exe`) |

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

## CSV Export Schema

When saving in CSV format, the export produces one row per check result across all three assessment types. Every row includes system context so the file is self-contained when loaded into Power BI or Excel.

| Column | Type | Description |
| --- | --- | --- |
| `ReportDate` | string | Timestamp the report was generated (AEST/AEDT) |
| `Hostname` | string | Host the tool was run on |
| `IPAddress` | string | Primary IPv4 address |
| `LoggedInUser` | string | Account that ran the tool |
| `Domain` | string | Domain or workgroup membership |
| `OSName` | string | Windows edition name |
| `OSBuild` | string | OS build number |
| `LastPatch` | string | Date of the most recently installed update |
| `AssessmentType` | string | `E8`, `MDE`, or `AuditPolicy` — primary slicer |
| `Category` | string | Grouping label (e.g. `Memory Protection`, `MDE Exclusions`) |
| `Check` | string | Individual check name |
| `ML` | string | ASD maturity level (`ML1`–`ML3`); blank for MDE rows |
| `Status` | string | `PASS`, `FAIL`, `AUDIT`, `REVIEW`, `HIGH RISK`, `N/A`, `NOT SUPPORTED` |
| `Enabled` | string | `True` / `False` / blank; blank for MDE and indeterminate results |
| `RawValue` | string | Serialised raw registry or API value; array values joined with a semicolon |
| `Detail` | string | Human-readable evidence summary |
| `Description` | string | One-sentence control explanation |
| `Recommendation` | string | Brief recommended target state |
| `Supported` | string | `True` / `False` / blank; `False` means the check was skipped on this OS build |
| `RequiredSetting` | string | Target audit policy setting; populated for `AuditPolicy` rows only |
| `ActionLabel` | string | `Audit` or `Warn` for advisory checks; blank otherwise |
| `MDE_Source` | string | `Local` or `Policy`; populated for `MDE` rows only |
| `MDE_ExclusionType` | string | `Path` or `Process`; populated for `MDE` rows only |
| `MDE_ExclusionValue` | string | The exclusion path or process name; populated for `MDE` rows only |
| `MDE_Alert` | string | `True` if the exclusion matched a high-risk pattern; populated for `MDE` rows only |
| `MDE_Reason` | string | Risk classification reason; populated for `MDE` rows only |
| `MDE_NormalisedValue` | string | Normalised exclusion path used for pattern matching; populated for `MDE` rows only |

The file is written as UTF-8 with BOM so Excel on Windows opens it without a text import wizard.

## References

- [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight)
- [ASD Essential Eight Maturity Model](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model)
- [ASD Windows Event Logging and Forwarding](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding)
- [ACSC Hardening Microsoft Windows 10 version 21H1 Workstations](https://www.cyber.gov.au/resources-business-and-government/maintaining-devices-and-systems/system-hardening-and-administration/system-hardening/hardening-microsoft-windows-10-version-21h1-workstations)
- [Microsoft ASR Rules Reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft BitLocker Overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [Microsoft Defender Antivirus Exclusions](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-antivirus-exclusions)
