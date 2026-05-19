# Changelog

All notable changes to this project will be documented here.

## [0.4.0] - 2026-05-19

### Added

- `auditpolicyassess.ps1`, a read-only ASD Windows Audit Policy compliance checker with 25 checks covering event log sizes, logon/logoff auditing, account management, policy change, system integrity, process tracking, object access, and outgoing NTLM auditing.
- Cached `auditpol.exe /get /category:* /r` collection so audit policy subcategory checks reuse a single `auditpol.exe` call per Audit Policy button run.
- `Audit Policy` button in `starthere.ps1` that appends audit policy findings to the existing GUI results list.
- Dedicated markdown report sections for `ASD Audit Policy Assessment` and `Non-Compliant Audit Policy Controls`.

### Changed

- Bumped the GUI tool version to `0.4.0`.
- Updated the GUI subtitle to reflect the three scan modes: Essential Eight hardening, MDE exclusions, and audit policy.
- Extended documentation and project instructions to include `auditpolicyassess.ps1`, the new Audit Policy workflow, and the ASD Windows Event Logging and Forwarding reference.

### Fixed

- Audit Policy re-runs now remove previous audit policy rows from the GUI and rebuild the shared results collection before adding fresh results.

### Validation

- PowerShell parser validation passed for `starthere.ps1`, `essential8compliancecheck.ps1`, `mdeexclusionsassess.ps1`, and `auditpolicyassess.ps1`.
- PSScriptAnalyzer returned no findings for `starthere.ps1`, `essential8compliancecheck.ps1`, `mdeexclusionsassess.ps1`, and `auditpolicyassess.ps1`.
- Windows GUI execution and end-to-end `auditpol.exe` validation remain pending because the implementation workspace is not a Windows host.

## [Unreleased]

### Added

- `Get-SMBClientSigningStatus` to assess outbound SMB client signing alongside existing server-side SMB signing.
- `Get-PSConstrainedLanguageModeStatus` and `Get-PSExecutionPolicyStatus` to cover additional PowerShell hardening scope.
- `Get-SystemInfo` in `starthere.ps1` to collect hostname, IPv4 address, logged-in user, domain/workgroup state, OS name, OS build, and last installed patch date.
- Markdown report generation in `starthere.ps1` with system information, executive summary, maturity-level grouped results, MDE exclusion findings, and non-compliant control summary.
- `Save Report` GUI workflow using `SaveFileDialog` with default filename `E8-Report-<hostname>-<yyyyMMdd>.md` and UTF-8 encoding without BOM.
- Full Windows Forms assessment GUI in `starthere.ps1`, including header panel, system information panel, results `ListView`, detail panel, progress bar, status bar, and button bar.
- GUI result row handling with `PASS`, `FAIL`, `AUDIT`, `REVIEW`, `N/A`, `NOT SUPPORTED`, and `HIGH RISK` status values.
- GUI row colour coding for pass, fail/high-risk, audit/review, not applicable, and not supported states.
- GUI detail panel behaviour that shows the selected check name, description, ASD maturity level/category, and recommendation.
- Inline Essential Eight scan flow in `starthere.ps1` that dot-sources the assessment libraries, runs each check in sequence, updates the GUI row-by-row, and keeps the UI responsive with `Application.DoEvents()`.
- Inline `MDE Exclusions` GUI workflow that runs Defender exclusion assessment results into the same `ListView` and can be re-run independently.
- `mdeexclusionsassess.ps1` read-only Microsoft Defender Antivirus exclusion assessment that reads local and policy registry exclusion locations and alerts on exclusions for `C:\Users`, `C:\Temp`, or entire drive roots.
- `ISSUES.md` issue log for tracking known problems and open investigations across context.

### Changed

- Report timestamps now convert to Australian Eastern time explicitly before labelling `AEST` or `AEDT`.
- GUI title, header, subtitle, and report heading now use the planned em dash and middle-dot separators.
- The MDE Exclusions GUI workflow now filters internal sentinel rows from the ListView and reports when no exclusions are found.
- The detail panel now labels guidance as `Recommendation:` instead of prepending `Should be:` to full-sentence recommendations.
- Essential Eight scan progress now uses a safer progress maximum and completes the bar at scan completion.
- `essential8compliancecheck.ps1` is now a dot-sourced function library with enriched output fields: `Category`, `ML`, `Detail`, `Description`, and `Recommendation`.
- `essential8compliancecheck.ps1` no longer performs script-level execution or emits `Format-List` output when loaded; it now exposes check functions for the GUI.
- All Essential Eight check functions now include category, maturity level, human-readable detail, one-sentence description, and brief recommendation metadata for GUI display and reporting.
- ASR rule results now include the enriched schema while preserving `ActionLabel`, `RuleGUID`, and raw action value evidence.
- `mdeexclusionsassess.ps1` is now a dot-sourced function library; elevation, orchestration, GUI display, and reporting are handled by `starthere.ps1`.
- `mdeexclusionsassess.ps1` no longer performs self-elevation or script-level output when loaded.
- MDE exclusion results now include `Category = 'MDE Exclusions'`, `ML = $null`, `Detail`, `Description`, and `Recommendation`.
- `starthere.ps1` now acts as the main tool entry point instead of a basic launcher that starts separate PowerShell windows.
- `starthere.ps1` now includes `Run Scan`, `MDE Exclusions`, and `Save Report` workflows in one GUI.
- `README.md` now documents the GUI-first architecture, dot-sourced library scripts, GUI output schema, new PowerShell hardening checks, and markdown report workflow.
- `AGENTS.md` now documents the new entry point, library roles, enriched result schema, and PSScriptAnalyzer commands.
- `ISSUES.md` now records ISSUE-001 as fixed pending validation on a Windows host with GPO-configured Defender exclusions.
- Renamed `Lsassandmemoryintegrity.ps1` to `essential8compliancecheck.ps1`.
- Added `Set-StrictMode -Version Latest` to `essential8compliancecheck.ps1` for consistency with the other scripts.
- Fixed `Sort-Object` in `mdeexclusionsassess.ps1` - only `Alert` is now sorted descending; `Source`, `ExclusionType`, and `ExclusionValue` sort ascending.
- Updated `AGENTS.md` repository structure to include all current scripts and files.
- Treat `RunAsPPL` values `1` and `2` as LSASS PPL enabled to avoid false negatives on newer Windows builds.
- `Get-MemoryIntegrityStatus` now prefers `Win32_DeviceGuard.SecurityServicesRunning` for HVCI runtime state and falls back to registry configuration only when runtime state is unavailable.
- Corrected Credential Guard registry fallback to read `LsaCfgFlags` from `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`.
- `Get-RDPNLAStatus` now checks the standard `UserAuthentication` value and falls back to `UserAuthenticationEnabled` if present.

### Fixed

- Secure Boot now returns `Enabled = $null` for unsupported or non-UEFI systems so the GUI reports `N/A` instead of `FAIL`.
- Memory Integrity and Credential Guard version-gate OS queries now handle CIM/WMI failures and return skipped results instead of aborting the whole scan.
- ASR rule assessment now emits placeholder rows when `Get-MpPreference` fails, so ASR checks remain visible in the GUI and report.
- SMB signing coverage now includes both server-side and client-side signing.
- Fixed ISSUE-001 by changing policy Defender exclusion registry paths from `Exclusions_Paths` and `Exclusions_Processes` subkeys to `Paths` and `Processes`.
- Removed standalone execution side effects from both assessment library scripts so they can be safely dot-sourced by the GUI.
- Resolved PSScriptAnalyzer approved-verb warnings introduced during the refactor by renaming helper functions.

### Validation

- PowerShell parser validation passed for `starthere.ps1`, `essential8compliancecheck.ps1`, and `mdeexclusionsassess.ps1`.
- PSScriptAnalyzer returned no findings for `starthere.ps1`, `essential8compliancecheck.ps1`, and `mdeexclusionsassess.ps1`.
- Windows GUI execution, Defender registry assessment, and server/workstation end-to-end validation remain pending because the implementation workspace is not a Windows host.

## [0.2.0] — 2026-05-18

### Added

- `Get-CredentialGuardStatus` — queries Win32_DeviceGuard WMI; falls back to registry
- `Get-PSModuleLoggingStatus` — PowerShell Module Logging (Event ID 4103)
- `Get-PSTranscriptionStatus` — PowerShell session transcription
- `Get-PowerShellV2Status` — checks legacy PS v2 engine is disabled via DISM
- `Get-DefenderRealTimeStatus` — Defender real-time protection state
- `Get-DefenderCloudProtectionStatus` — Defender MAPS/cloud-delivered protection
- `Get-DefenderTamperProtectionStatus` — Defender tamper protection registry check
- `Get-ASRRuleStatus` — 14 E8-relevant ASR rules checked via Get-MpPreference; GUIDs sourced from Microsoft Learn
- `Get-SMBv1Status` — SMBv1 protocol disabled check via Get-SmbServerConfiguration
- `Get-SMBSigningStatus` — SMB signing required check
- `Get-FirewallProfileStatus` — Windows Firewall enabled state for all three profiles
- `Get-RDPNLAStatus` — RDP NLA required; skips check if RDP is disabled
- `Get-WDigestStatus` — WDigest plaintext credential caching disabled
- `Get-UACStatus` — UAC enabled registry check
- `Get-SecureBootStatus` — Secure Boot via Confirm-SecureBootUEFI; graceful fallback on non-UEFI
- `Get-AutoRunStatus` — AutoRun disabled for all drive types (NoDriveTypeAutoRun = 0xFF)
- Added `[CmdletBinding()]` to script for proper common parameter support

## [0.1.0] — 2026-05-18

### Added

- `essential8compliancecheck.ps1` (originally `Lsassandmemoryintegrity.ps1`) — initial audit script covering four hardening controls:
  - LSASS Protected Process Light (PPL) — checks `RunAsPPL` registry value
  - Memory Integrity / HVCI — version-gated check (Win 10 1709+ / Server 2019+), reads `HypervisorEnforcedCodeIntegrity` registry value
  - Process Creation Command Line Logging — checks `ProcessCreationIncludeCmdLine_Enabled` registry value
  - PowerShell Script Block Logging — checks `EnableScriptBlockLogging` registry value
- `CLAUDE.md` — project instructions covering scope, target environment, script conventions, and E8 references
- `CHANGELOG.md` — this file
