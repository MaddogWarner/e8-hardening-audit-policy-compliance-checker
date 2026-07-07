# Changelog

All notable changes to this project will be documented here.

## [1.0.1] - 2026-07-07

### Fixed

- `Get-PSExecutionPolicyStatus` in `essential8compliancecheck.ps1` had no `try`/`catch` at all, so any unexpected shape from `Get-ExecutionPolicy -List` threw an unhandled `PropertyNotFoundException` under `Set-StrictMode -Version Latest` and aborted the entire E8 scan partway through, discarding all previously collected results. The function is now wrapped in a full `try`/`catch`, filters `Get-ExecutionPolicy -List` output to entries that actually expose `Scope` and `ExecutionPolicy`, and degrades to an indeterminate result with the real error message in `Detail` instead of crashing the scan. First reported when running the released v1.0.0 build on a real Windows 11 host.
- `Get-NTLMAuditingStatus` in `auditpolicyassess.ps1` read `RestrictSendingNTLMTraffic` via `(Get-ItemProperty ... -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic`. When the registry value is absent — the common case on a workgroup host where outgoing NTLM auditing has never been configured — `Get-ItemProperty` returns `$null`, and dot-accessing a property on `$null` throws under `Set-StrictMode -Version Latest`, aborting the entire Audit Policy scan uncaught. The check now reuses the existing `Get-RegistryPropertyValue` helper from `essential8compliancecheck.ps1`, which already handles a missing value safely.
- `Get-PowerShellV2Status` in `essential8compliancecheck.ps1` treated a `$null` result from `Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root` as a query failure (indeterminate), even though some newer Windows builds no longer ship this optional feature at all. A missing optional feature now reports `Enabled $true` (compliant) with a `Detail` explaining the legacy engine is not present on this Windows build, rather than an indeterminate (`N/A`) result.

## [1.0.0] - 2026-07-07

First stable release. All accuracy, reliability, and performance findings from the full codebase review are resolved; the tool is considered release-ready.

### Fixed

- `Get-PSExecutionPolicyStatus` in `essential8compliancecheck.ps1` was failing on every self-elevated run because `starthere.ps1`'s `Start-ElevatedScript` relaunches with `-ExecutionPolicy Bypass`, which sets the Process scope to Bypass. The Process scope is session-local and does not reflect host configuration, so it is now excluded from the unsafe-scope evaluation. A `Note` is added via `AdditionalProperties` when Process scope is Unrestricted or Bypass, stating it was excluded as session-transient.
- `Get-AuditSubcategoryInclusion` in `auditpolicyassess.ps1` matched rows on the localised `Subcategory` display name column, which (a) breaks on non-English Windows where `auditpol /r` emits localised subcategory names, and (b) caused a lookup miss to silently return the literal `'No Auditing'`, making `Audit Detailed File Share` falsely `PASS`. Matching now uses the locale-stable `Subcategory GUID` column against a well-known GUID map for each subcategory. A lookup miss now returns `$null`, and `ConvertTo-AuditSettingResult` reports an indeterminate result (`Enabled $null`) with a detail explaining the subcategory could not be resolved, instead of evaluating compliance against a placeholder value. Added a comment noting that the `Inclusion Setting` text comparison still assumes an English-language OS.
- `Get-DefenderRealTimeStatus` and `Get-DefenderTamperProtectionStatus` in `essential8compliancecheck.ps1` read policy preference rather than runtime state. Real-Time Protection now uses `Get-MpComputerStatus.RealTimeProtectionEnabled`, with `AMRunningMode` included in `Detail` and passive mode flagged explicitly; a try/catch fallback returns indeterminate (`$null`) if `Get-MpComputerStatus` fails. Tamper Protection now uses `Get-MpComputerStatus.IsTamperProtected`, keeping the registry `Features\TamperProtection` value as evidence only in `Detail`, with a try/catch fallback to indeterminate if runtime state is unavailable.
- `Get-PSConstrainedLanguageModeStatus` in `essential8compliancecheck.ps1` hard-failed on elevated administrator sessions, which are almost always `FullLanguage` even where Constrained Language Mode is enforced for standard users via WDAC or AppLocker. The check keeps `Enabled $false` but now adds `ActionLabel = 'Warn'` (mapped to `REVIEW` in the GUI) and notes in `Detail` that the elevated session is not representative of standard-user enforcement.
- Query failures no longer report a hard `FAIL`. `Get-AuditLogSizeStatus` in `auditpolicyassess.ps1` and `Get-BitLockerOSDriveStatus` in `essential8compliancecheck.ps1` now return `Enabled $null` on their generic catch paths, since a query failure is not evidence of non-compliance.
- `Get-UACStatus` in `essential8compliancecheck.ps1` keeps the conservative `FAIL` when `EnableLUA` is absent, but now adds a `Note` via `AdditionalProperties` stating that Windows defaults UAC to enabled in this case, while explicit policy configuration remains recommended.
- `Start-ElevatedScript` in `starthere.ps1` now wraps `Start-Process -Verb RunAs` in try/catch. If the user declines the UAC prompt, the tool writes a friendly `Write-Warning` and exits instead of surfacing an unhandled exception.
- `Get-CachedAuditPolicies` in `auditpolicyassess.ps1` no longer merges `auditpol.exe` stderr into the CSV parser (dropped `2>&1` in favour of `2>$null`). The cached output is also filtered to `[string]` lines before `ConvertFrom-Csv` as defence in depth.
- All four `.ps1` files are now saved as UTF-8 **with BOM**. Windows PowerShell 5.1 reads BOM-less files as ANSI, which could corrupt non-ASCII characters such as the em dash used in comments and UI text.

### Added

- Extension exclusion coverage in `mdeexclusionsassess.ps1`: `Get-DefenderExclusionRegistryTarget` now includes Local and Policy registry targets for `Exclusions\Extensions`, alongside the existing Path and Process targets.
- New high-risk patterns in `Get-DefenderExclusionRisk` (`mdeexclusionsassess.ps1`): bare executable/script file extensions (`exe`, `ps1`, `dll`, `js`, `vbs`, `bat`, `cmd`, `scr`, `com`, `msi`, with or without a leading dot or asterisk); `C:\Windows\Temp` and `C:\ProgramData` path prefixes; and bare process-name exclusions for common LOLBins (`powershell.exe`, `pwsh.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `msbuild.exe`). `Get-DefenderExclusionRisk` gained an optional `-ExclusionType` parameter, passed from `Get-MdeExclusionAssessment`, used to scope the extension and LOLBin-process patterns to their respective exclusion types.
- `Get-CachedMpPreference` and `$script:MpPreferenceCache` in `essential8compliancecheck.ps1` — caches a single `Get-MpPreference` call per scan run, used by `Get-DefenderCloudProtectionStatus` and `Get-ASRRuleStatus`.
- `Get-CachedOsInfo` and `$script:OsInfoCache` in `essential8compliancecheck.ps1` — caches a single `Get-CimInstance Win32_OperatingSystem` call per scan run, used by `Get-MemoryIntegrityStatus`, `Get-CredentialGuardStatus`, and (cross-library) `Get-CurrentOsBuild` in `auditpolicyassess.ps1`.
- `starthere.ps1` resets `$script:MpPreferenceCache` and `$script:OsInfoCache` at the start of the Run E8 Scan and Audit Policy button handlers, alongside the existing `$script:AuditPolCache` reset, so a re-scan reflects current state.
- `starthere.ps1` now updates `$statusLabel.Text` with the current check name and calls `[System.Windows.Forms.Application]::DoEvents()` before invoking each check command in the E8 scan and Audit Policy handlers, so the UI shows progress during long blocking calls such as `Get-WindowsOptionalFeature`.

### Changed

- The E8 scan progress bar `Maximum` is now set from `Get-E8CheckCommand`'s command count instead of a hardcoded value of 50, and increments once per command rather than once per result row, so the bar reaches full exactly at the end of the scan.
- Bumped tool version to `0.6.0`.

## [0.5.4] - 2026-05-27

### Added

- CSV export format for the Save Report workflow. A **MD / CSV** radio button pair appears to the right of the Save Report button; MD is selected by default. Selecting CSV and clicking Save Report opens a file dialog pre-named `E8-Report-<hostname>-<yyyyMMdd>.csv` and writes a flat, 26-column UTF-8 with BOM CSV containing one row per check result across all three assessment types (E8, MDE Exclusions, Audit Policy). Every row includes system context columns (Hostname, IPAddress, LoggedInUser, Domain, OSName, OSBuild, LastPatch, ReportDate) so the file is self-contained for Power BI and Excel.
- `Get-CsvReport` in `starthere.ps1` — builds the unified flat result list from `$script:AssessmentResults` and `$script:AuditPolicyResults`. Uses an `AssessmentType` column (`E8`, `MDE`, `AuditPolicy`) as the primary slicer. MDE-specific fields (`MDE_Source`, `MDE_ExclusionType`, `MDE_ExclusionValue`, `MDE_Alert`, `MDE_Reason`, `MDE_NormalisedValue`) are populated for MDE rows and blank for all others.
- `Save-CsvReport` in `starthere.ps1` — SaveFileDialog and CSV write. Uses `UTF8Encoding($true)` to emit a BOM, enabling Excel on Windows to auto-detect encoding without the text import wizard. Uses `ConvertTo-Csv -NoTypeInformation` to suppress the `#TYPE` comment row.
- `ConvertTo-CsvSafeString` helper in `starthere.ps1` — serialises null, arrays, and multiline strings to a single CSV-safe string; array values are joined with a semicolon.

### Changed

- Status bar now shows `Report saved (Markdown)` or `Report saved (CSV)` after a save so the format used is visible at a glance.
- Bumped tool version to `0.5.4`.

## [0.5.3] - 2026-05-22

### Fixed

- `Get-ItemPropertyValue` throws a terminating exception in PowerShell 5.1 when the registry path exists but the named value is absent — `-ErrorAction SilentlyContinue` only suppresses non-terminating errors and cannot catch it. This caused the E8 scan to show "Scan Failed" immediately on hosts where controls such as LSASS PPL, Script Block Logging, or Tamper Protection are not configured. Added a private helper `Get-RegistryPropertyValue` that wraps `Get-ItemPropertyValue` in `try/catch` and returns `$null` cleanly when the value is absent. Replaced all 15 `Get-ItemPropertyValue ... -ErrorAction SilentlyContinue` call sites in `essential8compliancecheck.ps1` with this helper.
- MDE Exclusions Detail column showed `0 - No risky path pattern matched` instead of the actual exclusion path. Windows Defender stores the exclusion path or process name as the registry value **name** and `0` (DWORD) as the value data; `GetValue()` can return `"0"` as a string, causing the value data to be used as the exclusion display value. Fixed `ExclusionValue` in `Get-DefenderExclusionRegistryEntry` to always use the value name. Simplified the `Detail` field to show the exclusion value only — the existing REVIEW (yellow) / HIGH RISK (red) colour coding already communicates risk level.

### Changed

- Bumped tool version to `0.5.3`.

## [0.5.2] - 2026-05-22

### Fixed

- `Set-StrictMode -Version Latest` was causing all registry checks in `essential8compliancecheck.ps1` to fail with "The property 'X' cannot be found on this object" whenever the registry key exists but the named value is absent. The pattern `(Get-ItemProperty -Name 'X').X` returns the key object without the property in that case; StrictMode then throws `PropertyNotFoundException`. Replaced all 15 occurrences with `Get-ItemPropertyValue -ErrorAction SilentlyContinue`, which returns `$null` cleanly when the key or value is absent. Also replaced the `Get-RDPNLAStatus` multi-property read pattern (`$rdpTcp.UserAuthentication`, `$rdpTcp.UserAuthenticationEnabled`) with two separate `Get-ItemPropertyValue` calls for the same reason.

### Changed

- Bumped tool version to `0.5.2`.

## [0.5.1] - 2026-05-22

### Fixed

- Dot-source scoping bug in `starthere.ps1`: `Import-AssessmentLibrary` was dot-sourcing the three library scripts inside a function, loading all library function definitions into that function's local scope. When the function returned, those definitions were gone, causing the Run Scan, MDE Exclusions, and Audit Policy buttons to fail with "term not recognised" errors. Fixed by removing `Import-AssessmentLibrary` and dot-sourcing the libraries at script scope directly.

### Changed

- "Run Scan" button renamed to "Run E8 Scan".
- "MDE Exclusions" button renamed to "MDE Exclusions List".
- Button widths and X-positions adjusted to accommodate the new labels without clipping.
- Bumped tool version to `0.5.1`.

## [0.5.0] - 2026-05-20

### Added

- `Get-BitLockerOSDriveStatus` in `essential8compliancecheck.ps1` to check whether BitLocker Drive Encryption is enabled and actively protecting the OS drive. It distinguishes fully encrypted and active drives (`PASS`), fully decrypted drives (`FAIL`), and suspended or partially encrypted states (`REVIEW`).
- `Get-BitLockerOSDriveProtectorStatus` in `essential8compliancecheck.ps1` to check whether the OS drive BitLocker configuration uses a TPM-backed key protector for hardware binding. It skips the check (`NOT SUPPORTED`) if BitLocker is not configured on the drive.
- `Encryption` category for BitLocker-related checks in GUI results and markdown reports.

### Changed

- `Get-E8CheckCommand` in `starthere.ps1` now includes `Get-BitLockerOSDriveStatus` and `Get-BitLockerOSDriveProtectorStatus`, bringing the E8 scan to 25 checks.
- Bumped tool version to `0.5.0`.

### Validation

- PowerShell parser validation passed for `starthere.ps1` and `essential8compliancecheck.ps1`.
- PSScriptAnalyzer returned no findings for `starthere.ps1` and `essential8compliancecheck.ps1`.
- Windows GUI execution and end-to-end BitLocker validation remain pending because the implementation workspace is not a Windows host.

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
