# Changelog

All notable changes to this project will be documented here.

## [Unreleased]

### Changed

- Renamed `Lsassandmemoryintegrity.ps1` to `essential8compliancecheck.ps1`.
- Treat `RunAsPPL` values `1` and `2` as LSASS PPL enabled to avoid false negatives on newer Windows builds.
- `Get-MemoryIntegrityStatus` now prefers `Win32_DeviceGuard.SecurityServicesRunning` for HVCI runtime state and falls back to registry configuration only when runtime state is unavailable.
- Corrected Credential Guard registry fallback to read `LsaCfgFlags` from `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`.
- `Get-RDPNLAStatus` now checks the standard `UserAuthentication` value and falls back to `UserAuthenticationEnabled` if present.

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
