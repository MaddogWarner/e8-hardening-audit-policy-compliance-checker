# AGENTS.md

Before starting work, review `CLAUDE.md` if it exists so Codex can inherit Claude's project context, conventions, constraints, and current collaboration notes.

## Project Overview

This repository contains a read-only PowerShell and Windows Forms assessment tool for Windows OS and application hardening checks aligned to the ASD Essential Eight maturity model. The current entry point is `starthere.ps1`.

The project is security-focused and should be treated as relevant to Australian healthcare environments where auditability, access control, privacy, and operational safety matter.

## Repository Structure

- `starthere.ps1` - Windows Forms assessment GUI, self-elevation entry point, scan orchestrator, system information collector, and markdown report generator.
- `essential8compliancecheck.ps1` - administrator-only dot-sourced function library covering 30+ E8 hardening controls.
- `mdeexclusionsassess.ps1` - dot-sourced Microsoft Defender Antivirus exclusion assessment library that alerts on risky exclusions.
- `auditpolicyassess.ps1` - administrator-only dot-sourced ASD Windows Audit Policy and event log configuration assessment library.
- `README.md` - usage, requirements, current check coverage, and references.
- `AGENTS.md` - this file; Codex-specific project context and coding standards.
- `CLAUDE.md` - peer project instructions and script conventions; review before making changes.
- `CHANGELOG.md` - notable project changes.
- `ISSUES.md` - known issues and open investigations requiring follow-up.
- `.claude/` - Claude-specific local settings and collaboration context.

## Technology Stack

- PowerShell 5.1 or later.
- Target platforms: Windows 10, Windows 11, Windows Server 2016, Windows Server 2019, and Windows Server 2022.
- Windows APIs and modules used by the script include registry providers, CIM/WMI, Defender cmdlets, Windows Optional Features, SMB server/client configuration, firewall profiles, Secure Boot checks, `auditpol.exe`, and event log configuration APIs.

## Common Commands

- Run the assessment GUI: `.\starthere.ps1` (verified from `README.md`; prompts for elevation on a supported Windows host).
- Run automated tests: To be confirmed; no test framework or test script is currently present.
- Lint PowerShell: `Invoke-ScriptAnalyzer -Path .\starthere.ps1`, `Invoke-ScriptAnalyzer -Path .\essential8compliancecheck.ps1`, `Invoke-ScriptAnalyzer -Path .\mdeexclusionsassess.ps1`, and `Invoke-ScriptAnalyzer -Path .\auditpolicyassess.ps1` where PSScriptAnalyzer is installed.

Only document new commands after they can be verified from repository files.

## Coding Standards

- Use Australian English spelling and terminology in documentation and user-facing strings unless quoting APIs, registry values, command names, or vendor terminology.
- Maintain a professional, technical tone suitable for cyber security and enterprise IT contexts.
- Keep scripts audit-only unless the user explicitly changes project scope.
- Preserve `#Requires -RunAsAdministrator` for scripts that require elevated Windows security state inspection.
- Use one function per control check.
- Name control functions as `Get-<ControlName>Status`.
- Each control function should return a `[PSCustomObject]` with at minimum:
  - `Check` - human-readable control name.
  - `Category` - grouping label for the GUI and report.
  - `ML` - ASD maturity level where applicable.
  - `Enabled` - `$true`, `$false`, or `$null` when indeterminate.
  - `RawValue` - the raw registry, API, or command value used for verification.
  - `Detail` - concise human-readable evidence summary.
  - `Description` - one-sentence explanation of the control.
  - `Recommendation` - brief recommended target state.
  - `Supported` - include when an OS or feature gate applies.
- Use `-ErrorAction SilentlyContinue` for expected missing registry values where absence means not configured or non-compliant.
- Do not silently discard unexpected errors; use `Write-Warning` for recoverable issues and `throw` for fatal conditions such as inability to determine OS version.
- Add a concise comment block per function explaining what the check validates and why. Avoid line-by-line narration.
- When workstation and server behaviour differs, branch on `Win32_OperatingSystem.ProductType` and document the difference in the function comment.

## Security and Compliance Expectations

- Default to secure-by-design recommendations suitable for Australian healthcare and enterprise environments.
- Prefer least privilege access, defence-in-depth, segmentation, encryption in transit and at rest, and auditable logging.
- Consider Australian Privacy Principles, ISO 27001, ASD Essential Eight guidance, healthcare auditability, data protection, and access control when changing behaviour or documentation.
- Prefer official and high-confidence sources for security logic, especially ACSC, Australian Government, Microsoft, NIST, ISO, AWS, and Azure documentation.
- Avoid relying on low-quality blogs for control definitions or compliance claims.

## Secrets and Configuration Handling

- Never hardcode or expose API keys, passwords, access tokens, certificates, private keys, connection strings, tenant identifiers, or environment-specific secrets.
- Use obvious placeholder values in examples.
- Prefer environment variables, managed identities, secret managers, and vault-backed configuration for any future integrations.
- Preserve existing configuration and local settings unless the user explicitly requests a change.

## Testing and Validation Requirements

- Validate PowerShell syntax before finalising script changes where tooling is available.
- For behaviour changes, describe manual validation steps for a supported Windows host because automated tests are not currently defined.
- Where checks depend on OS version, Windows SKU, registry state, Defender configuration, or hardware capabilities, include validation for supported, unsupported, enabled, disabled, and indeterminate states where practical.
- Avoid introducing host-modifying tests into the main script. Any future tests should remain read-only or use mocks/fixtures.

## Deployment and Operational Safety

- The current script is audit-only and must not change registry values, Defender configuration, firewall settings, SMB settings, RDP settings, credentials, permissions, logging, or other host security controls.
- Prefer reversible changes and include rollback guidance for operationally significant work.
- Do not broaden scope from audit to remediation without explicit user approval.
- Be careful with code that may behave differently on workstations versus servers, or across Windows build versions.

## Git and Change Management Rules

- Inspect the current repository state before editing, especially files Claude or the user may have touched.
- Do not revert user or Claude changes unless explicitly instructed.
- Keep changes focused on the requested task.
- Update `CHANGELOG.md` when changing script behaviour, supported checks, output shape, or operational assumptions.
- Do not commit, push, create branches, or open pull requests unless the user asks.

## Collaboration Rules for Codex and Claude

- Treat Claude's notes, diffs, plans, and `CLAUDE.md` as peer input.
- Review current file contents before editing files Claude or the user may have touched.
- Avoid duplicated work and conflicting edits.
- If disagreeing with Claude's approach, explain the technical reason clearly and propose the safer implementation path.
- Preserve useful context from `CLAUDE.md` without copying stale or irrelevant detail into this file.

## Documentation Expectations

- Keep `README.md` aligned with the actual checks, requirements, usage, output fields, and references.
- Keep `CHANGELOG.md` current for notable additions, fixes, and behaviour changes.
- Clearly distinguish verified behaviour from assumptions or future work.
- Use tables for check coverage where they improve scanability.

## Actions Requiring Explicit User Confirmation

Ask for confirmation before:

- Deleting files or data.
- Overwriting configuration.
- Running destructive commands.
- Applying migrations or host-changing scripts.
- Changing production credentials, permissions, networking, logging, or security controls.
- Performing actions that may cause downtime, data loss, reduced visibility, or weakened security posture.
