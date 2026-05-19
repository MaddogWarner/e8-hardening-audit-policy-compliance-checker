# Plan: ASD Essential Eight Hardening Compliance Tool — Full Build-Out

**Project:** `/Users/maddog/Documents/Claudius/Code Projects/Security/`  
**Author:** David (via Claude Code)  
**Date:** 19/05/2026  
**For:** Codex implementation

---

## Context

The project currently has three functional PowerShell scripts:
- `essential8compliancecheck.ps1` — 22 audit functions covering core E8 hardening controls, outputs to `Format-List`
- `mdeexclusionsassess.ps1` — Defender exclusion inventory and risk assessment, outputs to `Format-List`
- `starthere.ps1` — Basic WinForms launcher that spawns the other two in separate PowerShell windows

The goal is to unify these into a single cohesive tool with a professional WinForms GUI, real-time scan progress, ML-tagged results, system info collection, and markdown report export — while keeping the code audit-only, safe, and structured for future remediation guidance.

This is the **foundation** for a future tool that will also offer:
- Per-control remediation guidance (on-host steps, GPO instructions, Intune policy links)
- Potentially guided remediation (admin-confirmed, auditable)

Every design decision here should make that future work easier to add without rewrites.

---

## Architecture Decision

**Keep three separate files; refactor their roles.**

| File | Old Role | New Role |
|------|----------|----------|
| `starthere.ps1` | Launcher only | **Full GUI orchestrator** — owns the form, runs checks inline, collects system info, renders results, generates reports |
| `essential8compliancecheck.ps1` | Standalone script | **Pure function library** — check functions only, no script-level execution logic, dot-sourced by `starthere.ps1` |
| `mdeexclusionsassess.ps1` | Standalone script | **Pure function library** — exclusion check functions only, dot-sourced by `starthere.ps1` |

**Why not all-in-one?** Keeping functions in separate files means Codex and future contributors can add new checks, fix existing ones, or eventually convert them to modules without touching the GUI. The file boundary is also a natural seam for future remediation metadata.

**Why not dot-source modules?** The project is early-stage. Named modules add friction (PSModulePath, manifests, versioning). Dot-sourcing achieves the same separation at zero overhead. Migrate to proper modules when check count justifies it.

---

## GUI Design — `starthere.ps1`

### Window Specification

```
Title: "ASD Essential Eight — Hardening Compliance Tool"
Size: 980 × 680 (min 880 × 580), centre screen, no maximise
```

### Layout (top to bottom)

```
┌─────────────────────────────────────────────────────────────────┐
│  HEADER PANEL (60px tall, light grey background)                 │
│  [Title: bold 15pt] ASD Essential Eight — Hardening Compliance  │
│  [Subtitle: 9pt grey] Audit-only · Read-only · No changes made  │
├─────────────────────────────────────────────────────────────────┤
│  SYSTEM INFO PANEL (95px tall, white background)                 │
│  Hostname: [value]   IP: [value]   User: [value]                 │
│  OS: [value]   Build: [value]   Domain: [value]   Patch: [value] │
│  (populated after scan; greyed placeholder text before)          │
├─────────────────────────────────────────────────────────────────┤
│  RESULTS PANEL (fills remaining space)                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ ListView (full-row-select, grid lines, virtual mode off)  │   │
│  │ Columns:                                                  │   │
│  │  Category (120px) | Check (240px) | ML (45px) |          │   │
│  │  Status (80px) | Details (fill)                          │   │
│  │                                                          │   │
│  │ Row colours: Pass=light green | Fail=light red |         │   │
│  │              N/A=light grey | Not Supported=white        │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ DETAIL PANEL (120px, auto-shows when row selected)        │   │
│  │ [Check name bold] — [one-line explanation of the control] │   │
│  │ ASD Reference: ML2 · Hardening — OS                      │   │
│  └──────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  PROGRESS BAR (20px, hidden until scan starts)                   │
├─────────────────────────────────────────────────────────────────┤
│  STATUS BAR (24px)                                               │
│  [Status label — left]              [Admin indicator — right]    │
├─────────────────────────────────────────────────────────────────┤
│  BUTTON BAR (50px, anchored bottom)                              │
│  [Run Scan]  [MDE Exclusions]  [Save Report]  ──  [Close]       │
│              (toggle-style — can re-run independently)           │
└─────────────────────────────────────────────────────────────────┘
```

### Scan Flow

1. User clicks **Run Scan** → button disabled, progress bar shown, status = "Scanning…"
2. `Get-SystemInfo` runs first → system info panel populates
3. Each check function is called in sequence; after each call, one row is added to the ListView and `[System.Windows.Forms.Application]::DoEvents()` is called to keep the UI responsive
4. Progress bar increments per check (calculated from total check count including all ASR rules and firewall profiles)
5. Scan complete → status shows summary ("28 of 34 checks passed"), Save Report button enabled, Run Scan re-enabled
6. **MDE Exclusions** button triggers the exclusion check functions in the same pattern and appends those rows to the ListView

### ListView Row Format

| Category | Check | ML | Status | Details |
|---|---|---|---|---|
| Memory Protection | LSASS PPL | ML2 | PASS | RunAsPPL = 2 |
| Defender | ASR: Block LSASS credential theft | ML3 | AUDIT | Action = 2 (Audit, not Block) |
| MDE Exclusions | Local Path | — | HIGH RISK | C:\Temp\* — overly broad exclusion |

Status values: `PASS` · `FAIL` · `AUDIT` · `N/A` · `NOT SUPPORTED` · `HIGH RISK` · `REVIEW`

### Detail Panel Content (per check)

Each check function should carry a `Description` and `Reference` field in its output. When a row is selected, the detail panel shows:
- **Check name** (bold)
- One-sentence plain-English explanation of what the control does and why it matters
- ASD maturity level and category
- For failures: a one-line indicator of what the recommended value should be (e.g., "Should be: Enabled (RunAsPPL = 1 or 2)")

---

## Output Schema — Enhanced PSCustomObject

All check functions in both library scripts must return this shape. Add `Description`, `Category`, `ML`, `Detail`, and `Recommendation` to the existing fields. Do not remove existing fields — extend them.

```powershell
[PSCustomObject]@{
    Check          = "LSASS Protected Process Light"   # human-readable name
    Category       = "Memory Protection"               # grouping label
    ML             = "ML2"                             # ASD maturity level (ML1/ML2/ML3)
    Enabled        = $true                             # $true=pass $false=fail $null=N/A
    RawValue       = 2                                 # raw registry/API value
    Detail         = "RunAsPPL = 2 (enabled)"         # human-readable value summary
    Description    = "Protects the LSASS process..."  # one-sentence plain-English explanation
    Recommendation = "Set RunAsPPL to 1 or 2 via..." # what to do if failing (brief)
    Supported      = $true                             # omit if no version gate applies
}
```

For MDE exclusion results, the shape stays as-is but adds `Category = "MDE Exclusions"` and `ML = $null` (exclusions don't have a maturity level).

For ASR rules, each rule is its own row with `Category = "Attack Surface Reduction"` and individual `ML` assignment (see ML mapping below).

---

## ML Mapping — All Checks

Based on ASD Essential Eight Maturity Model (hardening controls):

| Check | Category | ML |
|---|---|---|
| UAC Enabled | System Security | ML1 |
| Real-Time Protection | Defender | ML1 |
| Cloud-Delivered Protection | Defender | ML1 |
| Firewall — Domain Profile | Firewall | ML1 |
| Firewall — Private Profile | Firewall | ML1 |
| Firewall — Public Profile | Firewall | ML1 |
| SMBv1 Disabled | Network | ML1 |
| AutoRun Disabled | System Security | ML1 |
| WDigest Disabled | Credential Protection | ML2 |
| LSASS PPL | Memory Protection | ML2 |
| Credential Guard | Memory Protection | ML2 |
| SMB Signing Required | Network | ML2 |
| RDP NLA | Remote Access | ML2 |
| PS Script Block Logging | PowerShell Hardening | ML2 |
| PS Module Logging | PowerShell Hardening | ML2 |
| PS Transcription | PowerShell Hardening | ML2 |
| Process Cmd-Line Logging | Audit Logging | ML2 |
| Secure Boot | System Security | ML2 |
| Tamper Protection | Defender | ML2 |
| PS v2 Disabled | PowerShell Hardening | ML2 |
| PS Constrained Language Mode | PowerShell Hardening | ML2 |
| PS Execution Policy | PowerShell Hardening | ML2 |
| Memory Integrity (HVCI) | Memory Protection | ML3 |
| ASR — Block LSASS credential theft | Attack Surface Reduction | ML3 |
| ASR — Block abuse of vulnerable drivers | Attack Surface Reduction | ML3 |
| ASR — Block WMI persistence | Attack Surface Reduction | ML3 |
| ASR — Block Office child processes | Attack Surface Reduction | ML3 |
| ASR — Block Office comms child processes | Attack Surface Reduction | ML3 |
| ASR — Block Office executable content | Attack Surface Reduction | ML3 |
| ASR — Block Office injection | Attack Surface Reduction | ML3 |
| ASR — Block Office Win32 API calls | Attack Surface Reduction | ML3 |
| ASR — Block obfuscated scripts | Attack Surface Reduction | ML3 |
| ASR — Block JS/VBScript launching downloads | Attack Surface Reduction | ML3 |
| ASR — Block email/webmail executable content | Attack Surface Reduction | ML3 |
| ASR — Block untrusted executables (prevalence) | Attack Surface Reduction | ML3 |
| ASR — Block USB untrusted processes | Attack Surface Reduction | ML3 |
| ASR — Ransomware protection | Attack Surface Reduction | ML3 |

---

## New Checks to Add

Two checks listed in `CLAUDE.md` scope are not yet implemented. Add these to `essential8compliancecheck.ps1`:

### `Get-PSConstrainedLanguageModeStatus`
- Check `$ExecutionContext.SessionState.LanguageMode` — compliant = `ConstrainedLanguage`
- Also check registry: `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\__PSLockdownPolicy` (value 4 = CLM)
- Note: CLM may be enforced by AppLocker/WDAC; the registry key is one mechanism
- Output: `Enabled = $true` if CLM is active at time of check; `RawValue = $ExecutionContext.SessionState.LanguageMode`
- Category: PowerShell Hardening · ML2

### `Get-PSExecutionPolicyStatus`
- Use `Get-ExecutionPolicy -List` to retrieve all scopes
- Compliant = MachinePolicy or LocalMachine set to `AllSigned` or `RemoteSigned` (not `Unrestricted` or `Bypass`)
- Flag `Unrestricted` or `Bypass` at any scope as non-compliant
- Output: `Enabled = $true` if effective policy is restrictive; `RawValue = effective policy string`
- Category: PowerShell Hardening · ML2

---

## System Info Collection — New Function

Add `Get-SystemInfo` to `starthere.ps1` (not the library scripts — it belongs to the GUI layer):

```powershell
function Get-SystemInfo {
    $os  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs  = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction Stop
    $ip  = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and
                           $_.PrefixOrigin -ne 'WellKnown' } |
            Select-Object -First 1).IPAddress
    $patch = (Get-HotFix |
              Sort-Object InstalledOn -Descending |
              Select-Object -First 1 -ExpandProperty InstalledOn)

    [PSCustomObject]@{
        Hostname     = $env:COMPUTERNAME
        IPAddress    = if ($ip) { $ip } else { 'Unknown' }
        LoggedInUser = "$env:USERDOMAIN\$env:USERNAME"
        DomainJoined = $cs.PartOfDomain
        Domain       = if ($cs.PartOfDomain) { $cs.Domain } else { 'Workgroup' }
        OSName       = $os.Caption
        OSBuild      = $os.BuildNumber
        LastPatch    = if ($patch) { $patch.ToString('dd/MM/yyyy') } else { 'Unknown' }
    }
}
```

---

## ISSUE-001 Fix — mdeexclusionsassess.ps1

The GPO/Policy exclusion registry paths in `Get-DefenderExclusionRegistryTarget` are likely wrong.

**Current (suspected incorrect):**
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Paths
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Processes
```

**Correct paths (per Microsoft docs):**
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes
```

Fix: change `Exclusions_Paths` → `Paths` and `Exclusions_Processes` → `Processes` in `Get-DefenderExclusionRegistryTarget`. Update ISSUES.md and CHANGELOG.md accordingly.

---

## Markdown Report Format

The report is generated in memory as a string and optionally saved. Use a `SaveFileDialog` with default filename `E8-Report-<hostname>-<yyyyMMdd>.md`.

```markdown
# ASD Essential Eight — Hardening Compliance Report

**Generated:** DD/MM/YYYY HH:MM AEST  
**Tool Version:** 0.3.0

---

## System Information

| Field | Value |
|---|---|
| Hostname | WORKSTATION01 |
| IP Address | 192.168.1.100 |
| Logged-in User | DOMAIN\jsmith |
| Domain Joined | Yes — corp.example.com |
| Operating System | Windows 11 Pro |
| OS Build | 22631 |
| Last Patch Installed | 15/05/2026 |

---

## Executive Summary

| | Count |
|---|---|
| Total Checks | 36 |
| Pass | 28 |
| Fail | 6 |
| Not Applicable | 1 |
| Not Supported | 1 |

---

## Results by Maturity Level

### ML1 — Foundational Controls
| Category | Check | Status | Detail |
|---|---|---|---|
| System Security | UAC Enabled | PASS | EnableLUA = 1 |
...

### ML2 — Intermediate Controls
...

### ML3 — Advanced Controls
...

---

## MDE Exclusion Assessment

| Source | Type | Value | Risk | Reason |
|---|---|---|---|---|
| Local | Path | C:\Temp\* | HIGH | Overly broad — entire temp directory excluded |
| Policy | Process | notepad.exe | REVIEW | Unusual process exclusion |

---

## Non-Compliant Controls

| Check | ML | Detail | Recommendation |
|---|---|---|---|
| HVCI (Memory Integrity) | ML3 | Not enabled | Enable via Windows Security > Device Security > Core Isolation |
...

---

*This report was generated by the ASD Essential Eight Hardening Compliance Tool.*  
*All findings are read-only observations. No changes were made to this system.*
```

---

## Refactoring Rules for Library Scripts

When converting `essential8compliancecheck.ps1` and `mdeexclusionsassess.ps1` from standalone scripts to dot-sourceable libraries:

1. **Remove all script-level execution logic** — no `$results = ...`, no `Format-List`, no `Write-Host` at script scope
2. **Keep every function body intact** — only the output shape changes (add new fields)
3. **Remove self-elevation logic from `mdeexclusionsassess.ps1`** — elevation is handled by `starthere.ps1`
4. **Keep `#Requires -RunAsAdministrator`** in `essential8compliancecheck.ps1` — acts as a guard even when dot-sourced
5. **Add `Description` and `Recommendation` fields** to every check function's returned object
6. **All functions remain named `Get-<ControlName>Status`** — do not rename

---

## Implementation Order

Work through these in sequence. Each step is independently testable.

1. **Fix ISSUE-001** in `mdeexclusionsassess.ps1` → verify registry paths are correct
2. **Add `Description`, `Category`, `ML`, `Detail`, `Recommendation` fields** to all existing functions in `essential8compliancecheck.ps1`
3. **Add two new check functions** (`Get-PSConstrainedLanguageModeStatus`, `Get-PSExecutionPolicyStatus`) to `essential8compliancecheck.ps1`
4. **Strip standalone execution logic** from both library scripts (keep functions only)
5. **Rewrite `starthere.ps1`** — new GUI with system info panel, ListView, detail panel, progress bar, button bar
6. **Implement scan flow** in `starthere.ps1` — dot-source libraries, iterate checks, populate ListView row-by-row with DoEvents
7. **Implement `Get-SystemInfo`** and populate the system info panel
8. **Implement report generator** — build markdown string from collected results + system info
9. **Implement Save Report** — SaveFileDialog, write file with UTF-8 encoding (no BOM)
10. **Test end-to-end** on at least one workstation and one server

---

## Conventions Reminders for Codex

- Australian English in all strings and comments (organisation, colour, recognise)
- `Set-StrictMode -Version Latest` at top of each script
- `-ErrorAction SilentlyContinue` on registry reads; missing key = not configured = non-compliant
- `Write-Warning` for recoverable issues; `throw` for fatal errors
- No hardcoded paths, credentials, or environment-specific values
- No remediation actions — audit only
- All GUI strings should be plain, clear admin language — avoid jargon or acronym-only labels
- Follow existing `Get-<ControlName>Status` naming for all new check functions
- Update `CHANGELOG.md` with all changes under `[Unreleased]`
- Update `AGENTS.md` if any new conventions are introduced

---

## Verification Checklist

- [ ] Run `starthere.ps1` as administrator — form loads without errors
- [ ] Click **Run Scan** — progress bar advances, rows appear one-by-one in real-time
- [ ] System info panel populates after scan (hostname, IP, user, domain, OS, build, last patch)
- [ ] Select a result row — detail panel shows correct description and recommendation
- [ ] Rows are colour-coded: green for PASS, red for FAIL, grey for N/A/Not Supported
- [ ] Click **MDE Exclusions** — exclusion rows appear in same ListView
- [ ] High-risk MDE exclusions appear as HIGH RISK with red background
- [ ] Click **Save Report** — SaveFileDialog opens with correct default filename
- [ ] Saved `.md` file is valid markdown, readable in a text editor, and ingestible by an LLM
- [ ] Report includes: system info table, summary counts, ML-grouped results, MDE exclusion table, non-compliant summary
- [ ] Run on Windows 10 workstation — no unhandled exceptions
- [ ] Run on Windows Server 2019 — version-gated checks marked NOT SUPPORTED where expected
- [ ] Run without admin — self-elevation prompt appears
