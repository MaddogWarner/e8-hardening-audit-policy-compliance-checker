# Issue Log

Known issues and open investigations requiring follow-up.

---

## ISSUE-001 — Policy Defender exclusion registry paths may be incorrect

**Status:** Fixed in `[Unreleased]` — pending validation on a Windows host with GPO-configured exclusions
**File:** `mdeexclusionsassess.ps1`
**Lines:** `Get-DefenderExclusionRegistryTarget`

`Get-DefenderExclusionRegistryTarget` reads Group Policy Defender exclusions from:

```text
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Paths
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Processes
```

Microsoft documentation indicates `Exclusions_Paths` and `Exclusions_Processes` are **value names** under the parent `Exclusions` key (signalling the policy is configured), not registry subkeys. The actual exclusion entries applied via Group Policy are likely stored in the `\Paths` and `\Processes` subkeys — the same naming used for local exclusions.

If this is the case, policy-configured exclusions will be silently missed. The script returns `Present = $false` for missing paths, so there is no crash — but the assessment would produce a false-negative for any GPO-sourced Defender exclusion.

**How to verify:** On a Windows host where Defender exclusions have been configured via Group Policy, run:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
```

Check whether exclusion entries appear under `...\Exclusions\Paths` or `...\Exclusions\Processes` subkeys (correct — fixed implementation checks these), under `...\Exclusions\Exclusions_Paths` or `...\Exclusions\Exclusions_Processes` (old assumption, removed), or directly under `...\Exclusions` as value names (CSP/MDM signal, keep in mind during validation).

**Fix:** `Get-DefenderExclusionRegistryTarget` now reads policy exclusions from `\Paths` and `\Processes`:

```powershell
[PSCustomObject]@{
    Source        = 'Policy'
    ExclusionType = 'Path'
    RegistryPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'
}
[PSCustomObject]@{
    Source        = 'Policy'
    ExclusionType = 'Process'
    RegistryPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes'
}
```

The old `Exclusions_Paths` and `Exclusions_Processes` subkey assumptions have been removed.

---

## ISSUE-002 — Report timestamp hardcodes AEST/AEDT regardless of system timezone

**Status:** Fixed in `[Unreleased]`
**File:** `starthere.ps1`
**Function:** `Get-ReportTimestamp`

`Get-ReportTimestamp` determines the timezone label using `[DateTime].IsDaylightSavingTime()` and unconditionally writes either `AEST` or `AEDT`:

```powershell
$zoneLabel = if ($now.IsDaylightSavingTime()) { 'AEDT' } else { 'AEST' }
```

`IsDaylightSavingTime()` reflects whether the current date falls within DST as defined by the **local system timezone** — not the Australian Eastern timezone. On any host set to UTC, US Eastern, or another timezone, the label will be wrong. For example, a server in UTC with DST active shows a UTC time labelled `AEDT`, which is both the wrong zone and potentially the wrong offset. Servers are commonly set to UTC in enterprise environments, making this a meaningful accuracy problem for audit reports.

**Suggested fix:** Use the actual UTC offset, which is unambiguous regardless of system timezone:

```powershell
function Get-ReportTimestamp {
    $now = Get-Date
    return $now.ToString('dd/MM/yyyy HH:mm zzz')
}
```

This produces `19/05/2026 14:30 +10:00`. Alternatively, use the Windows timezone display name:

```powershell
$tz = [System.TimeZoneInfo]::Local
$tzLabel = $tz.IsDaylightSavingTime($now) ? $tz.DaylightName : $tz.StandardName
return "$($now.ToString('dd/MM/yyyy HH:mm')) ($tzLabel)"
```

---

## ISSUE-003 — Progress bar Maximum hardcoded to 36; actual result count is ~37

**Status:** Fixed in `[Unreleased]`
**File:** `starthere.ps1`
**Lines:** `Show-StartHereForm` (initial `$progressBar.Maximum = 36`) and `runScanButton.Add_Click` handler (resets to 36)

The progress bar Maximum is hardcoded to 36 in two places. The 22-function scan produces approximately 37 result rows: 20 single-result functions (20 rows), `Get-ASRRuleStatus` (14 rows — one per rule), and `Get-FirewallProfileStatus` (3 rows — Domain, Private, Public), totalling ~37. The scan loop guard `if ($progressBar.Value -lt $progressBar.Maximum)` prevents an overflow exception, but the bar stops incrementing at 36 and never reaches full, leaving it visually incomplete at the end of every scan. The count also varies at runtime — version-gated checks still emit one row, and the ASR function returns 0 rows if `Get-MpPreference` fails (see ISSUE-009).

**Suggested fix:** Set a safe fixed upper bound of 50, or switch to `ProgressBarStyle.Marquee` during scanning:

```powershell
$progressBar.Maximum = 50   # safe upper bound covering current and near-future check count
```

Using `Marquee` style during the scan and switching back to `Blocks` when done avoids needing an accurate count altogether.

---

## ISSUE-004 — MDE exclusion sentinel rows appear in the GUI as N/A when no exclusions are configured

**Status:** Fixed in `[Unreleased]`
**File:** `starthere.ps1` and `mdeexclusionsassess.ps1`
**Functions:** `Get-MdeExclusionAssessment`, `Add-AssessmentResultRow`

`Get-MdeExclusionAssessment` emits one result row for every registry target location regardless of whether exclusions are present. When a registry path does not exist or has no entries, it emits a result with `ExclusionValue = $null` and `EntryStatus` of `'Registry path not present'` or `'No exclusion values configured'`. `Get-AssessmentStatus` maps these to `N/A` because `$result.ExclusionValue` is falsy. The result is that on a clean system with no exclusions configured, 4 N/A rows appear in the ListView after every MDE scan. Admins may not know whether N/A means the check ran and found nothing (good) or was not run. The markdown report correctly filters these rows out via `$_.ExclusionValue` truthiness check, so only the GUI is affected.

**Suggested fix — Option A:** Filter sentinel rows out of the ListView and display a status bar message like "No exclusions found at any configured location" to confirm the scan ran and returned clean. This is the least surprising option for admins.

**Suggested fix — Option B:** Give sentinel rows a `CLEAN` status label with a neutral (white) colour so the row communicates that the check ran and found nothing, rather than showing N/A which looks like a skipped check.

**Suggested fix — Option C (minimal):** Update the `Check` field on sentinel rows from `'Microsoft Defender Antivirus Exclusions'` to `'No exclusions at this location'` so the N/A status is clearly good news in context.

---

## ISSUE-005 — Secure Boot check returns FAIL instead of N/A on non-UEFI systems

**Status:** Fixed in `[Unreleased]`
**File:** `essential8compliancecheck.ps1`
**Function:** `Get-SecureBootStatus`

`Confirm-SecureBootUEFI` returns `$true` when Secure Boot is on, `$false` when Secure Boot is off, and throws `NotSupportedException` when the system is not UEFI-capable. The catch block sets `Enabled = $false`, which causes `Get-AssessmentStatus` to return `FAIL` and the GUI to render the row in red. However, a non-UEFI system (e.g. an older server running in BIOS mode) is not failing Secure Boot — the control is not applicable to that hardware. The correct value is `Enabled = $null`, which maps to `N/A` (grey row). The existing `Supported = $false` pattern used by version-gated checks demonstrates the right approach; this check should follow the same convention.

**Suggested fix:** Change the catch block to return `Enabled = $null`:

```powershell
} catch {
    ConvertTo-E8AssessmentResult `
        -Check 'Secure Boot' `
        -Category 'System Security' `
        -ML 'ML2' `
        -Enabled $null `
        -RawValue $null `
        -Detail 'Secure Boot state unavailable; system may not be UEFI-based' `
        -Description 'Validates boot components to reduce bootkit and early-start malware risk.' `
        -Recommendation 'Confirm firmware mode and enable Secure Boot on supported UEFI systems.' `
        -AdditionalProperties @{ Note = 'Cmdlet unavailable; system may not be UEFI-based' }
}
```

---

## ISSUE-006 — Detail panel prepends "Should be:" before full-sentence recommendation text

**Status:** Fixed in `[Unreleased]`
**File:** `starthere.ps1`
**Function:** `Show-DetailPanel`

`Show-DetailPanel` constructs the detail body with a hardcoded `Should be:` prefix before the `Recommendation` field:

```powershell
$DetailBody.Text = "$description`r`nASD Reference: $ml - $($result.Category)`r`nShould be: $recommendation"
```

The `Recommendation` field contains complete guidance sentences, for example: "Configure RunAsPPL to 1 or 2 through policy or managed endpoint configuration." Prefixing this with `Should be:` produces: "Should be: Configure RunAsPPL to 1 or 2 through policy or managed endpoint configuration." — grammatically broken. The prefix reads naturally for short values (e.g. "Should be: Enabled") but not for prose.

**Suggested fix:** Replace `Should be:` with `Recommendation:`, which works as a neutral prefix for any sentence style:

```powershell
$DetailBody.Text = "$description`r`nASD Reference: $ml - $($result.Category)`r`nRecommendation: $recommendation"
```

---

## ISSUE-007 — Window title, labels, and report heading use ASCII hyphens instead of em dash

**Status:** Fixed in `[Unreleased]`
**File:** `starthere.ps1`
**Lines:** `$form.Text`, `$titleLabel.Text`, `$subtitleLabel.Text`, `Get-MarkdownReport` report heading

The plan specified em dash (`—`) and middle dot (`·`) as separators throughout. The implemented code uses regular ASCII hyphens in all three visible locations: `'ASD Essential Eight - Hardening Compliance Tool'` (form title), `'Audit-only - Read-only - No changes made'` (subtitle), and `'# ASD Essential Eight - Hardening Compliance Report'` (report heading). This is a cosmetic issue but affects the professional appearance of the tool and the readability of reports shared with stakeholders.

**Suggested fix:** Replace hyphens with em dashes (`—`, Unicode U+2014) and middle dots (`·`, Unicode U+00B7) as specified. PowerShell string literals support Unicode characters directly.

---

## ISSUE-008 — Version-gate CIM call in Get-MemoryIntegrityStatus and Get-CredentialGuardStatus has no error handling

**Status:** Fixed in `[Unreleased]`
**File:** `essential8compliancecheck.ps1`
**Functions:** `Get-MemoryIntegrityStatus`, `Get-CredentialGuardStatus`

Both functions call `Get-CimInstance Win32_OperatingSystem` without a try/catch to retrieve the OS build number for version gating:

```powershell
$os = Get-CimInstance Win32_OperatingSystem
$build = $os.BuildNumber -as [int]
```

If WMI is unavailable (rare but possible on hardened, misconfigured, or degraded hosts) this throws an unhandled exception that propagates to the scan button's catch block in `starthere.ps1`, aborting the entire scan and stopping all subsequent checks. Other WMI calls in these same functions (e.g. the `Win32_DeviceGuard` query) already use try/catch; the version-gate call should follow the same pattern.

**Suggested fix:** Wrap the OS version query in a try/catch and return a `Supported = $false` result if it fails, allowing the scan to continue:

```powershell
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
    Write-Warning "Could not determine OS version for version gate: $_"
    return ConvertTo-E8AssessmentResult `
        -Check 'Memory Integrity / HVCI' `
        -Category 'Memory Protection' `
        -ML 'ML3' `
        -Enabled $null `
        -RawValue $null `
        -Detail 'Unable to determine OS version; check skipped' `
        -Description 'Uses virtualisation-based security to block unsigned or untrusted kernel-mode code.' `
        -Recommendation 'Validate WMI availability and retry on a healthy host.' `
        -AdditionalProperties @{ Supported = $false }
}
```

Apply the same pattern to `Get-CredentialGuardStatus`.

---

## ISSUE-009 — Get-ASRRuleStatus silently emits no rows when Get-MpPreference fails

**Status:** Fixed in `[Unreleased]`
**File:** `essential8compliancecheck.ps1`
**Function:** `Get-ASRRuleStatus`

When `Get-MpPreference` throws (e.g. Defender service is stopped or third-party AV has replaced Defender), the function issues `Write-Warning` and returns immediately with no output:

```powershell
} catch {
    Write-Warning "Could not query MpPreference for ASR rules: $_"
    return
}
```

The scan loop processes an empty result set and adds no rows to the ListView. All 14 ASR checks simply disappear from the results and the report with no indication of whether they were skipped or whether the rules are genuinely not configured. This also causes the non-compliant summary count in the report to undercount when Defender is not queryable.

**Suggested fix:** Emit 14 placeholder rows with `Enabled = $null` so admins can see the checks were attempted:

```powershell
} catch {
    Write-Warning "Could not query MpPreference for ASR rules: $_"
    foreach ($guid in $rules.Keys) {
        ConvertTo-E8AssessmentResult `
            -Check "ASR: $($rules[$guid])" `
            -Category 'Attack Surface Reduction' `
            -ML 'ML3' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query Defender preferences' `
            -Description 'Reduces common malware and intrusion techniques by blocking risky process, script, Office, and driver behaviours.' `
            -Recommendation 'Confirm Defender Antivirus is installed and healthy, then re-run the assessment.' `
            -AdditionalProperties @{ ActionLabel = 'Unknown'; RuleGUID = $guid }
    }
    return
}
```

---

## ISSUE-010 — SMB signing check covers server-side only; client-side signing not assessed

**Status:** Fixed in `[Unreleased]`
**File:** `essential8compliancecheck.ps1`
**Function:** `Get-SMBSigningStatus`

`Get-SMBSigningStatus` checks `RequireSecuritySignature` on the SMB **server** configuration only. Client-side SMB signing (`RequireSecuritySignature` on `Get-SmbClientConfiguration`) is not checked. ASD E8 hardening guidance recommends enforcing signing on both server and client: a host that requires signing as a server but not as a client can still initiate unsigned SMB connections to other servers, which is a lateral movement risk.

**Suggested fix:** Add a companion function `Get-SMBClientSigningStatus` that checks `(Get-SmbClientConfiguration).RequireSecuritySignature`, or expand `Get-SMBSigningStatus` to return two result rows (server and client) with appropriate `Check` names. Add the new function to `Get-E8CheckCommand` in `starthere.ps1`.
