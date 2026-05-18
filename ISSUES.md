# Issue Log

Known issues and open investigations requiring follow-up.

---

## ISSUE-001 — Policy Defender exclusion registry paths may be incorrect

**Status:** Open — awaiting verification on a Windows host with GPO-configured exclusions  
**File:** `mdeexclusionsassess.ps1`  
**Lines:** 62, 66

### Description

`Get-DefenderExclusionRegistryTarget` reads Group Policy Defender exclusions from:

```
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Paths
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Processes
```

Microsoft documentation indicates `Exclusions_Paths` and `Exclusions_Processes` are **value names** under the parent `Exclusions` key (signalling the policy is configured), not registry subkeys. The actual exclusion entries applied via Group Policy are likely stored in the `\Paths` and `\Processes` subkeys — the same naming used for local exclusions.

If this is the case, policy-configured exclusions will be silently missed. The script returns `Present = $false` for missing paths, so there is no crash — but the assessment would produce a false-negative for any GPO-sourced Defender exclusion.

### How to verify

On a Windows host where Defender path or process exclusions have been configured via Group Policy:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
```

Check whether the exclusion entries appear as:
- Values under `...\Exclusions\Paths` (subkey) — current assumption used by local path
- Values under `...\Exclusions\Exclusions_Paths` (subkey) — current script assumption
- Values directly under `...\Exclusions` with name `Exclusions_Paths` — CSP/MDM pattern

### Fix (pending verification)

If exclusions are stored under `\Paths` and `\Processes`, update `Get-DefenderExclusionRegistryTarget`:

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
