[CmdletBinding()]
param(
    [switch]$NoElevation
)

Set-StrictMode -Version Latest

function Test-IsWindowsHost {
    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevation {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if (-not $PSCommandPath) {
        throw 'Unable to determine the current script path for elevation.'
    }

    $powerShellPath = (Get-Process -Id $PID).Path
    if (-not $powerShellPath) {
        $powerShellPath = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    }

    $argumentList = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        "`"$PSCommandPath`""
        '-NoElevation'
    )

    if ($PSCmdlet.ShouldProcess($PSCommandPath, 'Restart this script with administrator privileges')) {
        Start-Process -FilePath $powerShellPath -ArgumentList $argumentList -Verb RunAs
    }
}

function Get-DefenderExclusionRegistryTarget {
    @(
        [PSCustomObject]@{
            Source        = 'Local'
            ExclusionType = 'Path'
            RegistryPath  = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths'
        }
        [PSCustomObject]@{
            Source        = 'Local'
            ExclusionType = 'Process'
            RegistryPath  = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes'
        }
        [PSCustomObject]@{
            Source        = 'Policy'
            ExclusionType = 'Path'
            RegistryPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Paths'
        }
        [PSCustomObject]@{
            Source        = 'Policy'
            ExclusionType = 'Process'
            RegistryPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Exclusions_Processes'
        }
    )
}

function Get-DefenderExclusionRegistryEntry {
    <#
    Reads Microsoft Defender Antivirus exclusion entries from local and policy
    registry locations. The script is audit-only and does not modify Defender,
    registry, or policy state.
    #>
    foreach ($target in Get-DefenderExclusionRegistryTarget) {
        if (-not (Test-Path -Path $target.RegistryPath -PathType Container)) {
            [PSCustomObject]@{
                Source         = $target.Source
                ExclusionType  = $target.ExclusionType
                RegistryPath   = $target.RegistryPath
                ExclusionValue = $null
                ValueName      = $null
                ValueData      = $null
                Present        = $false
                EntryStatus    = 'Registry path not present'
            }
            continue
        }

        try {
            $registryKey = Get-Item -Path $target.RegistryPath -ErrorAction Stop
            $valueNames = @($registryKey.GetValueNames())

            if ($valueNames.Count -eq 0) {
                [PSCustomObject]@{
                    Source         = $target.Source
                    ExclusionType  = $target.ExclusionType
                    RegistryPath   = $target.RegistryPath
                    ExclusionValue = $null
                    ValueName      = $null
                    ValueData      = $null
                    Present        = $false
                    EntryStatus    = 'No exclusion values configured'
                }
                continue
            }

            foreach ($valueName in $valueNames) {
                $valueData = $registryKey.GetValue($valueName)
                $exclusionValue = if ($valueData -is [string] -and -not [string]::IsNullOrWhiteSpace($valueData)) {
                    $valueData
                } else {
                    $valueName
                }

                [PSCustomObject]@{
                    Source         = $target.Source
                    ExclusionType  = $target.ExclusionType
                    RegistryPath   = $target.RegistryPath
                    ExclusionValue = $exclusionValue
                    ValueName      = $valueName
                    ValueData      = $valueData
                    Present        = $true
                    EntryStatus    = 'Exclusion value configured'
                }
            }
        } catch {
            Write-Warning "Could not read Defender exclusion registry path '$($target.RegistryPath)': $_"
            [PSCustomObject]@{
                Source         = $target.Source
                ExclusionType  = $target.ExclusionType
                RegistryPath   = $target.RegistryPath
                ExclusionValue = $null
                ValueName      = $null
                ValueData      = $null
                Present        = $null
                EntryStatus    = 'Registry path not readable'
            }
        }
    }
}

function ConvertTo-NormalisedExclusionValue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $expanded = [System.Environment]::ExpandEnvironmentVariables($Value)
    $trimmed = $expanded.Trim().Trim('"')

    return $trimmed -replace '/', '\'
}

function Get-DefenderExclusionRisk {
    <#
    Identifies high-risk file, folder, and process exclusions that create broad
    blind spots in locations commonly abused by malware and hands-on-keyboard
    activity: C:\Users, C:\Temp, and entire drive roots such as C:\ or D:.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ExclusionValue
    )

    $normalisedValue = ConvertTo-NormalisedExclusionValue -Value $ExclusionValue

    if ([string]::IsNullOrWhiteSpace($normalisedValue)) {
        return [PSCustomObject]@{
            Alert      = $false
            Severity   = 'None'
            Reason     = 'Empty exclusion value'
            Normalised = $normalisedValue
        }
    }

    if ($normalisedValue -match '^[A-Za-z]:\\?(\*|\*\.\*)?$' -or $normalisedValue -match '^[A-Za-z]:\\(\*|\*\.\*)$') {
        return [PSCustomObject]@{
            Alert      = $true
            Severity   = 'High'
            Reason     = 'Entire drive root excluded'
            Normalised = $normalisedValue
        }
    }

    if ($normalisedValue -match '^(?i)c:\\users(\\|$|\*)') {
        return [PSCustomObject]@{
            Alert      = $true
            Severity   = 'High'
            Reason     = 'C:\Users path excluded'
            Normalised = $normalisedValue
        }
    }

    if ($normalisedValue -match '^(?i)c:\\temp(\\|$|\*)') {
        return [PSCustomObject]@{
            Alert      = $true
            Severity   = 'High'
            Reason     = 'C:\Temp path excluded'
            Normalised = $normalisedValue
        }
    }

    [PSCustomObject]@{
        Alert      = $false
        Severity   = 'None'
        Reason     = 'No risky path pattern matched'
        Normalised = $normalisedValue
    }
}

function Get-MdeExclusionAssessment {
    $entries = @(Get-DefenderExclusionRegistryEntry)

    foreach ($entry in $entries) {
        if (-not $entry.Present) {
            [PSCustomObject]@{
                Check            = 'Microsoft Defender Antivirus Exclusions'
                Alert            = $false
                Severity         = 'None'
                Source           = $entry.Source
                ExclusionType    = $entry.ExclusionType
                ExclusionValue   = $entry.ExclusionValue
                NormalisedValue  = $null
                Reason           = $entry.EntryStatus
                RegistryPath     = $entry.RegistryPath
                RegistryValue    = $entry.ValueName
                RegistryData     = $entry.ValueData
            }
            continue
        }

        $risk = Get-DefenderExclusionRisk -ExclusionValue $entry.ExclusionValue

        [PSCustomObject]@{
            Check            = 'Microsoft Defender Antivirus Exclusions'
            Alert            = $risk.Alert
            Severity         = $risk.Severity
            Source           = $entry.Source
            ExclusionType    = $entry.ExclusionType
            ExclusionValue   = $entry.ExclusionValue
            NormalisedValue  = $risk.Normalised
            Reason           = $risk.Reason
            RegistryPath     = $entry.RegistryPath
            RegistryValue    = $entry.ValueName
            RegistryData     = $entry.ValueData
        }
    }
}

if (-not (Test-IsWindowsHost)) {
    throw 'mdeexclusionsassess.ps1 requires Windows because Microsoft Defender Antivirus exclusion state is stored in the Windows registry.'
}

if (-not (Test-IsAdministrator)) {
    if ($NoElevation) {
        throw 'Administrator privileges are required to read Microsoft Defender Antivirus exclusion registry locations.'
    }

    Invoke-SelfElevation
    return
}

$results = @(Get-MdeExclusionAssessment)
$alerts = @($results | Where-Object { $_.Alert -eq $true })

if ($alerts.Count -gt 0) {
    Write-Warning "$($alerts.Count) high-risk Microsoft Defender Antivirus exclusion(s) detected."
}

$results | Sort-Object @{Expression = 'Alert'; Descending = $true}, Source, ExclusionType, ExclusionValue | Format-List
