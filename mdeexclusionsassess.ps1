Set-StrictMode -Version Latest

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
            RegistryPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths'
        }
        [PSCustomObject]@{
            Source        = 'Policy'
            ExclusionType = 'Process'
            RegistryPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes'
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

    if ($normalisedValue -match '(?i)^c:\\users(\\|$|\*)') {
        return [PSCustomObject]@{
            Alert      = $true
            Severity   = 'High'
            Reason     = 'C:\Users path excluded'
            Normalised = $normalisedValue
        }
    }

    if ($normalisedValue -match '(?i)^c:\\temp(\\|$|\*)') {
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
                Category         = 'MDE Exclusions'
                ML               = $null
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
                Detail           = $entry.EntryStatus
                Description      = 'Inventories Microsoft Defender Antivirus exclusions from local and policy registry locations.'
                Recommendation   = 'Review broad or unnecessary exclusions and remove them through the controlling policy or management plane.'
            }
            continue
        }

        $risk = Get-DefenderExclusionRisk -ExclusionValue $entry.ExclusionValue
        $severity = if ($risk.Alert) { 'High' } else { 'Review' }

        [PSCustomObject]@{
            Check            = "$($entry.Source) $($entry.ExclusionType) Exclusion"
            Category         = 'MDE Exclusions'
            ML               = $null
            Alert            = $risk.Alert
            Severity         = $severity
            Source           = $entry.Source
            ExclusionType    = $entry.ExclusionType
            ExclusionValue   = $entry.ExclusionValue
            NormalisedValue  = $risk.Normalised
            Reason           = $risk.Reason
            RegistryPath     = $entry.RegistryPath
            RegistryValue    = $entry.ValueName
            RegistryData     = $entry.ValueData
            Detail           = "$($entry.ExclusionValue) - $($risk.Reason)"
            Description      = 'Inventories Microsoft Defender Antivirus exclusions and highlights broad exclusions that create avoidable detection blind spots.'
            Recommendation   = 'Validate the business need, scope the exclusion as narrowly as possible, and remove exclusions covering user profiles, temporary folders, or drive roots.'
        }
    }
}
