#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

$script:AuditPolCache = $null

# Maps each supported audit subcategory to its well-known Microsoft GUID (curly-brace
# format, as emitted by auditpol.exe). GUIDs are stable across locales, unlike the
# 'Subcategory' display name column, which auditpol localises on non-English Windows.
$script:AuditSubcategoryGuidMap = @{
    'Account Lockout'                  = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    'Logon'                            = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Logoff'                           = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    'Special Logon'                    = '{0CCE921B-69AE-11D9-BED3-505054503030}'
    'Group Membership'                 = '{0CCE9249-69AE-11D9-BED3-505054503030}'
    'Other Logon/Logoff Events'        = '{0CCE921C-69AE-11D9-BED3-505054503030}'
    'User Account Management'          = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management'        = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Computer Account Management'      = '{0CCE9236-69AE-11D9-BED3-505054503030}'
    'Other Account Management Events'  = '{0CCE923A-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change'              = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    'Other Policy Change Events'       = '{0CCE9234-69AE-11D9-BED3-505054503030}'
    'System Integrity'                 = '{0CCE9212-69AE-11D9-BED3-505054503030}'
    'Process Creation'                 = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'Process Termination'              = '{0CCE922C-69AE-11D9-BED3-505054503030}'
    'File Share'                       = '{0CCE9224-69AE-11D9-BED3-505054503030}'
    'Other Object Access Events'       = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'Kernel Object'                    = '{0CCE921F-69AE-11D9-BED3-505054503030}'
    'Detailed File Share'              = '{0CCE9244-69AE-11D9-BED3-505054503030}'
    'File System'                      = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    'Registry'                         = '{0CCE921E-69AE-11D9-BED3-505054503030}'
}

function Get-CachedAuditPolicies {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Public helper name follows the phase implementation plan.')]
    param()

    if ($null -eq $script:AuditPolCache) {
        $raw = & auditpol.exe /get /category:* /r 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "auditpol.exe failed with exit code $LASTEXITCODE. Ensure the script is running as administrator."
        }

        # Defence in depth: filter to string lines only before CSV parsing, in case
        # any non-string output slips through despite discarding stderr above.
        $script:AuditPolCache = @($raw | Where-Object { $_ -is [string] }) | ConvertFrom-Csv
    }

    return $script:AuditPolCache
}

function Get-AuditSubcategoryInclusion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubcategoryName
    )

    $guid = $script:AuditSubcategoryGuidMap[$SubcategoryName]
    if (-not $guid) {
        Write-Warning "No known GUID mapping for audit subcategory '$SubcategoryName'."
        return $null
    }

    $all = Get-CachedAuditPolicies
    # Match on the 'Subcategory GUID' column rather than the localised 'Subcategory'
    # name column, so this works on non-English Windows installations.
    $entry = $all | Where-Object { $_.'Subcategory GUID' -and $_.'Subcategory GUID'.Trim() -ieq $guid } | Select-Object -First 1
    if ($entry) {
        # NOTE: the 'Inclusion Setting' text itself (e.g. 'Success and Failure') is also
        # localised by auditpol on non-English Windows. Comparison against RequiredSetting
        # in Test-AuditSubcategoryCompliant assumes an English-language OS.
        return ($entry.'Inclusion Setting').Trim()
    }

    return $null
}

function Test-AuditSubcategoryCompliant {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentSetting,

        [Parameter(Mandatory = $true)]
        [string]$RequiredSetting
    )

    switch ($RequiredSetting) {
        'Success and Failure' { return $CurrentSetting -eq 'Success and Failure' }
        'Success'             { return $CurrentSetting -in @('Success', 'Success and Failure') }
        'Failure'             { return $CurrentSetting -in @('Failure', 'Success and Failure') }
        'No Auditing'         { return $CurrentSetting -eq 'No Auditing' }
        default               { return $false }
    }
}

function ConvertTo-AuditPolicyResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$ML,

        [AllowNull()]
        [System.Nullable[bool]]$Enabled,

        [AllowNull()]
        [object]$RawValue,

        [Parameter(Mandatory = $true)]
        [string]$Detail,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation,

        [bool]$Supported = $true,

        [string]$RequiredSetting = '',

        [string]$ActionLabel = ''
    )

    $obj = [PSCustomObject][ordered]@{
        Check           = $CheckName
        Category        = $Category
        ML              = $ML
        Enabled         = $Enabled
        RawValue        = $RawValue
        Detail          = $Detail
        Description     = $Description
        Recommendation  = $Recommendation
        Supported       = $Supported
        RequiredSetting = $RequiredSetting
    }

    if ($ActionLabel) {
        Add-Member -InputObject $obj -NotePropertyName ActionLabel -NotePropertyValue $ActionLabel
    }

    return $obj
}

function ConvertTo-AuditSettingResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $true)]
        [string]$SubcategoryName,

        [Parameter(Mandatory = $true)]
        [string]$RequiredSetting,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$ML,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation,

        [switch]$Advisory
    )

    $current = Get-AuditSubcategoryInclusion -SubcategoryName $SubcategoryName

    if ($null -eq $current) {
        # The subcategory could not be resolved from auditpol output (e.g. GUID not
        # present in this auditpol.exe /r dump). Report indeterminate rather than
        # evaluating compliance against a missing value.
        return ConvertTo-AuditPolicyResult `
            -CheckName $CheckName `
            -Category $Category `
            -ML $ML `
            -Enabled $null `
            -RawValue $null `
            -Detail "Subcategory '$SubcategoryName' could not be resolved from auditpol.exe output" `
            -Description $Description `
            -Recommendation $Recommendation `
            -RequiredSetting $RequiredSetting
    }

    $compliant = Test-AuditSubcategoryCompliant -CurrentSetting $current -RequiredSetting $RequiredSetting
    $actionLabel = if ($Advisory -and -not $compliant) { 'Warn' } else { '' }

    ConvertTo-AuditPolicyResult `
        -CheckName $CheckName `
        -Category $Category `
        -ML $ML `
        -Enabled $compliant `
        -RawValue $current `
        -Detail $current `
        -Description $Description `
        -Recommendation $Recommendation `
        -RequiredSetting $RequiredSetting `
        -ActionLabel $actionLabel
}

function Get-AuditLogSizeStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [string]$CheckName,

        [Parameter(Mandatory = $true)]
        [int]$MinimumKb,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Recommendation
    )

    try {
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        $currentKb = [int64]($log.MaximumSizeInBytes / 1KB)
        $formattedCurrent = '{0:N0} KB' -f $currentKb
        $formattedMinimum = '{0:N0} KB' -f $MinimumKb

        ConvertTo-AuditPolicyResult `
            -CheckName $CheckName `
            -Category 'Event Log Configuration' `
            -ML 'ML1' `
            -Enabled ($currentKb -ge $MinimumKb) `
            -RawValue $currentKb `
            -Detail "$formattedCurrent (minimum $formattedMinimum recommended)" `
            -Description $Description `
            -Recommendation $Recommendation `
            -RequiredSetting "$formattedMinimum minimum"
    } catch {
        Write-Warning "Unable to read $LogName event log configuration: $_"
        ConvertTo-AuditPolicyResult `
            -CheckName $CheckName `
            -Category 'Event Log Configuration' `
            -ML 'ML1' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to read log configuration' `
            -Description $Description `
            -Recommendation $Recommendation `
            -RequiredSetting ('{0:N0} KB minimum' -f $MinimumKb)
    }
}

# Uses Get-CachedOsInfo from essential8compliancecheck.ps1, which starthere.ps1 dot-sources
# before this library, so the OS query is shared across both assessment libraries per scan.
function Get-CurrentOsBuild {
    try {
        $os = Get-CachedOsInfo
        return ($os.BuildNumber -as [int])
    } catch {
        Write-Warning "Could not determine OS version for audit policy version gate: $_"
        return $null
    }
}

# Checks that the Security event log has enough capacity to retain high-value security events before overwriting.
function Get-SecurityEventLogSizeStatus {
    Get-AuditLogSizeStatus `
        -LogName 'Security' `
        -CheckName 'Security Event Log Size' `
        -MinimumKb 2097152 `
        -Description 'Ensures the Security event log is large enough to retain events before overwriting.' `
        -Recommendation 'Set the Security event log maximum size to at least 2,097,152 KB (2 GB) via Group Policy: Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security.'
}

# Checks that the Application event log has a minimum capacity suitable for operational investigations.
function Get-ApplicationEventLogSizeStatus {
    Get-AuditLogSizeStatus `
        -LogName 'Application' `
        -CheckName 'Application Event Log Size' `
        -MinimumKb 65536 `
        -Description 'Ensures the Application event log is large enough to retain application and service events before overwriting.' `
        -Recommendation 'Set the Application event log maximum size to at least 65,536 KB (64 MB) via Group Policy: Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application.'
}

# Checks that the System event log has a minimum capacity suitable for host security and reliability investigations.
function Get-SystemEventLogSizeStatus {
    Get-AuditLogSizeStatus `
        -LogName 'System' `
        -CheckName 'System Event Log Size' `
        -MinimumKb 65536 `
        -Description 'Ensures the System event log is large enough to retain operating system and service events before overwriting.' `
        -Recommendation 'Set the System event log maximum size to at least 65,536 KB (64 MB) via Group Policy: Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System.'
}

# Checks failed account lockout auditing for brute-force and password spray detection.
function Get-AuditAccountLockoutStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Account Lockout' -SubcategoryName 'Account Lockout' -RequiredSetting 'Failure' -Category 'Logon & Logoff Auditing' -ML 'ML1' -Description 'Captures account lockout failures that can indicate password spray or brute-force activity.' -Recommendation 'Configure Advanced Audit Policy to audit Failure events for Account Lockout.'
}

# Checks successful and failed logon auditing for authentication visibility.
function Get-AuditLogonStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Logon' -SubcategoryName 'Logon' -RequiredSetting 'Success and Failure' -Category 'Logon & Logoff Auditing' -ML 'ML1' -Description 'Captures successful and failed logon events needed for authentication monitoring and investigations.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Logon.'
}

# Checks logoff auditing to support session reconstruction.
function Get-AuditLogoffStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Logoff' -SubcategoryName 'Logoff' -RequiredSetting 'Success' -Category 'Logon & Logoff Auditing' -ML 'ML1' -Description 'Captures successful logoff events to support session reconstruction during investigations.' -Recommendation 'Configure Advanced Audit Policy to audit Success events for Logoff.'
}

# Checks special logon auditing for privileged and sensitive session tracking.
function Get-AuditSpecialLogonStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Special Logon' -SubcategoryName 'Special Logon' -RequiredSetting 'Success and Failure' -Category 'Logon & Logoff Auditing' -ML 'ML1' -Description 'Captures special logon events associated with privileged and sensitive security contexts.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Special Logon.'
}

# Checks additional logon and logoff auditing for broader authentication event coverage.
function Get-AuditOtherLogonLogoffStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Other Logon/Logoff Events' -SubcategoryName 'Other Logon/Logoff Events' -RequiredSetting 'Success and Failure' -Category 'Logon & Logoff Auditing' -ML 'ML2' -Description 'Captures additional logon and logoff events that assist with authentication monitoring.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Other Logon/Logoff Events.'
}

# Checks group membership auditing where supported; this subcategory exists on Windows 10 and Server 2016 or later.
function Get-AuditGroupMembershipStatus {
    $build = Get-CurrentOsBuild
    if ($null -eq $build -or $build -lt 10240) {
        return ConvertTo-AuditPolicyResult `
            -CheckName 'Audit Group Membership' `
            -Category 'Logon & Logoff Auditing' `
            -ML 'ML2' `
            -Enabled $null `
            -RawValue $build `
            -Detail 'OS build does not support Group Membership audit subcategory' `
            -Description 'Captures group membership details at logon to support privilege and access investigations.' `
            -Recommendation 'Use Windows 10, Windows Server 2016, or later to audit Group Membership events.' `
            -Supported $false `
            -RequiredSetting 'Success'
    }

    ConvertTo-AuditSettingResult -CheckName 'Audit Group Membership' -SubcategoryName 'Group Membership' -RequiredSetting 'Success' -Category 'Logon & Logoff Auditing' -ML 'ML2' -Description 'Captures group membership details at logon to support privilege and access investigations.' -Recommendation 'Configure Advanced Audit Policy to audit Success events for Group Membership.'
}

# Checks user account management auditing for identity lifecycle changes.
function Get-AuditUserAccountMgmtStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit User Account Management' -SubcategoryName 'User Account Management' -RequiredSetting 'Success and Failure' -Category 'Account Management Auditing' -ML 'ML2' -Description 'Captures user account creation, deletion, disablement, and modification events.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for User Account Management.'
}

# Checks security group management auditing for privilege and access control changes.
function Get-AuditSecurityGroupMgmtStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Security Group Management' -SubcategoryName 'Security Group Management' -RequiredSetting 'Success and Failure' -Category 'Account Management Auditing' -ML 'ML2' -Description 'Captures security group creation, deletion, and membership changes.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Security Group Management.'
}

# Checks computer account management auditing for domain-joined endpoint lifecycle visibility.
function Get-AuditComputerAccountMgmtStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Computer Account Management' -SubcategoryName 'Computer Account Management' -RequiredSetting 'Success and Failure' -Category 'Account Management Auditing' -ML 'ML2' -Description 'Captures computer account creation, deletion, and modification events.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Computer Account Management.'
}

# Checks other account management auditing for account events not covered by narrower subcategories.
function Get-AuditOtherAccountMgmtStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Other Account Management Events' -SubcategoryName 'Other Account Management Events' -RequiredSetting 'Success and Failure' -Category 'Account Management Auditing' -ML 'ML2' -Description 'Captures account management events that are not covered by the primary account management subcategories.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Other Account Management Events.'
}

# Checks audit policy change auditing so reductions in logging are themselves visible.
function Get-AuditPolicyChangeStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Policy Change' -SubcategoryName 'Audit Policy Change' -RequiredSetting 'Success and Failure' -Category 'Policy Change Auditing' -ML 'ML2' -Description 'Captures changes to audit policy so logging reductions and tampering can be investigated.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Audit Policy Change.'
}

# Checks other policy change auditing for additional security policy modifications.
function Get-AuditOtherPolicyChangeStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Other Policy Change Events' -SubcategoryName 'Other Policy Change Events' -RequiredSetting 'Success and Failure' -Category 'Policy Change Auditing' -ML 'ML2' -Description 'Captures additional policy change events relevant to host security posture.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Other Policy Change Events.'
}

# Checks system integrity auditing for code integrity, security package, and system-level integrity events.
function Get-AuditSystemIntegrityStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit System Integrity' -SubcategoryName 'System Integrity' -RequiredSetting 'Success and Failure' -Category 'System Auditing' -ML 'ML2' -Description 'Captures system integrity events relevant to code integrity, security package, and host tampering investigations.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for System Integrity.'
}

# Checks native process creation auditing as a fallback and complement to Sysmon and command-line capture checks.
function Get-AuditProcessCreationStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Process Creation' -SubcategoryName 'Process Creation' -RequiredSetting 'Success' -Category 'Process Tracking Auditing' -ML 'ML2' -Description 'Captures process creation events; Sysmon is preferred, but this verifies native process tracking is configured as a fallback.' -Recommendation 'Configure Advanced Audit Policy to audit Success events for Process Creation and ensure command-line capture is enabled.'
}

# Checks process termination auditing to help reconstruct process activity timelines.
function Get-AuditProcessTerminationStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Process Termination' -SubcategoryName 'Process Termination' -RequiredSetting 'Success' -Category 'Process Tracking Auditing' -ML 'ML2' -Description 'Captures process termination events to help reconstruct process activity timelines.' -Recommendation 'Configure Advanced Audit Policy to audit Success events for Process Termination.'
}

# Checks file share access auditing for network share access visibility.
function Get-AuditFileShareStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit File Share' -SubcategoryName 'File Share' -RequiredSetting 'Success and Failure' -Category 'Object Access Auditing' -ML 'ML2' -Description 'Captures file share access events that support investigation of network share activity.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for File Share.'
}

# Checks additional object access auditing, including WMI and scheduled task activity.
function Get-AuditOtherObjectAccessStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Other Object Access Events' -SubcategoryName 'Other Object Access Events' -RequiredSetting 'Success and Failure' -Category 'Object Access Auditing' -ML 'ML2' -Description 'Captures additional object access events, including WMI and scheduled task activity.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Other Object Access Events.'
}

# Checks kernel object access auditing for higher-maturity object access visibility.
function Get-AuditKernelObjectStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Kernel Object' -SubcategoryName 'Kernel Object' -RequiredSetting 'Success and Failure' -Category 'Object Access Auditing' -ML 'ML3' -Description 'Captures kernel object access events that can support higher-maturity host investigations.' -Recommendation 'Configure Advanced Audit Policy to audit Success and Failure events for Kernel Object.'
}

# Checks that Detailed File Share auditing remains disabled because ASD advises against its high-volume, low-value event stream.
function Get-AuditDetailedFileShareStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Detailed File Share' -SubcategoryName 'Detailed File Share' -RequiredSetting 'No Auditing' -Category 'Object Access Auditing' -ML 'ML2' -Description 'ASD advises against enabling Detailed File Share auditing due to the high volume of low-value events it generates.' -Recommendation 'Ensure Detailed File Share auditing remains set to No Auditing to avoid log noise.' -Advisory
}

# Checks optional file system auditing and reports gaps as REVIEW because ASD treats it as optional.
function Get-AuditFileSystemStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit File System' -SubcategoryName 'File System' -RequiredSetting 'Success and Failure' -Category 'Object Access Auditing' -ML 'ML3' -Description 'Captures file system object access events where targeted auditing is required for higher-maturity monitoring.' -Recommendation 'Consider configuring Success and Failure auditing for File System where the event volume is supportable and scoped SACLs are managed.' -Advisory
}

# Checks optional registry auditing and reports gaps as REVIEW because ASD treats it as optional.
function Get-AuditRegistryStatus {
    ConvertTo-AuditSettingResult -CheckName 'Audit Registry' -SubcategoryName 'Registry' -RequiredSetting 'Success and Failure' -Category 'Object Access Auditing' -ML 'ML3' -Description 'Captures registry object access events where targeted auditing is required for higher-maturity monitoring.' -Recommendation 'Consider configuring Success and Failure auditing for Registry where the event volume is supportable and scoped SACLs are managed.' -Advisory
}

# Checks outgoing NTLM auditing to support detection of NTLM relay, misuse, and brute-force activity.
function Get-NTLMAuditingStatus {
    # Uses Get-RegistryPropertyValue from essential8compliancecheck.ps1 (dot-sourced by
    # starthere.ps1 before this library) rather than Get-ItemProperty directly, because
    # dot-accessing a property on the $null Get-ItemProperty returns when the value is
    # absent throws under Set-StrictMode -Version Latest — the common case on a host
    # where NTLM outgoing traffic auditing has never been configured.
    $val = Get-RegistryPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
        -Name 'RestrictSendingNTLMTraffic'

    $effectiveValue = if ($null -eq $val) { 0 } else { [int]$val }
    $detail = switch ($effectiveValue) {
        0 { 'Not configured - Allow all (0)' }
        1 { 'Audit all (1)' }
        2 { 'Deny all (2)' }
        default { "Unexpected value ($effectiveValue)" }
    }

    ConvertTo-AuditPolicyResult `
        -CheckName 'NTLM Outgoing Traffic Auditing' `
        -Category 'Network Auditing' `
        -ML 'ML3' `
        -Enabled ($effectiveValue -ge 1) `
        -RawValue $val `
        -Detail $detail `
        -Description 'Audits outgoing NTLM authentication requests, enabling detection of NTLM relay and brute-force attacks.' `
        -Recommendation 'Set Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers to Audit all (1) or Deny all (2) via Group Policy or Local Security Policy.' `
        -RequiredSetting 'Audit all (1) or Deny all (2)'
}

function Get-AuditPolicyCheckCommands {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Public command-list helper name follows the phase implementation plan.')]
    param()

    return @(
        'Get-SecurityEventLogSizeStatus'
        'Get-ApplicationEventLogSizeStatus'
        'Get-SystemEventLogSizeStatus'
        'Get-AuditAccountLockoutStatus'
        'Get-AuditLogonStatus'
        'Get-AuditLogoffStatus'
        'Get-AuditSpecialLogonStatus'
        'Get-AuditGroupMembershipStatus'
        'Get-AuditOtherLogonLogoffStatus'
        'Get-AuditUserAccountMgmtStatus'
        'Get-AuditSecurityGroupMgmtStatus'
        'Get-AuditComputerAccountMgmtStatus'
        'Get-AuditOtherAccountMgmtStatus'
        'Get-AuditPolicyChangeStatus'
        'Get-AuditOtherPolicyChangeStatus'
        'Get-AuditSystemIntegrityStatus'
        'Get-AuditProcessCreationStatus'
        'Get-AuditProcessTerminationStatus'
        'Get-AuditFileShareStatus'
        'Get-AuditOtherObjectAccessStatus'
        'Get-AuditKernelObjectStatus'
        'Get-AuditDetailedFileShareStatus'
        'Get-AuditFileSystemStatus'
        'Get-AuditRegistryStatus'
        'Get-NTLMAuditingStatus'
    )
}
