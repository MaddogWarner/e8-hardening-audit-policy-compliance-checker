#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

function ConvertTo-E8AssessmentResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Check,

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

        [hashtable]$AdditionalProperties
    )

    $result = [ordered]@{
        Check          = $Check
        Category       = $Category
        ML             = $ML
        Enabled        = $Enabled
        RawValue       = $RawValue
        Detail         = $Detail
        Description    = $Description
        Recommendation = $Recommendation
    }

    if ($AdditionalProperties) {
        foreach ($key in $AdditionalProperties.Keys) {
            $result[$key] = $AdditionalProperties[$key]
        }
    }

    [PSCustomObject]$result
}

function ConvertTo-E8ValueText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'Not configured'
    }

    if ($Value -is [array]) {
        return ($Value -join ', ')
    }

    return [string]$Value
}

# Checks whether LSASS is configured to run as a Protected Process Light (PPL),
# preventing code injection and memory dumping by non-protected processes.
function Get-LsaProtectionStatus {
    $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL

    ConvertTo-E8AssessmentResult `
        -Check 'LSASS Protected Process Light (PPL)' `
        -Category 'Memory Protection' `
        -ML 'ML2' `
        -Enabled ($val -in 1, 2) `
        -RawValue $val `
        -Detail "RunAsPPL = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Protects the LSASS process from non-protected code injection and credential dumping.' `
        -Recommendation 'Configure RunAsPPL to 1 or 2 through policy or managed endpoint configuration.'
}

# Checks whether Hypervisor-Protected Code Integrity (HVCI / Memory Integrity) is running.
# Workstations require Windows 10 1709+; servers require Windows Server 2019+.
function Get-MemoryIntegrityStatus {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    } catch {
        Write-Warning "Could not determine OS version for Memory Integrity version gate: $_"
        return ConvertTo-E8AssessmentResult `
            -Check 'Memory Integrity / HVCI' `
            -Category 'Memory Protection' `
            -ML 'ML3' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to determine OS version; check skipped' `
            -Description 'Uses virtualisation-based security to block unsigned or untrusted kernel-mode code.' `
            -Recommendation 'Validate WMI/CIM availability and retry on a healthy host.' `
            -AdditionalProperties @{ Supported = $false }
    }

    $build = $os.BuildNumber -as [int]
    $minBuild = if ($os.ProductType -eq 1) { 16299 } else { 17763 }

    if ($build -lt $minBuild) {
        return ConvertTo-E8AssessmentResult `
            -Check 'Memory Integrity / HVCI' `
            -Category 'Memory Protection' `
            -ML 'ML3' `
            -Enabled $null `
            -RawValue $build `
            -Detail "OS build $build does not meet the minimum supported build $minBuild" `
            -Description 'Uses virtualisation-based security to block unsigned or untrusted kernel-mode code.' `
            -Recommendation 'Use a supported Windows build and enable Memory Integrity where hardware and driver compatibility allow.' `
            -AdditionalProperties @{ Supported = $false }
    }

    $configuredValue = (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' `
        -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
            -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        $enabled = ($dg.SecurityServicesRunning -contains 2)
        ConvertTo-E8AssessmentResult `
            -Check 'Memory Integrity / HVCI' `
            -Category 'Memory Protection' `
            -ML 'ML3' `
            -Enabled $enabled `
            -RawValue $dg.SecurityServicesRunning `
            -Detail "SecurityServicesRunning = $(ConvertTo-E8ValueText -Value $dg.SecurityServicesRunning); configured registry value = $(ConvertTo-E8ValueText -Value $configuredValue)" `
            -Description 'Uses virtualisation-based security to block unsigned or untrusted kernel-mode code.' `
            -Recommendation 'Enable Memory Integrity through Windows Security, Intune, Group Policy, or baseline configuration where compatible.' `
            -AdditionalProperties @{ Supported = $true; Configured = ($configuredValue -eq 1) }
    } catch {
        Write-Warning "Win32_DeviceGuard unavailable, falling back to registry configuration: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'Memory Integrity / HVCI' `
            -Category 'Memory Protection' `
            -ML 'ML3' `
            -Enabled ($configuredValue -eq 1) `
            -RawValue $configuredValue `
            -Detail "Runtime state unavailable; configured registry value = $(ConvertTo-E8ValueText -Value $configuredValue)" `
            -Description 'Uses virtualisation-based security to block unsigned or untrusted kernel-mode code.' `
            -Recommendation 'Confirm runtime state on a supported host and enable Memory Integrity where compatible.' `
            -AdditionalProperties @{ Supported = $true; Configured = ($configuredValue -eq 1); Note = 'Runtime state unavailable; reporting configured registry state' }
    }
}

# Checks whether Credential Guard is actively running via Virtualisation-Based Security.
function Get-CredentialGuardStatus {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    } catch {
        Write-Warning "Could not determine OS version for Credential Guard version gate: $_"
        return ConvertTo-E8AssessmentResult `
            -Check 'Credential Guard' `
            -Category 'Memory Protection' `
            -ML 'ML2' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to determine OS version; check skipped' `
            -Description 'Protects domain credential material by isolating secrets with virtualisation-based security.' `
            -Recommendation 'Validate WMI/CIM availability and retry on a healthy host.' `
            -AdditionalProperties @{ Supported = $false }
    }

    $build = $os.BuildNumber -as [int]
    $minBuild = if ($os.ProductType -eq 1) { 10586 } else { 14393 }

    if ($build -lt $minBuild) {
        return ConvertTo-E8AssessmentResult `
            -Check 'Credential Guard' `
            -Category 'Memory Protection' `
            -ML 'ML2' `
            -Enabled $null `
            -RawValue $build `
            -Detail "OS build $build does not meet the minimum supported build $minBuild" `
            -Description 'Protects domain credential material by isolating secrets with virtualisation-based security.' `
            -Recommendation 'Use a supported Windows build and enable Credential Guard where identity workflows support it.' `
            -AdditionalProperties @{ Supported = $false }
    }

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
            -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'Credential Guard' `
            -Category 'Memory Protection' `
            -ML 'ML2' `
            -Enabled ($dg.SecurityServicesRunning -contains 1) `
            -RawValue $dg.SecurityServicesRunning `
            -Detail "SecurityServicesRunning = $(ConvertTo-E8ValueText -Value $dg.SecurityServicesRunning)" `
            -Description 'Protects domain credential material by isolating secrets with virtualisation-based security.' `
            -Recommendation 'Enable Credential Guard through Intune, Group Policy, or enterprise security baseline after compatibility testing.' `
            -AdditionalProperties @{ Supported = $true }
    } catch {
        Write-Warning "Win32_DeviceGuard unavailable, falling back to registry: $_"
        $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue).LsaCfgFlags
        ConvertTo-E8AssessmentResult `
            -Check 'Credential Guard' `
            -Category 'Memory Protection' `
            -ML 'ML2' `
            -Enabled ($val -in 1, 2) `
            -RawValue $val `
            -Detail "Runtime state unavailable; LsaCfgFlags = $(ConvertTo-E8ValueText -Value $val)" `
            -Description 'Protects domain credential material by isolating secrets with virtualisation-based security.' `
            -Recommendation 'Confirm runtime state and configure Credential Guard where supported by hardware, OS, and operational requirements.' `
            -AdditionalProperties @{ Supported = $true; Note = 'Runtime state unavailable; reporting configured registry state' }
    }
}

# Checks whether full command-line arguments are captured in process creation audit events.
function Get-ProcessCmdLineAuditStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled

    ConvertTo-E8AssessmentResult `
        -Check 'Process Creation Command Line Logging' `
        -Category 'Audit Logging' `
        -ML 'ML2' `
        -Enabled ($val -eq 1) `
        -RawValue $val `
        -Detail "ProcessCreationIncludeCmdLine_Enabled = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Captures command-line arguments in process creation events to improve investigation and detection context.' `
        -Recommendation 'Enable command-line capture for process creation auditing and ensure Event ID 4688 is collected centrally.'
}

# Checks whether PowerShell Script Block Logging is enabled.
function Get-PSScriptBlockLoggingStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging

    ConvertTo-E8AssessmentResult `
        -Check 'PowerShell Script Block Logging' `
        -Category 'PowerShell Hardening' `
        -ML 'ML2' `
        -Enabled ($val -eq 1) `
        -RawValue $val `
        -Detail "EnableScriptBlockLogging = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Records executed PowerShell script block content for detection, investigation, and audit evidence.' `
        -Recommendation 'Enable Script Block Logging by Group Policy, Intune, or equivalent managed configuration.'
}

# Checks whether PowerShell Module Logging is enabled.
function Get-PSModuleLoggingStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging

    ConvertTo-E8AssessmentResult `
        -Check 'PowerShell Module Logging' `
        -Category 'PowerShell Hardening' `
        -ML 'ML2' `
        -Enabled ($val -eq 1) `
        -RawValue $val `
        -Detail "EnableModuleLogging = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Records PowerShell module and pipeline activity to support monitoring and forensic review.' `
        -Recommendation 'Enable Module Logging for all modules and collect Event ID 4103 centrally.'
}

# Checks whether PowerShell Transcription is enabled.
function Get-PSTranscriptionStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        -Name 'EnableTranscripting' -ErrorAction SilentlyContinue).EnableTranscripting

    ConvertTo-E8AssessmentResult `
        -Check 'PowerShell Transcription' `
        -Category 'PowerShell Hardening' `
        -ML 'ML2' `
        -Enabled ($val -eq 1) `
        -RawValue $val `
        -Detail "EnableTranscripting = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Creates text transcripts of PowerShell activity for auditability and incident response.' `
        -Recommendation 'Enable PowerShell transcription and store transcripts in a protected, centralised location.'
}

# Checks whether the legacy PowerShell v2 engine is disabled.
function Get-PowerShellV2Status {
    try {
        $feature = Get-WindowsOptionalFeature -Online `
            -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'PowerShell v2 Engine Disabled' `
            -Category 'PowerShell Hardening' `
            -ML 'ML2' `
            -Enabled ($feature.State -eq 'Disabled') `
            -RawValue $feature.State `
            -Detail "MicrosoftWindowsPowerShellV2Root = $($feature.State)" `
            -Description 'Removes the legacy PowerShell v2 engine, which lacks modern logging and AMSI integration.' `
            -Recommendation 'Disable the MicrosoftWindowsPowerShellV2Root optional feature unless a documented legacy dependency exists.'
    } catch {
        Write-Warning "Could not check PowerShell v2 feature status: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'PowerShell v2 Engine Disabled' `
            -Category 'PowerShell Hardening' `
            -ML 'ML2' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query Windows optional feature state' `
            -Description 'Removes the legacy PowerShell v2 engine, which lacks modern logging and AMSI integration.' `
            -Recommendation 'Validate the optional feature state on the host and disable PowerShell v2 where possible.'
    }
}

# Checks whether this PowerShell session is running under Constrained Language Mode.
function Get-PSConstrainedLanguageModeStatus {
    $languageMode = $ExecutionContext.SessionState.LanguageMode
    $lockdownPolicy = (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' `
        -Name '__PSLockdownPolicy' -ErrorAction SilentlyContinue).__PSLockdownPolicy

    ConvertTo-E8AssessmentResult `
        -Check 'PowerShell Constrained Language Mode' `
        -Category 'PowerShell Hardening' `
        -ML 'ML2' `
        -Enabled ($languageMode -eq 'ConstrainedLanguage') `
        -RawValue $languageMode `
        -Detail "LanguageMode = $languageMode; __PSLockdownPolicy = $(ConvertTo-E8ValueText -Value $lockdownPolicy)" `
        -Description 'Restricts PowerShell language features to reduce abuse of .NET, COM, and arbitrary code execution primitives.' `
        -Recommendation 'Enforce Constrained Language Mode through WDAC or AppLocker; registry lockdown policy alone should not be treated as the preferred enterprise control.' `
        -AdditionalProperties @{ LockdownPolicy = $lockdownPolicy }
}

# Checks whether execution policy is restrictive at MachinePolicy or LocalMachine scope.
function Get-PSExecutionPolicyStatus {
    $policies = @(Get-ExecutionPolicy -List)
    $machinePolicy = ($policies | Where-Object { $_.Scope -eq 'MachinePolicy' }).ExecutionPolicy
    $localMachine = ($policies | Where-Object { $_.Scope -eq 'LocalMachine' }).ExecutionPolicy
    $effectivePolicy = Get-ExecutionPolicy
    $unsafeScopes = @($policies | Where-Object { $_.ExecutionPolicy -in @('Unrestricted', 'Bypass') })
    $restrictivePolicy = @('AllSigned', 'RemoteSigned')
    $enabled = (($machinePolicy -in $restrictivePolicy) -or ($localMachine -in $restrictivePolicy)) -and ($unsafeScopes.Count -eq 0)

    ConvertTo-E8AssessmentResult `
        -Check 'PowerShell Execution Policy' `
        -Category 'PowerShell Hardening' `
        -ML 'ML2' `
        -Enabled $enabled `
        -RawValue $effectivePolicy `
        -Detail "Effective = $effectivePolicy; MachinePolicy = $machinePolicy; LocalMachine = $localMachine" `
        -Description 'Sets a baseline control for script execution and helps prevent accidental execution of untrusted scripts.' `
        -Recommendation 'Set MachinePolicy or LocalMachine to AllSigned or RemoteSigned and remove Unrestricted or Bypass from all scopes.' `
        -AdditionalProperties @{ PolicyList = $policies; UnsafeScopes = ($unsafeScopes.Scope -join ', ') }
}

# Checks whether Windows Defender real-time protection is active.
function Get-DefenderRealTimeStatus {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'Defender Real-Time Protection' `
            -Category 'Defender' `
            -ML 'ML1' `
            -Enabled (-not $pref.DisableRealtimeMonitoring) `
            -RawValue $pref.DisableRealtimeMonitoring `
            -Detail "DisableRealtimeMonitoring = $($pref.DisableRealtimeMonitoring)" `
            -Description 'Ensures Defender Antivirus actively scans files and processes as they are accessed.' `
            -Recommendation 'Enable Defender real-time protection and prevent local users from disabling it.'
    } catch {
        Write-Warning "Could not query Defender preferences: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'Defender Real-Time Protection' `
            -Category 'Defender' `
            -ML 'ML1' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query Defender preferences' `
            -Description 'Ensures Defender Antivirus actively scans files and processes as they are accessed.' `
            -Recommendation 'Confirm Defender Antivirus is installed, healthy, and manageable on this host.'
    }
}

# Checks whether Defender cloud-delivered protection is enabled.
function Get-DefenderCloudProtectionStatus {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'Defender Cloud-Delivered Protection' `
            -Category 'Defender' `
            -ML 'ML1' `
            -Enabled ($pref.MAPSReporting -ge 1) `
            -RawValue $pref.MAPSReporting `
            -Detail "MAPSReporting = $($pref.MAPSReporting)" `
            -Description 'Uses Microsoft cloud intelligence to improve malware detection and response.' `
            -Recommendation 'Enable cloud-delivered protection at Basic or Advanced level through managed Defender policy.'
    } catch {
        Write-Warning "Could not query Defender preferences: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'Defender Cloud-Delivered Protection' `
            -Category 'Defender' `
            -ML 'ML1' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query Defender preferences' `
            -Description 'Uses Microsoft cloud intelligence to improve malware detection and response.' `
            -Recommendation 'Confirm Defender Antivirus is installed, healthy, and managed by policy.'
    }
}

# Checks whether Defender Tamper Protection is active.
function Get-DefenderTamperProtectionStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' `
        -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection

    ConvertTo-E8AssessmentResult `
        -Check 'Defender Tamper Protection' `
        -Category 'Defender' `
        -ML 'ML2' `
        -Enabled ($val -eq 5) `
        -RawValue $val `
        -Detail "TamperProtection = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Prevents unauthorised or malicious changes to critical Defender settings.' `
        -Recommendation 'Enable Tamper Protection through Microsoft Defender for Endpoint or endpoint security policy.'
}

# Checks the configured action for each E8-relevant ASR rule via Get-MpPreference.
function Get-ASRRuleStatus {
    $rules = [ordered]@{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from injecting into other processes'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executables'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email and webmail'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables not meeting prevalence, age, or trusted list criteria'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes from USB'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
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

    $ruleMap = @{}
    if ($pref.AttackSurfaceReductionRules_Ids) {
        for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $ruleMap[$pref.AttackSurfaceReductionRules_Ids[$i].ToLower()] = $pref.AttackSurfaceReductionRules_Actions[$i]
        }
    }

    foreach ($guid in $rules.Keys) {
        $action = $ruleMap[$guid.ToLower()]
        $actionLabel = switch ($action) {
            0       { 'Not Configured' }
            1       { 'Block' }
            2       { 'Audit' }
            6       { 'Warn' }
            default { if ($null -eq $action) { 'Not Configured' } else { "Unknown ($action)" } }
        }

        ConvertTo-E8AssessmentResult `
            -Check "ASR: $($rules[$guid])" `
            -Category 'Attack Surface Reduction' `
            -ML 'ML3' `
            -Enabled ($action -eq 1) `
            -RawValue $action `
            -Detail "Action = $(ConvertTo-E8ValueText -Value $action) ($actionLabel)" `
            -Description 'Reduces common malware and intrusion techniques by blocking risky process, script, Office, and driver behaviours.' `
            -Recommendation 'Configure this ASR rule to Block mode after staged Audit or Warn mode validation.' `
            -AdditionalProperties @{ ActionLabel = $actionLabel; RuleGUID = $guid }
    }
}

# Checks whether the legacy SMBv1 protocol is disabled.
function Get-SMBv1Status {
    try {
        $config = Get-SmbServerConfiguration -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'SMBv1 Disabled' `
            -Category 'Network' `
            -ML 'ML1' `
            -Enabled (-not $config.EnableSMB1Protocol) `
            -RawValue $config.EnableSMB1Protocol `
            -Detail "EnableSMB1Protocol = $($config.EnableSMB1Protocol)" `
            -Description 'Disables the legacy SMBv1 protocol to reduce exposure to known remote exploitation paths.' `
            -Recommendation 'Disable SMBv1 unless a formally accepted legacy dependency exists.'
    } catch {
        Write-Warning "Could not query SMB server configuration: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'SMBv1 Disabled' `
            -Category 'Network' `
            -ML 'ML1' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query SMB server configuration' `
            -Description 'Disables the legacy SMBv1 protocol to reduce exposure to known remote exploitation paths.' `
            -Recommendation 'Validate SMB server configuration on this host and disable SMBv1 where possible.'
    }
}

# Checks whether SMB packet signing is required on the server.
function Get-SMBSigningStatus {
    try {
        $config = Get-SmbServerConfiguration -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'SMB Server Signing Required' `
            -Category 'Network' `
            -ML 'ML2' `
            -Enabled $config.RequireSecuritySignature `
            -RawValue $config.RequireSecuritySignature `
            -Detail "RequireSecuritySignature = $($config.RequireSecuritySignature)" `
            -Description 'Requires SMB signing for inbound SMB server sessions to reduce man-in-the-middle tampering.' `
            -Recommendation 'Require SMB server signing and validate compatibility with legacy clients.'
    } catch {
        Write-Warning "Could not query SMB server configuration: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'SMB Server Signing Required' `
            -Category 'Network' `
            -ML 'ML2' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query SMB server configuration' `
            -Description 'Requires SMB signing for inbound SMB server sessions to reduce man-in-the-middle tampering.' `
            -Recommendation 'Validate SMB server signing configuration through policy and server configuration.'
    }
}

# Checks whether SMB packet signing is required for outbound client sessions.
function Get-SMBClientSigningStatus {
    try {
        $config = Get-SmbClientConfiguration -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'SMB Client Signing Required' `
            -Category 'Network' `
            -ML 'ML2' `
            -Enabled $config.RequireSecuritySignature `
            -RawValue $config.RequireSecuritySignature `
            -Detail "RequireSecuritySignature = $($config.RequireSecuritySignature)" `
            -Description 'Requires SMB signing for outbound SMB client sessions to reduce man-in-the-middle tampering and lateral movement risk.' `
            -Recommendation 'Require SMB client signing and validate compatibility with legacy file services.'
    } catch {
        Write-Warning "Could not query SMB client configuration: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'SMB Client Signing Required' `
            -Category 'Network' `
            -ML 'ML2' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query SMB client configuration' `
            -Description 'Requires SMB signing for outbound SMB client sessions to reduce man-in-the-middle tampering and lateral movement risk.' `
            -Recommendation 'Validate SMB client signing configuration through policy and client configuration.'
    }
}

# Checks whether Windows Firewall is enabled for each network profile.
function Get-FirewallProfileStatus {
    try {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            ConvertTo-E8AssessmentResult `
                -Check "Windows Firewall - $($_.Name) Profile" `
                -Category 'Firewall' `
                -ML 'ML1' `
                -Enabled ($_.Enabled -eq $true) `
                -RawValue $_.Enabled `
                -Detail "Enabled = $($_.Enabled)" `
                -Description 'Ensures host firewall filtering is enabled for the network profile.' `
                -Recommendation 'Enable Windows Firewall for this profile and manage allowed traffic through documented rules.'
        }
    } catch {
        Write-Warning "Could not query Windows Firewall profiles: $_"
        ConvertTo-E8AssessmentResult `
            -Check 'Windows Firewall' `
            -Category 'Firewall' `
            -ML 'ML1' `
            -Enabled $null `
            -RawValue $null `
            -Detail 'Unable to query Windows Firewall profiles' `
            -Description 'Ensures host firewall filtering is enabled for network profiles.' `
            -Recommendation 'Validate firewall profile state through policy and local firewall configuration.'
    }
}

# Checks whether Network Level Authentication is required for RDP connections.
function Get-RDPNLAStatus {
    $rdpDisabled = (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections

    if ($rdpDisabled -eq 1) {
        return ConvertTo-E8AssessmentResult `
            -Check 'RDP Network Level Authentication (NLA)' `
            -Category 'Remote Access' `
            -ML 'ML2' `
            -Enabled $null `
            -RawValue $rdpDisabled `
            -Detail 'RDP is disabled; check not applicable' `
            -Description 'Requires authentication before establishing a full Remote Desktop session.' `
            -Recommendation 'If RDP is later enabled, require Network Level Authentication.' `
            -AdditionalProperties @{ Note = 'RDP is disabled; check not applicable' }
    }

    $rdpTcp = Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
        -ErrorAction SilentlyContinue

    $nla = if ($null -ne $rdpTcp.UserAuthentication) {
        $rdpTcp.UserAuthentication
    } elseif ($null -ne $rdpTcp.UserAuthenticationEnabled) {
        $rdpTcp.UserAuthenticationEnabled
    } else {
        $null
    }

    ConvertTo-E8AssessmentResult `
        -Check 'RDP Network Level Authentication (NLA)' `
        -Category 'Remote Access' `
        -ML 'ML2' `
        -Enabled ($nla -eq 1) `
        -RawValue $nla `
        -Detail "UserAuthentication = $(ConvertTo-E8ValueText -Value $nla)" `
        -Description 'Requires authentication before establishing a full Remote Desktop session.' `
        -Recommendation 'Require NLA for RDP and restrict RDP exposure through administrative access controls and network segmentation.'
}

# Checks whether WDigest authentication is disabled.
function Get-WDigestStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
        -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential

    ConvertTo-E8AssessmentResult `
        -Check 'WDigest Plaintext Credential Caching Disabled' `
        -Category 'Credential Protection' `
        -ML 'ML2' `
        -Enabled ($val -ne 1) `
        -RawValue $val `
        -Detail "UseLogonCredential = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Prevents WDigest from caching plaintext credentials in LSASS memory.' `
        -Recommendation 'Ensure UseLogonCredential is absent or set to 0 unless a formally accepted legacy dependency exists.'
}

# Checks whether User Account Control is enabled.
function Get-UACStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA

    ConvertTo-E8AssessmentResult `
        -Check 'User Account Control (UAC) Enabled' `
        -Category 'System Security' `
        -ML 'ML1' `
        -Enabled ($val -eq 1) `
        -RawValue $val `
        -Detail "EnableLUA = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Requires elevation for privileged operations and reduces the impact of standard user compromise.' `
        -Recommendation 'Enable UAC and manage privileged access through least privilege administrative processes.'
}

# Checks whether Secure Boot is active on this host.
function Get-SecureBootStatus {
    try {
        $state = Confirm-SecureBootUEFI -ErrorAction Stop
        ConvertTo-E8AssessmentResult `
            -Check 'Secure Boot' `
            -Category 'System Security' `
            -ML 'ML2' `
            -Enabled $state `
            -RawValue $state `
            -Detail "Secure Boot enabled = $state" `
            -Description 'Validates boot components to reduce bootkit and early-start malware risk.' `
            -Recommendation 'Enable Secure Boot on UEFI-capable devices after validating firmware and OS compatibility.'
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
}

# Checks whether AutoRun is disabled for all drive types.
function Get-AutoRunStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun

    ConvertTo-E8AssessmentResult `
        -Check 'AutoRun Disabled (All Drives)' `
        -Category 'System Security' `
        -ML 'ML1' `
        -Enabled ($val -eq 0xFF) `
        -RawValue $val `
        -Detail "NoDriveTypeAutoRun = $(ConvertTo-E8ValueText -Value $val)" `
        -Description 'Prevents automatic execution of content from removable and other drive types.' `
        -Recommendation 'Set NoDriveTypeAutoRun to 255 through policy to disable AutoRun for all drive types.'
}
