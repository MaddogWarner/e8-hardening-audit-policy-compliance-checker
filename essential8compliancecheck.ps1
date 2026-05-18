#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Set-StrictMode -Version Latest

# ── Process & Memory Protection ───────────────────────────────────────────────

# Checks whether LSASS is configured to run as a Protected Process Light (PPL),
# preventing code injection and memory dumping by non-protected processes.
# RunAsPPL values 1 and 2 both indicate PPL is enabled; 2 is used on newer
# Windows builds where UEFI lock is not required.
function Get-LsaProtectionStatus {
    $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL

    [PSCustomObject]@{
        Check    = 'LSASS Protected Process Light (PPL)'
        Enabled  = ($val -in 1, 2)
        RawValue = $val
    }
}

# Checks whether Hypervisor-Protected Code Integrity (HVCI / Memory Integrity) is running.
# Skips and reports Supported = $false on builds that predate the feature:
# workstation Win 10 1709+ (build 16299), Server 2019+ (build 17763).
# Queries Win32_DeviceGuard for runtime state; falls back to registry configuration
# if the WMI class is unavailable.
function Get-MemoryIntegrityStatus {
    $os    = Get-CimInstance Win32_OperatingSystem
    $build = $os.BuildNumber -as [int]

    $minBuild = if ($os.ProductType -eq 1) { 16299 } else { 17763 }

    if ($build -lt $minBuild) {
        return [PSCustomObject]@{
            Check     = 'Memory Integrity / HVCI'
            Supported = $false
            Enabled   = $null
            RawValue  = $null
        }
    }

    $configuredValue = (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' `
        -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
            -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        # SecurityServicesRunning: 1 = Credential Guard running, 2 = HVCI running
        [PSCustomObject]@{
            Check      = 'Memory Integrity / HVCI'
            Supported  = $true
            Enabled    = ($dg.SecurityServicesRunning -contains 2)
            Configured = ($configuredValue -eq 1)
            RawValue   = $dg.SecurityServicesRunning
        }
    } catch {
        Write-Warning "Win32_DeviceGuard unavailable, falling back to registry configuration: $_"
        [PSCustomObject]@{
            Check      = 'Memory Integrity / HVCI'
            Supported  = $true
            Enabled    = ($configuredValue -eq 1)
            Configured = ($configuredValue -eq 1)
            Note       = 'Runtime state unavailable; reporting configured registry state'
            RawValue   = $configuredValue
        }
    }
}

# Checks whether Credential Guard is actively running via Virtualisation-Based Security,
# protecting domain credential hashes from extraction by tools such as Mimikatz.
# Queries Win32_DeviceGuard WMI; falls back to registry if the class is unavailable.
# Requires Win 10 1511+ (build 10586) or Server 2016+ (build 14393).
function Get-CredentialGuardStatus {
    $os    = Get-CimInstance Win32_OperatingSystem
    $build = $os.BuildNumber -as [int]

    $minBuild = if ($os.ProductType -eq 1) { 10586 } else { 14393 }

    if ($build -lt $minBuild) {
        return [PSCustomObject]@{
            Check     = 'Credential Guard'
            Supported = $false
            Enabled   = $null
            RawValue  = $null
        }
    }

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
            -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        # SecurityServicesRunning: 1 = Credential Guard running, 2 = HVCI running
        [PSCustomObject]@{
            Check     = 'Credential Guard'
            Supported = $true
            Enabled   = ($dg.SecurityServicesRunning -contains 1)
            RawValue  = $dg.SecurityServicesRunning
        }
    } catch {
        Write-Warning "Win32_DeviceGuard unavailable, falling back to registry: $_"
        $val = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
            -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue).LsaCfgFlags
        [PSCustomObject]@{
            Check     = 'Credential Guard'
            Supported = $true
            Enabled   = ($val -in 1, 2)
            Note      = 'Runtime state unavailable; reporting configured registry state'
            RawValue  = $val
        }
    }
}

# ── Audit Logging ─────────────────────────────────────────────────────────────

# Checks whether full command-line arguments are captured in process creation
# audit events (Event ID 4688), enabling visibility into executed commands.
function Get-ProcessCmdLineAuditStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled

    [PSCustomObject]@{
        Check    = 'Process Creation Command Line Logging'
        Enabled  = ($val -eq 1)
        RawValue = $val
    }
}

# ── PowerShell Hardening ──────────────────────────────────────────────────────

# Checks whether PowerShell Script Block Logging is enabled, recording the full
# content of all executed script blocks to the event log (Event ID 4104).
function Get-PSScriptBlockLoggingStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging

    [PSCustomObject]@{
        Check    = 'PowerShell Script Block Logging'
        Enabled  = ($val -eq 1)
        RawValue = $val
    }
}

# Checks whether PowerShell Module Logging is enabled, recording pipeline
# execution details for all PowerShell modules (Event ID 4103).
function Get-PSModuleLoggingStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging

    [PSCustomObject]@{
        Check    = 'PowerShell Module Logging'
        Enabled  = ($val -eq 1)
        RawValue = $val
    }
}

# Checks whether PowerShell Transcription is enabled, writing a full record
# of every PowerShell session to a text file on disk.
function Get-PSTranscriptionStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        -Name 'EnableTranscripting' -ErrorAction SilentlyContinue).EnableTranscripting

    [PSCustomObject]@{
        Check    = 'PowerShell Transcription'
        Enabled  = ($val -eq 1)
        RawValue = $val
    }
}

# Checks whether the legacy PowerShell v2 engine is disabled. PowerShell v2 lacks
# AMSI and Script Block Logging, and can be used to bypass those controls entirely.
# Uses DISM (Get-WindowsOptionalFeature) which works on both workstation and server.
function Get-PowerShellV2Status {
    try {
        $feature = Get-WindowsOptionalFeature -Online `
            -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop
        [PSCustomObject]@{
            Check    = 'PowerShell v2 Engine Disabled'
            Enabled  = ($feature.State -eq 'Disabled')
            RawValue = $feature.State
        }
    } catch {
        Write-Warning "Could not check PowerShell v2 feature status: $_"
        [PSCustomObject]@{
            Check    = 'PowerShell v2 Engine Disabled'
            Enabled  = $null
            RawValue = $null
        }
    }
}

# ── Windows Defender ──────────────────────────────────────────────────────────

# Checks whether Windows Defender real-time protection is active.
function Get-DefenderRealTimeStatus {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        [PSCustomObject]@{
            Check    = 'Defender Real-Time Protection'
            Enabled  = (-not $pref.DisableRealtimeMonitoring)
            RawValue = $pref.DisableRealtimeMonitoring
        }
    } catch {
        Write-Warning "Could not query Defender preferences: $_"
        [PSCustomObject]@{
            Check    = 'Defender Real-Time Protection'
            Enabled  = $null
            RawValue = $null
        }
    }
}

# Checks whether Defender cloud-delivered (MAPS) protection is enabled.
# MAPSReporting: 0 = disabled, 1 = basic, 2 = advanced. Compliant at 1 or above.
function Get-DefenderCloudProtectionStatus {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        [PSCustomObject]@{
            Check    = 'Defender Cloud-Delivered Protection'
            Enabled  = ($pref.MAPSReporting -ge 1)
            RawValue = $pref.MAPSReporting
        }
    } catch {
        Write-Warning "Could not query Defender preferences: $_"
        [PSCustomObject]@{
            Check    = 'Defender Cloud-Delivered Protection'
            Enabled  = $null
            RawValue = $null
        }
    }
}

# Checks whether Defender Tamper Protection is active, preventing unauthorised
# changes to Defender settings. Registry value 5 = enabled, 4 = disabled.
function Get-DefenderTamperProtectionStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' `
        -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection

    [PSCustomObject]@{
        Check    = 'Defender Tamper Protection'
        Enabled  = ($val -eq 5)
        RawValue = $val
    }
}

# ── Attack Surface Reduction ──────────────────────────────────────────────────

# Checks the configured action for each E8-relevant ASR rule via Get-MpPreference.
# Returns one result object per rule. Compliant state is Block (action = 1).
# GUIDs sourced from Microsoft Learn ASR rules reference (learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference).
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
        return
    }

    $ruleMap = @{}
    if ($pref.AttackSurfaceReductionRules_Ids) {
        for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            $ruleMap[$pref.AttackSurfaceReductionRules_Ids[$i].ToLower()] =
                $pref.AttackSurfaceReductionRules_Actions[$i]
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
        [PSCustomObject]@{
            Check       = "ASR: $($rules[$guid])"
            Enabled     = ($action -eq 1)
            ActionLabel = $actionLabel
            RuleGUID    = $guid
            RawValue    = $action
        }
    }
}

# ── Network Hardening ─────────────────────────────────────────────────────────

# Checks whether the legacy SMBv1 protocol is disabled, eliminating exposure
# to EternalBlue and related SMBv1 exploits.
function Get-SMBv1Status {
    try {
        $config = Get-SmbServerConfiguration -ErrorAction Stop
        [PSCustomObject]@{
            Check    = 'SMBv1 Disabled'
            Enabled  = (-not $config.EnableSMB1Protocol)
            RawValue = $config.EnableSMB1Protocol
        }
    } catch {
        Write-Warning "Could not query SMB server configuration: $_"
        [PSCustomObject]@{
            Check    = 'SMBv1 Disabled'
            Enabled  = $null
            RawValue = $null
        }
    }
}

# Checks whether SMB packet signing is required on the server, preventing
# man-in-the-middle tampering of SMB sessions.
function Get-SMBSigningStatus {
    try {
        $config = Get-SmbServerConfiguration -ErrorAction Stop
        [PSCustomObject]@{
            Check    = 'SMB Signing Required'
            Enabled  = $config.RequireSecuritySignature
            RawValue = $config.RequireSecuritySignature
        }
    } catch {
        Write-Warning "Could not query SMB server configuration: $_"
        [PSCustomObject]@{
            Check    = 'SMB Signing Required'
            Enabled  = $null
            RawValue = $null
        }
    }
}

# Checks whether the Windows Firewall is enabled for each network profile.
# Returns one result object per profile (Domain, Private, Public).
function Get-FirewallProfileStatus {
    try {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Check    = "Windows Firewall — $($_.Name) Profile"
                Enabled  = ($_.Enabled -eq $true)
                RawValue = $_.Enabled
            }
        }
    } catch {
        Write-Warning "Could not query Windows Firewall profiles: $_"
        [PSCustomObject]@{
            Check    = 'Windows Firewall'
            Enabled  = $null
            RawValue = $null
        }
    }
}

# ── Remote Access ─────────────────────────────────────────────────────────────

# Checks whether Network Level Authentication (NLA) is required for RDP connections,
# ensuring users authenticate before a full session is established.
# If RDP is disabled entirely, the check is skipped and marked not applicable.
function Get-RDPNLAStatus {
    $rdpDisabled = (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
        -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections

    if ($rdpDisabled -eq 1) {
        return [PSCustomObject]@{
            Check    = 'RDP Network Level Authentication (NLA)'
            Enabled  = $null
            Note     = 'RDP is disabled — check not applicable'
            RawValue = $null
        }
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

    [PSCustomObject]@{
        Check    = 'RDP Network Level Authentication (NLA)'
        Enabled  = ($nla -eq 1)
        RawValue = $nla
    }
}

# ── Credential Protection ─────────────────────────────────────────────────────

# Checks whether WDigest authentication is disabled, preventing Windows from
# caching plaintext credentials in LSASS memory.
# UseLogonCredential absent or 0 = compliant; 1 = credentials cached in plaintext.
function Get-WDigestStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
        -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential

    [PSCustomObject]@{
        Check    = 'WDigest Plaintext Credential Caching Disabled'
        Enabled  = ($val -ne 1)
        RawValue = $val
    }
}

# ── System Security ────────────────────────────────────────────────────────────

# Checks whether User Account Control (UAC) is enabled, requiring elevation
# prompts for operations that need administrative privileges.
function Get-UACStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA

    [PSCustomObject]@{
        Check    = 'User Account Control (UAC) Enabled'
        Enabled  = ($val -eq 1)
        RawValue = $val
    }
}

# Checks whether Secure Boot is active on this host.
# Reports Enabled = $false with a note on non-UEFI systems where the cmdlet is unavailable.
function Get-SecureBootStatus {
    try {
        $state = Confirm-SecureBootUEFI -ErrorAction Stop
        [PSCustomObject]@{
            Check    = 'Secure Boot'
            Enabled  = $state
            RawValue = $state
        }
    } catch {
        [PSCustomObject]@{
            Check    = 'Secure Boot'
            Enabled  = $false
            Note     = 'Cmdlet unavailable — system may not be UEFI-based'
            RawValue = $null
        }
    }
}

# Checks whether AutoRun is disabled for all drive types, preventing automatic
# execution of content from removable media. 0xFF (255) = all drive types disabled.
function Get-AutoRunStatus {
    $val = (Get-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
        -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun

    [PSCustomObject]@{
        Check    = 'AutoRun Disabled (All Drives)'
        Enabled  = ($val -eq 0xFF)
        RawValue = $val
    }
}

# ── Run All Checks ─────────────────────────────────────────────────────────────

$results = @(
    Get-LsaProtectionStatus
    Get-MemoryIntegrityStatus
    Get-CredentialGuardStatus
    Get-ProcessCmdLineAuditStatus
    Get-PSScriptBlockLoggingStatus
    Get-PSModuleLoggingStatus
    Get-PSTranscriptionStatus
    Get-PowerShellV2Status
    Get-DefenderRealTimeStatus
    Get-DefenderCloudProtectionStatus
    Get-DefenderTamperProtectionStatus
    Get-ASRRuleStatus
    Get-SMBv1Status
    Get-SMBSigningStatus
    Get-FirewallProfileStatus
    Get-RDPNLAStatus
    Get-WDigestStatus
    Get-UACStatus
    Get-SecureBootStatus
    Get-AutoRunStatus
)

$results | Format-List
