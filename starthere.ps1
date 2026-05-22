[CmdletBinding()]
param()

Set-StrictMode -Version Latest

$script:ToolVersion = '0.5.3'
$script:AssessmentResults = New-Object System.Collections.ArrayList
$script:AuditPolicyResults = New-Object System.Collections.ArrayList
$script:AuditPolCache = $null
$script:SystemInfo = $null

function Test-IsWindowsHost {
    return [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Start-ElevatedScript {
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
    )

    if ($PSCmdlet.ShouldProcess($PSCommandPath, 'Restart this script with administrator privileges')) {
        Start-Process -FilePath $powerShellPath -ArgumentList $argumentList -Verb RunAs
    }
}


function Get-SystemInfo {
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    } catch {
        throw "Unable to collect system information: $_"
    }

    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and $_.PrefixOrigin -ne 'WellKnown' } |
            Select-Object -First 1).IPAddress
    } catch {
        Write-Warning "Could not determine IPv4 address: $_"
        $ip = $null
    }

    try {
        $patch = Get-HotFix -ErrorAction Stop |
            Sort-Object InstalledOn -Descending |
            Select-Object -First 1 -ExpandProperty InstalledOn
    } catch {
        Write-Warning "Could not determine last installed patch: $_"
        $patch = $null
    }

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

function Get-E8CheckCommand {
    @(
        'Get-LsaProtectionStatus'
        'Get-MemoryIntegrityStatus'
        'Get-CredentialGuardStatus'
        'Get-ProcessCmdLineAuditStatus'
        'Get-PSScriptBlockLoggingStatus'
        'Get-PSModuleLoggingStatus'
        'Get-PSTranscriptionStatus'
        'Get-PowerShellV2Status'
        'Get-PSConstrainedLanguageModeStatus'
        'Get-PSExecutionPolicyStatus'
        'Get-DefenderRealTimeStatus'
        'Get-DefenderCloudProtectionStatus'
        'Get-DefenderTamperProtectionStatus'
        'Get-ASRRuleStatus'
        'Get-SMBv1Status'
        'Get-SMBSigningStatus'
        'Get-SMBClientSigningStatus'
        'Get-FirewallProfileStatus'
        'Get-RDPNLAStatus'
        'Get-WDigestStatus'
        'Get-UACStatus'
        'Get-SecureBootStatus'
        'Get-AutoRunStatus'
        'Get-BitLockerOSDriveStatus'
        'Get-BitLockerOSDriveProtectorStatus'
    )
}

function Get-AssessmentStatus {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Result
    )

    if ($Result.Category -eq 'MDE Exclusions') {
        if ($Result.Alert -eq $true) {
            return 'HIGH RISK'
        }

        if ($Result.ExclusionValue) {
            return 'REVIEW'
        }

        return 'N/A'
    }

    if ($Result.PSObject.Properties.Name -contains 'Supported' -and $Result.Supported -eq $false) {
        return 'NOT SUPPORTED'
    }

    if ($Result.PSObject.Properties.Name -contains 'ActionLabel') {
        if ($Result.ActionLabel -eq 'Audit') {
            return 'AUDIT'
        }

        if ($Result.ActionLabel -eq 'Warn') {
            return 'REVIEW'
        }
    }

    if ($Result.Enabled -eq $true) {
        return 'PASS'
    }

    if ($Result.Enabled -eq $false) {
        return 'FAIL'
    }

    return 'N/A'
}

function Get-RowColour {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    switch ($Status) {
        'PASS'          { return [System.Drawing.Color]::FromArgb(226, 246, 229) }
        'FAIL'          { return [System.Drawing.Color]::FromArgb(253, 226, 226) }
        'HIGH RISK'     { return [System.Drawing.Color]::FromArgb(253, 226, 226) }
        'AUDIT'         { return [System.Drawing.Color]::FromArgb(255, 243, 205) }
        'REVIEW'        { return [System.Drawing.Color]::FromArgb(255, 243, 205) }
        'N/A'           { return [System.Drawing.Color]::FromArgb(240, 240, 240) }
        'NOT SUPPORTED' { return [System.Drawing.Color]::White }
        default         { return [System.Drawing.Color]::White }
    }
}

function Add-AssessmentResultRow {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView,

        [Parameter(Mandatory = $true)]
        [psobject]$Result
    )

    $status = Get-AssessmentStatus -Result $Result
    $ml = if ($Result.ML) { $Result.ML } else { '-' }
    $detail = if ($Result.PSObject.Properties.Name -contains 'Detail' -and $Result.Detail) { $Result.Detail } else { '' }

    $item = New-Object System.Windows.Forms.ListViewItem($Result.Category)
    [void]$item.SubItems.Add($Result.Check)
    [void]$item.SubItems.Add($ml)
    [void]$item.SubItems.Add($status)
    [void]$item.SubItems.Add($detail)
    $item.BackColor = Get-RowColour -Status $status
    $item.Tag = $Result

    [void]$ListView.Items.Add($item)
    [void]$script:AssessmentResults.Add($Result)
}

function Show-SystemInfoPanel {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Labels,

        [Parameter(Mandatory = $true)]
        [psobject]$Info
    )

    $Labels.Hostname.Text = "Hostname: $($Info.Hostname)"
    $Labels.IP.Text = "IP: $($Info.IPAddress)"
    $Labels.User.Text = "User: $($Info.LoggedInUser)"
    $Labels.OS.Text = "OS: $($Info.OSName)"
    $Labels.Build.Text = "Build: $($Info.OSBuild)"
    $Labels.Domain.Text = "Domain: $($Info.Domain)"
    $Labels.Patch.Text = "Patch: $($Info.LastPatch)"
}

function Show-DetailPanel {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.ListView]$ListView,

        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Label]$DetailTitle,

        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.Label]$DetailBody
    )

    if ($ListView.SelectedItems.Count -eq 0) {
        $DetailTitle.Text = 'Select a result to view details'
        $DetailBody.Text = 'The selected check description, maturity level, and recommendation will appear here.'
        return
    }

    $result = $ListView.SelectedItems[0].Tag
    $ml = if ($result.ML) { $result.ML } else { 'No ASD maturity level mapping' }
    $recommendation = if ($result.PSObject.Properties.Name -contains 'Recommendation') { $result.Recommendation } else { 'Review this finding against local policy.' }
    $description = if ($result.PSObject.Properties.Name -contains 'Description') { $result.Description } else { '' }

    $DetailTitle.Text = $result.Check
    $DetailBody.Text = "$description`r`nASD Reference: $ml - $($result.Category)`r`nRecommendation: $recommendation"
}

function ConvertTo-MarkdownSafeText {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return ([string]$Value).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
}

function Get-ReportTimestamp {
    try {
        $aetTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById('AUS Eastern Standard Time')
        $now = [System.TimeZoneInfo]::ConvertTimeFromUtc([DateTime]::UtcNow, $aetTimeZone)
        $zoneLabel = if ($aetTimeZone.IsDaylightSavingTime($now)) { 'AEDT' } else { 'AEST' }

        return "$($now.ToString('dd/MM/yyyy HH:mm')) $zoneLabel"
    } catch {
        $now = Get-Date
        return $now.ToString('dd/MM/yyyy HH:mm zzz')
    }
}

function Get-MarkdownReport {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$SystemInfo,

        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [object[]]$AuditPolicyResults = @()
    )

    $e8Results = @($Results | Where-Object { $_.Category -ne 'MDE Exclusions' -and $_.PSObject.Properties.Name -notcontains 'RequiredSetting' })
    $mdeResults = @($Results | Where-Object { $_.Category -eq 'MDE Exclusions' -and $_.ExclusionValue })
    $auditResults = @($AuditPolicyResults)
    $summaryResults = @($e8Results + $mdeResults + $auditResults)
    $totalChecks = $summaryResults.Count
    $passCount = @($e8Results | Where-Object { (Get-AssessmentStatus -Result $_) -eq 'PASS' }).Count
    $failCount = @($e8Results | Where-Object { (Get-AssessmentStatus -Result $_) -eq 'FAIL' }).Count
    $auditPassCount = @($auditResults | Where-Object { (Get-AssessmentStatus -Result $_) -eq 'PASS' }).Count
    $auditFailCount = @($auditResults | Where-Object { (Get-AssessmentStatus -Result $_) -eq 'FAIL' }).Count
    $naCount = @($summaryResults | Where-Object { (Get-AssessmentStatus -Result $_) -eq 'N/A' }).Count
    $notSupportedCount = @($summaryResults | Where-Object { (Get-AssessmentStatus -Result $_) -eq 'NOT SUPPORTED' }).Count
    $reviewCount = @($summaryResults | Where-Object { (Get-AssessmentStatus -Result $_) -in @('AUDIT', 'REVIEW', 'HIGH RISK') }).Count
    $nonCompliant = @($e8Results + $mdeResults | Where-Object { (Get-AssessmentStatus -Result $_) -in @('FAIL', 'AUDIT', 'REVIEW', 'HIGH RISK') })

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.AppendLine("# ASD Essential Eight $([char]0x2014) Hardening Compliance Report")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine("**Generated:** $(Get-ReportTimestamp)")
    [void]$builder.AppendLine("**Tool Version:** $script:ToolVersion")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('---')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## System Information')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('| Field | Value |')
    [void]$builder.AppendLine('|---|---|')
    [void]$builder.AppendLine("| Hostname | $(ConvertTo-MarkdownSafeText $SystemInfo.Hostname) |")
    [void]$builder.AppendLine("| IP Address | $(ConvertTo-MarkdownSafeText $SystemInfo.IPAddress) |")
    [void]$builder.AppendLine("| Logged-in User | $(ConvertTo-MarkdownSafeText $SystemInfo.LoggedInUser) |")
    [void]$builder.AppendLine("| Domain Joined | $(if ($SystemInfo.DomainJoined) { "Yes - $(ConvertTo-MarkdownSafeText $SystemInfo.Domain)" } else { 'No - Workgroup' }) |")
    [void]$builder.AppendLine("| Operating System | $(ConvertTo-MarkdownSafeText $SystemInfo.OSName) |")
    [void]$builder.AppendLine("| OS Build | $(ConvertTo-MarkdownSafeText $SystemInfo.OSBuild) |")
    [void]$builder.AppendLine("| Last Patch Installed | $(ConvertTo-MarkdownSafeText $SystemInfo.LastPatch) |")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('---')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## Executive Summary')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('| | Count |')
    [void]$builder.AppendLine('|---|---|')
    [void]$builder.AppendLine("| Total Checks | $totalChecks |")
    [void]$builder.AppendLine("| Pass | $($passCount + $auditPassCount) |")
    [void]$builder.AppendLine("| Fail | $($failCount + $auditFailCount) |")
    [void]$builder.AppendLine("| Review / Audit / High Risk | $reviewCount |")
    [void]$builder.AppendLine("| Not Applicable | $naCount |")
    [void]$builder.AppendLine("| Not Supported | $notSupportedCount |")
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('---')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## Results by Maturity Level')

    foreach ($level in @('ML1', 'ML2', 'ML3')) {
        $levelResults = @($e8Results | Where-Object { $_.ML -eq $level })
        if ($levelResults.Count -eq 0) {
            continue
        }

        [void]$builder.AppendLine()
        [void]$builder.AppendLine("### $level")
        [void]$builder.AppendLine('| Category | Check | Status | Detail |')
        [void]$builder.AppendLine('|---|---|---|---|')

        foreach ($result in $levelResults) {
            [void]$builder.AppendLine("| $(ConvertTo-MarkdownSafeText $result.Category) | $(ConvertTo-MarkdownSafeText $result.Check) | $(Get-AssessmentStatus -Result $result) | $(ConvertTo-MarkdownSafeText $result.Detail) |")
        }
    }

    [void]$builder.AppendLine()
    [void]$builder.AppendLine('---')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## MDE Exclusion Assessment')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('| Source | Type | Value | Risk | Reason |')
    [void]$builder.AppendLine('|---|---|---|---|---|')

    if ($mdeResults.Count -eq 0) {
        [void]$builder.AppendLine('| - | - | No exclusions surfaced | - | Run the MDE Exclusions assessment to populate this section |')
    } else {
        foreach ($result in $mdeResults) {
            [void]$builder.AppendLine("| $(ConvertTo-MarkdownSafeText $result.Source) | $(ConvertTo-MarkdownSafeText $result.ExclusionType) | $(ConvertTo-MarkdownSafeText $result.ExclusionValue) | $(Get-AssessmentStatus -Result $result) | $(ConvertTo-MarkdownSafeText $result.Reason) |")
        }
    }

    if ($auditResults.Count -gt 0) {
        [void]$builder.AppendLine()
        [void]$builder.AppendLine('---')
        [void]$builder.AppendLine()
        [void]$builder.AppendLine('## ASD Audit Policy Assessment')
        [void]$builder.AppendLine()
        [void]$builder.AppendLine('*Based on ASD "Windows Event Logging and Forwarding" guidance.*')
        [void]$builder.AppendLine()
        [void]$builder.AppendLine('| Category | Check | ML | Status | Current Setting | Required Setting |')
        [void]$builder.AppendLine('|---|---|---|---|---|---|')

        foreach ($result in $auditResults) {
            $ml = if ($result.ML) { $result.ML } else { '-' }
            [void]$builder.AppendLine("| $(ConvertTo-MarkdownSafeText $result.Category) | $(ConvertTo-MarkdownSafeText $result.Check) | $(ConvertTo-MarkdownSafeText $ml) | $(Get-AssessmentStatus -Result $result) | $(ConvertTo-MarkdownSafeText $result.Detail) | $(ConvertTo-MarkdownSafeText $result.RequiredSetting) |")
        }

        $nonCompliantAudit = @($auditResults | Where-Object { (Get-AssessmentStatus -Result $_) -in @('FAIL', 'REVIEW') })

        [void]$builder.AppendLine()
        [void]$builder.AppendLine('---')
        [void]$builder.AppendLine()
        [void]$builder.AppendLine('## Non-Compliant Audit Policy Controls')
        [void]$builder.AppendLine()
        [void]$builder.AppendLine('| Check | ML | Current Setting | Required Setting | Recommendation |')
        [void]$builder.AppendLine('|---|---|---|---|---|')

        if ($nonCompliantAudit.Count -eq 0) {
            [void]$builder.AppendLine('| - | - | No non-compliant audit policy findings captured | - | - |')
        } else {
            foreach ($result in $nonCompliantAudit) {
                $ml = if ($result.ML) { $result.ML } else { '-' }
                [void]$builder.AppendLine("| $(ConvertTo-MarkdownSafeText $result.Check) | $(ConvertTo-MarkdownSafeText $ml) | $(ConvertTo-MarkdownSafeText $result.Detail) | $(ConvertTo-MarkdownSafeText $result.RequiredSetting) | $(ConvertTo-MarkdownSafeText $result.Recommendation) |")
            }
        }
    }

    [void]$builder.AppendLine()
    [void]$builder.AppendLine('---')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('## Non-Compliant Controls')
    [void]$builder.AppendLine()
    [void]$builder.AppendLine('| Check | ML | Detail | Recommendation |')
    [void]$builder.AppendLine('|---|---|---|---|')

    if ($nonCompliant.Count -eq 0) {
        [void]$builder.AppendLine('| - | - | No non-compliant or review findings captured | - |')
    } else {
        foreach ($result in $nonCompliant) {
            $ml = if ($result.ML) { $result.ML } else { '-' }
            [void]$builder.AppendLine("| $(ConvertTo-MarkdownSafeText $result.Check) | $(ConvertTo-MarkdownSafeText $ml) | $(ConvertTo-MarkdownSafeText $result.Detail) | $(ConvertTo-MarkdownSafeText $result.Recommendation) |")
        }
    }

    [void]$builder.AppendLine()
    [void]$builder.AppendLine('*This report was generated by the ASD Essential Eight Hardening Compliance Tool.*')
    [void]$builder.AppendLine('*All findings are read-only observations. No changes were made to this system.*')

    return $builder.ToString()
}

function Save-MarkdownReport {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$SystemInfo,

        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [object[]]$AuditPolicyResults = @()
    )

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $date = Get-Date -Format 'yyyyMMdd'
    $hostname = if ($SystemInfo.Hostname) { $SystemInfo.Hostname } else { 'UnknownHost' }
    $dialog.FileName = "E8-Report-$hostname-$date.md"
    $dialog.Filter = 'Markdown files (*.md)|*.md|All files (*.*)|*.*'
    $dialog.Title = 'Save Assessment Report'

    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return $false
    }

    $report = Get-MarkdownReport -SystemInfo $SystemInfo -Results $Results -AuditPolicyResults $AuditPolicyResults
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($dialog.FileName, $report, $encoding)
    return $true
}

function Show-StartHereForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "ASD Essential Eight $([char]0x2014) Hardening Compliance Tool"
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(980, 680)
    $form.MinimumSize = New-Object System.Drawing.Size(880, 580)
    $form.MaximizeBox = $false

    $headerPanel = New-Object System.Windows.Forms.Panel
    $headerPanel.BackColor = [System.Drawing.Color]::FromArgb(242, 244, 247)
    $headerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $headerPanel.Size = New-Object System.Drawing.Size(980, 60)
    $headerPanel.Anchor = 'Top,Left,Right'

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "ASD Essential Eight $([char]0x2014) Hardening Compliance"
    $titleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object System.Drawing.Point(18, 10)

    $subtitleLabel = New-Object System.Windows.Forms.Label
    $subtitleLabel.Text = "ASD E8 Hardening  $([char]0x00B7)  MDE Exclusions  $([char]0x00B7)  Audit Policy  $([char]0x00B7)  Audit-only  $([char]0x00B7)  No system changes"
    $subtitleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $subtitleLabel.ForeColor = [System.Drawing.Color]::DimGray
    $subtitleLabel.AutoSize = $true
    $subtitleLabel.Location = New-Object System.Drawing.Point(21, 37)

    $headerPanel.Controls.AddRange(@($titleLabel, $subtitleLabel))

    $systemPanel = New-Object System.Windows.Forms.Panel
    $systemPanel.BackColor = [System.Drawing.Color]::White
    $systemPanel.BorderStyle = 'FixedSingle'
    $systemPanel.Location = New-Object System.Drawing.Point(14, 72)
    $systemPanel.Size = New-Object System.Drawing.Size(936, 95)
    $systemPanel.Anchor = 'Top,Left,Right'

    $systemLabels = @{
        Hostname = New-Object System.Windows.Forms.Label
        IP       = New-Object System.Windows.Forms.Label
        User     = New-Object System.Windows.Forms.Label
        OS       = New-Object System.Windows.Forms.Label
        Build    = New-Object System.Windows.Forms.Label
        Domain   = New-Object System.Windows.Forms.Label
        Patch    = New-Object System.Windows.Forms.Label
    }

    $labelFont = New-Object System.Drawing.Font('Segoe UI', 9)
    $labelColour = [System.Drawing.Color]::DimGray
    $positions = @{
        Hostname = New-Object System.Drawing.Point(14, 16)
        IP       = New-Object System.Drawing.Point(250, 16)
        User     = New-Object System.Drawing.Point(475, 16)
        OS       = New-Object System.Drawing.Point(14, 52)
        Build    = New-Object System.Drawing.Point(360, 52)
        Domain   = New-Object System.Drawing.Point(475, 52)
        Patch    = New-Object System.Drawing.Point(710, 52)
    }

    foreach ($key in $systemLabels.Keys) {
        $systemLabels[$key].Text = "$key`: Pending scan"
        $systemLabels[$key].Font = $labelFont
        $systemLabels[$key].ForeColor = $labelColour
        $systemLabels[$key].AutoSize = $true
        $systemLabels[$key].Location = $positions[$key]
        $systemPanel.Controls.Add($systemLabels[$key])
    }

    $resultsListView = New-Object System.Windows.Forms.ListView
    $resultsListView.View = 'Details'
    $resultsListView.FullRowSelect = $true
    $resultsListView.GridLines = $true
    $resultsListView.HideSelection = $false
    $resultsListView.Location = New-Object System.Drawing.Point(14, 181)
    $resultsListView.Size = New-Object System.Drawing.Size(936, 260)
    $resultsListView.Anchor = 'Top,Bottom,Left,Right'
    [void]$resultsListView.Columns.Add('Category', 120)
    [void]$resultsListView.Columns.Add('Check', 240)
    [void]$resultsListView.Columns.Add('ML', 45)
    [void]$resultsListView.Columns.Add('Status', 90)
    [void]$resultsListView.Columns.Add('Details', 420)

    $detailPanel = New-Object System.Windows.Forms.Panel
    $detailPanel.BackColor = [System.Drawing.Color]::White
    $detailPanel.BorderStyle = 'FixedSingle'
    $detailPanel.Location = New-Object System.Drawing.Point(14, 450)
    $detailPanel.Size = New-Object System.Drawing.Size(936, 86)
    $detailPanel.Anchor = 'Bottom,Left,Right'

    $detailTitle = New-Object System.Windows.Forms.Label
    $detailTitle.Text = 'Select a result to view details'
    $detailTitle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $detailTitle.AutoSize = $true
    $detailTitle.Location = New-Object System.Drawing.Point(12, 10)

    $detailBody = New-Object System.Windows.Forms.Label
    $detailBody.Text = 'The selected check description, maturity level, and recommendation will appear here.'
    $detailBody.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $detailBody.Location = New-Object System.Drawing.Point(12, 33)
    $detailBody.Size = New-Object System.Drawing.Size(905, 45)
    $detailBody.Anchor = 'Top,Left,Right'

    $detailPanel.Controls.AddRange(@($detailTitle, $detailBody))
    $resultsListView.Add_SelectedIndexChanged({
        Show-DetailPanel -ListView $resultsListView -DetailTitle $detailTitle -DetailBody $detailBody
    })

    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(14, 546)
    $progressBar.Size = New-Object System.Drawing.Size(936, 20)
    $progressBar.Anchor = 'Bottom,Left,Right'
    $progressBar.Visible = $false
    $progressBar.Minimum = 0
    $progressBar.Maximum = 50

    $statusStrip = New-Object System.Windows.Forms.StatusStrip
    $statusStrip.SizingGrip = $false
    $statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $statusLabel.Text = 'Ready'
    $statusLabel.Spring = $true
    $statusLabel.TextAlign = 'MiddleLeft'
    $adminLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
    $adminLabel.Text = if (Test-IsAdministrator) { 'Administrator: Yes' } else { 'Administrator: No' }
    [void]$statusStrip.Items.Add($statusLabel)
    [void]$statusStrip.Items.Add($adminLabel)

    $buttonPanel = New-Object System.Windows.Forms.Panel
    $buttonPanel.Location = New-Object System.Drawing.Point(14, 572)
    $buttonPanel.Size = New-Object System.Drawing.Size(936, 38)
    $buttonPanel.Anchor = 'Bottom,Left,Right'

    $runScanButton = New-Object System.Windows.Forms.Button
    $runScanButton.Text = 'Run E8 Scan'
    $runScanButton.Size = New-Object System.Drawing.Size(130, 32)
    $runScanButton.Location = New-Object System.Drawing.Point(0, 2)

    $mdeButton = New-Object System.Windows.Forms.Button
    $mdeButton.Text = 'MDE Exclusions List'
    $mdeButton.Size = New-Object System.Drawing.Size(165, 32)
    $mdeButton.Location = New-Object System.Drawing.Point(140, 2)

    $auditPolicyButton = New-Object System.Windows.Forms.Button
    $auditPolicyButton.Text = 'Audit Policy'
    $auditPolicyButton.Size = New-Object System.Drawing.Size(115, 32)
    $auditPolicyButton.Location = New-Object System.Drawing.Point(315, 2)

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = 'Save Report'
    $saveButton.Size = New-Object System.Drawing.Size(110, 32)
    $saveButton.Location = New-Object System.Drawing.Point(440, 2)
    $saveButton.Enabled = $false

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.Size = New-Object System.Drawing.Size(90, 32)
    $closeButton.Location = New-Object System.Drawing.Point(846, 2)
    $closeButton.Anchor = 'Top,Right'
    $closeButton.Add_Click({ $form.Close() })

    $buttonPanel.Controls.AddRange(@($runScanButton, $mdeButton, $auditPolicyButton, $saveButton, $closeButton))

    $runScanButton.Add_Click({
        try {
            $runScanButton.Enabled = $false
            $mdeButton.Enabled = $false
            $auditPolicyButton.Enabled = $false
            $saveButton.Enabled = $false
            $statusLabel.Text = 'Scanning Essential Eight hardening controls...'
            $progressBar.Visible = $true
            $progressBar.Value = 0
            $progressBar.Maximum = 50
            $resultsListView.Items.Clear()
            [void]$script:AssessmentResults.Clear()

            $script:SystemInfo = Get-SystemInfo
            Show-SystemInfoPanel -Labels $systemLabels -Info $script:SystemInfo

            foreach ($command in Get-E8CheckCommand) {
                $results = @(& $command)
                foreach ($result in $results) {
                    Add-AssessmentResultRow -ListView $resultsListView -Result $result
                    if ($progressBar.Value -lt $progressBar.Maximum) {
                        $progressBar.Value++
                    }
                    [System.Windows.Forms.Application]::DoEvents()
                }
            }

            $progressBar.Value = $progressBar.Maximum

            $passes = @($script:AssessmentResults | Where-Object { (Get-AssessmentStatus -Result $_) -eq 'PASS' }).Count
            $total = @($script:AssessmentResults | Where-Object { $_.Category -ne 'MDE Exclusions' }).Count
            $statusLabel.Text = "$passes of $total Essential Eight checks passed"
            $saveButton.Enabled = ($script:AssessmentResults.Count -gt 0)
        } catch {
            $statusLabel.Text = 'Scan failed'
            [System.Windows.Forms.MessageBox]::Show(
                "The scan failed:`r`n$_",
                'Scan Failed',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        } finally {
            $runScanButton.Enabled = $true
            $mdeButton.Enabled = $true
            $auditPolicyButton.Enabled = $true
            $saveButton.Enabled = ($script:AssessmentResults.Count -gt 0 -or $script:AuditPolicyResults.Count -gt 0)
            $progressBar.Visible = $false
        }
    })

    $mdeButton.Add_Click({
        try {
            $mdeButton.Enabled = $false
            $runScanButton.Enabled = $false
            $auditPolicyButton.Enabled = $false
            $saveButton.Enabled = $false
            $statusLabel.Text = 'Scanning Microsoft Defender Antivirus exclusions...'
            $progressBar.Visible = $true
            $progressBar.Value = 0
            $progressBar.Maximum = 4

            if (-not $script:SystemInfo) {
                $script:SystemInfo = Get-SystemInfo
                Show-SystemInfoPanel -Labels $systemLabels -Info $script:SystemInfo
            }

            $existingMdeItems = @($resultsListView.Items | Where-Object { $_.Tag.Category -eq 'MDE Exclusions' })
            foreach ($item in $existingMdeItems) {
                $resultsListView.Items.Remove($item)
            }
            $script:AssessmentResults = New-Object System.Collections.ArrayList
            foreach ($item in $resultsListView.Items) {
                [void]$script:AssessmentResults.Add($item.Tag)
            }

            $mdeResults = @(Get-MdeExclusionAssessment)
            $displayResults = @($mdeResults | Where-Object { $_.ExclusionValue })
            $progressBar.Maximum = [Math]::Max(1, $displayResults.Count)

            foreach ($result in $displayResults) {
                Add-AssessmentResultRow -ListView $resultsListView -Result $result
                if ($progressBar.Value -lt $progressBar.Maximum) {
                    $progressBar.Value++
                }
                [System.Windows.Forms.Application]::DoEvents()
            }

            if ($displayResults.Count -eq 0) {
                $progressBar.Value = $progressBar.Maximum
            }

            $highRisk = @($script:AssessmentResults | Where-Object { $_.Category -eq 'MDE Exclusions' -and $_.Alert -eq $true }).Count
            if ($displayResults.Count -eq 0) {
                $statusLabel.Text = 'MDE exclusion assessment complete; no exclusions found at configured registry locations'
            } else {
                $statusLabel.Text = "MDE exclusion assessment complete; exclusions found: $($displayResults.Count); high-risk exclusions: $highRisk"
            }
            $saveButton.Enabled = ($script:AssessmentResults.Count -gt 0)
        } catch {
            $statusLabel.Text = 'MDE exclusion assessment failed'
            [System.Windows.Forms.MessageBox]::Show(
                "The MDE exclusion assessment failed:`r`n$_",
                'MDE Assessment Failed',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        } finally {
            $mdeButton.Enabled = $true
            $runScanButton.Enabled = $true
            $auditPolicyButton.Enabled = $true
            $saveButton.Enabled = ($script:AssessmentResults.Count -gt 0 -or $script:AuditPolicyResults.Count -gt 0)
            $progressBar.Visible = $false
        }
    })

    $auditPolicyButton.Add_Click({
        try {
            $runScanButton.Enabled = $false
            $mdeButton.Enabled = $false
            $auditPolicyButton.Enabled = $false
            $saveButton.Enabled = $false
            $script:AuditPolCache = $null
            [void]$script:AuditPolicyResults.Clear()

            $existingAuditItems = @($resultsListView.Items | Where-Object {
                $_.Tag -and $_.Tag.PSObject.Properties.Name -contains 'RequiredSetting'
            })
            foreach ($item in $existingAuditItems) {
                $resultsListView.Items.Remove($item)
            }
            $script:AssessmentResults = New-Object System.Collections.ArrayList
            foreach ($item in $resultsListView.Items) {
                [void]$script:AssessmentResults.Add($item.Tag)
            }

            if (-not $script:SystemInfo) {
                $script:SystemInfo = Get-SystemInfo
                Show-SystemInfoPanel -Labels $systemLabels -Info $script:SystemInfo
            }

            $commands = @(Get-AuditPolicyCheckCommands)
            $progressBar.Visible = $true
            $progressBar.Value = 0
            $progressBar.Maximum = [Math]::Max(1, $commands.Count)
            $statusLabel.Text = 'Running audit policy checks...'
            [System.Windows.Forms.Application]::DoEvents()

            foreach ($command in $commands) {
                $results = @(& $command)
                foreach ($result in $results) {
                    Add-AssessmentResultRow -ListView $resultsListView -Result $result
                    [void]$script:AuditPolicyResults.Add($result)
                }

                $progressBar.Value = [Math]::Min($progressBar.Value + 1, $progressBar.Maximum)
                [System.Windows.Forms.Application]::DoEvents()
            }

            $passed = @($script:AuditPolicyResults | Where-Object {
                $_.Enabled -eq $true -or ($_.PSObject.Properties.Name -contains 'Supported' -and $_.Supported -eq $false)
            }).Count
            $total = $script:AuditPolicyResults.Count
            $statusLabel.Text = "Audit policy check complete - $passed of $total checks passed"
            $saveButton.Enabled = ($script:AssessmentResults.Count -gt 0 -or $script:AuditPolicyResults.Count -gt 0)
        } catch {
            Write-Warning "Audit policy assessment failed: $_"
            $statusLabel.Text = "Audit policy assessment failed: $_"
        } finally {
            $runScanButton.Enabled = $true
            $mdeButton.Enabled = $true
            $auditPolicyButton.Enabled = $true
            $saveButton.Enabled = ($script:AssessmentResults.Count -gt 0 -or $script:AuditPolicyResults.Count -gt 0)
            $progressBar.Visible = $false
        }
    })

    $saveButton.Add_Click({
        if (-not $script:SystemInfo) {
            [System.Windows.Forms.MessageBox]::Show(
                'Run a scan before saving a report.',
                'No Report Data',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }

        if (Save-MarkdownReport -SystemInfo $script:SystemInfo -Results @($script:AssessmentResults) -AuditPolicyResults @($script:AuditPolicyResults)) {
            $statusLabel.Text = 'Report saved'
        }
    })

    $form.Controls.AddRange(@(
        $headerPanel,
        $systemPanel,
        $resultsListView,
        $detailPanel,
        $progressBar,
        $buttonPanel,
        $statusStrip
    ))

    [void]$form.ShowDialog()
}

if (-not (Test-IsWindowsHost)) {
    throw 'starthere.ps1 requires Windows because it uses Windows Forms, Windows registry providers, and Windows security APIs.'
}

if (-not (Test-IsAdministrator)) {
    Start-ElevatedScript
    return
}

$scriptRoot = Split-Path -Parent $PSCommandPath
foreach ($library in @('essential8compliancecheck.ps1', 'mdeexclusionsassess.ps1', 'auditpolicyassess.ps1')) {
    $libraryPath = Join-Path -Path $scriptRoot -ChildPath $library
    if (-not (Test-Path -Path $libraryPath -PathType Leaf)) {
        throw "Required assessment library not found: $libraryPath"
    }
    . $libraryPath
}
Show-StartHereForm
