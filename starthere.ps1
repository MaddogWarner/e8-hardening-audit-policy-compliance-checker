[CmdletBinding()]
param()

Set-StrictMode -Version Latest

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

function Start-AssessmentScript {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$AssessmentName
    )

    if (-not (Test-Path -Path $ScriptPath -PathType Leaf)) {
        [System.Windows.Forms.MessageBox]::Show(
            "The $AssessmentName script could not be found:`r`n$ScriptPath",
            'Script Not Found',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }

    $powerShellPath = (Get-Process -Id $PID).Path
    $argumentList = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-NoExit'
        '-File'
        "`"$ScriptPath`""
    )

    if ($PSCmdlet.ShouldProcess($ScriptPath, "Start the $AssessmentName assessment script")) {
        if (Test-IsAdministrator) {
            Start-Process -FilePath $powerShellPath -ArgumentList $argumentList
        } else {
            Start-Process -FilePath $powerShellPath -ArgumentList $argumentList -Verb RunAs
        }
    }
}

function Show-StartHereForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    [System.Windows.Forms.Application]::EnableVisualStyles()

    $scriptRoot = Split-Path -Parent $PSCommandPath
    $auditScriptPath = Join-Path -Path $scriptRoot -ChildPath 'essential8compliancecheck.ps1'
    $mdeExclusionsScriptPath = Join-Path -Path $scriptRoot -ChildPath 'mdeexclusionsassess.ps1'
    $readmePath = Join-Path -Path $scriptRoot -ChildPath 'README.md'

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Security Assessment Tool'
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(760, 460)
    $form.MinimumSize = New-Object System.Drawing.Size(700, 420)
    $form.MaximizeBox = $false

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = 'Essential Eight Hardening Assessment'
    $titleLabel.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
    $titleLabel.AutoSize = $true
    $titleLabel.Location = New-Object System.Drawing.Point(24, 22)

    $descriptionTextBox = New-Object System.Windows.Forms.TextBox
    $descriptionTextBox.Multiline = $true
    $descriptionTextBox.ReadOnly = $true
    $descriptionTextBox.ScrollBars = 'Vertical'
    $descriptionTextBox.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $descriptionTextBox.Location = New-Object System.Drawing.Point(28, 70)
    $descriptionTextBox.Size = New-Object System.Drawing.Size(690, 220)
    $descriptionTextBox.Anchor = 'Top,Left,Right,Bottom'
    $descriptionTextBox.Text = @"
This tool assesses ASD Essential Eight compliance for system and application hardening controls on supported Windows workstations and servers.

It is intended for enterprise and healthcare environments where auditability, access control, and evidence collection are important. The current assessment workflow launches the read-only compliance audit and reports hardening status without changing host configuration.

The MDE Exclusions button launches a read-only Microsoft Defender Antivirus exclusion assessment. It surfaces configured file, folder, and process exclusions from local and policy registry locations, then highlights obviously risky exclusions such as C:\Users, C:\Temp, or entire drive roots.

Future workflow areas will provide remediation guidance and controlled remediation actions for authorised administrators. Remediation actions should remain explicit, auditable, and reversible, with clear validation steps before and after change.
"@

    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = 'Running with administrator privileges.'
    $statusLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $statusLabel.AutoSize = $true
    $statusLabel.Location = New-Object System.Drawing.Point(28, 310)
    $statusLabel.Anchor = 'Left,Bottom'

    $runAuditButton = New-Object System.Windows.Forms.Button
    $runAuditButton.Text = 'Run Assessment'
    $runAuditButton.Size = New-Object System.Drawing.Size(140, 34)
    $runAuditButton.Location = New-Object System.Drawing.Point(28, 350)
    $runAuditButton.Anchor = 'Left,Bottom'
    $runAuditButton.Add_Click({
        Start-AssessmentScript -ScriptPath $auditScriptPath -AssessmentName 'Essential Eight'
    })

    $mdeExclusionsButton = New-Object System.Windows.Forms.Button
    $mdeExclusionsButton.Text = 'MDE Exclusions'
    $mdeExclusionsButton.Size = New-Object System.Drawing.Size(140, 34)
    $mdeExclusionsButton.Location = New-Object System.Drawing.Point(180, 350)
    $mdeExclusionsButton.Anchor = 'Left,Bottom'
    $mdeExclusionsButton.Add_Click({
        Start-AssessmentScript -ScriptPath $mdeExclusionsScriptPath -AssessmentName 'MDE Exclusions'
    })

    $guidanceButton = New-Object System.Windows.Forms.Button
    $guidanceButton.Text = 'Remediation Guidance'
    $guidanceButton.Size = New-Object System.Drawing.Size(160, 34)
    $guidanceButton.Location = New-Object System.Drawing.Point(332, 350)
    $guidanceButton.Anchor = 'Left,Bottom'
    $guidanceButton.Enabled = $false

    $remediateButton = New-Object System.Windows.Forms.Button
    $remediateButton.Text = 'Apply Remediation'
    $remediateButton.Size = New-Object System.Drawing.Size(150, 34)
    $remediateButton.Location = New-Object System.Drawing.Point(504, 350)
    $remediateButton.Anchor = 'Left,Bottom'
    $remediateButton.Enabled = $false

    $readmeButton = New-Object System.Windows.Forms.Button
    $readmeButton.Text = 'Open README'
    $readmeButton.Size = New-Object System.Drawing.Size(120, 34)
    $readmeButton.Location = New-Object System.Drawing.Point(28, 392)
    $readmeButton.Anchor = 'Left,Bottom'
    $readmeButton.Add_Click({
        if (Test-Path -Path $readmePath -PathType Leaf) {
            Start-Process -FilePath $readmePath
        }
    })

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.Size = New-Object System.Drawing.Size(90, 34)
    $closeButton.Location = New-Object System.Drawing.Point(628, 392)
    $closeButton.Anchor = 'Right,Bottom'
    $closeButton.Add_Click({
        $form.Close()
    })

    $toolTip = New-Object System.Windows.Forms.ToolTip
    $toolTip.SetToolTip($guidanceButton, 'Planned workflow: display assessed control gaps and administrator remediation steps.')
    $toolTip.SetToolTip($remediateButton, 'Planned workflow: perform explicit, auditable remediation after operator confirmation.')

    $form.Controls.AddRange(@(
        $titleLabel,
        $descriptionTextBox,
        $statusLabel,
        $runAuditButton,
        $mdeExclusionsButton,
        $guidanceButton,
        $remediateButton,
        $readmeButton,
        $closeButton
    ))

    [void]$form.ShowDialog()
}

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'starthere.ps1 requires Windows because it uses Windows Forms and elevation via RunAs.'
}

if (-not (Test-IsAdministrator)) {
    Start-ElevatedScript
    return
}

Show-StartHereForm
