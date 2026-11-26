# Starts the app and checks that the window shows the core version from Cargo.toml.
# Run with Windows PowerShell 5.1, which loads UIAutomationClient without extra setup.
#   powershell windows/smoke.ps1 -Exe <path to LazyMail.exe> [-Seconds 30]
param(
    [Parameter(Mandatory)] [string] $Exe,
    [int] $Seconds = 30
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$cargo = Join-Path $PSScriptRoot '..\Cargo.toml'
$section = (Get-Content $cargo -Raw) -split '(?m)^\[workspace\.package\]' | Select-Object -Last 1
if ($section -notmatch '(?m)^version\s*=\s*"([^"]+)"') { throw 'no workspace version in Cargo.toml' }
$expected = $Matches[1]

function Find-Version([System.Diagnostics.Process] $process) {
    $process.Refresh()
    if ($process.MainWindowHandle -eq 0) { return $null }
    $window = [Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
    $condition = New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::AutomationIdProperty, 'CoreVersion')
    $window.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
}

$process = Start-Process $Exe -PassThru
try {
    $element = $null
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 500
        if ($process.HasExited) { throw "$Exe stopped with exit code $($process.ExitCode)" }
        $element = Find-Version $process
    } while (-not $element -and (Get-Date) -lt $deadline)
    if (-not $element) { throw "CoreVersion not found in $Seconds seconds; the window is '$($process.MainWindowTitle)'" }
    $found = $element.Current.Name
    Write-Host "window '$($process.MainWindowTitle)' shows core version '$found', Cargo.toml says '$expected'"
    if ($found -ne $expected) { throw 'core version mismatch' }
} finally {
    if (-not $process.HasExited) {
        [void]$process.CloseMainWindow()
        if (-not $process.WaitForExit(5000)) { $process.Kill(); $process.WaitForExit() }
    }
}
