param(
    [string]$OpenClawCommand = "openclaw",
    [string]$ConfigPath = (Join-Path $HOME ".openclaw\openclaw.json"),
    [string]$WorkingDirectory = (Join-Path $PSScriptRoot ".."),
    [string[]]$InstallArguments = @("plugins", "install", "-l", ".")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ConfigHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

if (-not (Get-Command $OpenClawCommand -ErrorAction SilentlyContinue)) {
    Write-Error "OpenClaw command '$OpenClawCommand' was not found. Install OpenClaw first, then rerun this verification."
}

$resolvedWorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory).Path
$beforeHash = Get-ConfigHash -Path $ConfigPath
$beforeDisplay = if ($null -eq $beforeHash) { "<missing>" } else { $beforeHash }

Write-Host "OpenClaw config path: $ConfigPath"
Write-Host "Hash before install: $beforeDisplay"
Write-Host "Running: $OpenClawCommand $($InstallArguments -join ' ')"

Push-Location $resolvedWorkingDirectory
try {
    & $OpenClawCommand @InstallArguments
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

$afterHash = Get-ConfigHash -Path $ConfigPath
$afterDisplay = if ($null -eq $afterHash) { "<missing>" } else { $afterHash }

Write-Host "Hash after install:  $afterDisplay"

if ($beforeHash -ne $afterHash) {
    Write-Error @"
OpenClaw modified '$ConfigPath' during plugin installation.
Plugin installation must not rewrite openclaw.json.
Run explicit config commands separately, for example:
  openclaw config set plugins.entries.clawguard-monitor.enabled true
  openclaw config set plugins.entries.clawguard-monitor.config.apiKey <cg_...>
"@
}

Write-Host "Install integrity check passed: openclaw.json was unchanged."
