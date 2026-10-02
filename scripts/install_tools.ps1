<#
.SYNOPSIS
    Fetch the scanner binaries that ship no Python package into vendor/bin.

.DESCRIPTION
    Trivy and OSV-Scanner are Go binaries distributed as GitHub release assets.
    This script resolves the latest release for each, downloads the Windows
    amd64 asset and places the executable in vendor/bin, which the agent
    searches in addition to PATH.

    This is a PROVISIONING step and is the only part of the project that talks
    to the public internet. Scans themselves run fully offline.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/install_tools.ps1
#>
[CmdletBinding()]
param(
    [string]$VendorBin,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# $PSScriptRoot is not reliably bound inside a param() default under Windows
# PowerShell 5.1, so the default is resolved here instead.
if (-not $VendorBin) {
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
    $VendorBin = Join-Path $scriptDir "..\vendor\bin"
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# GitHub's API rejects requests without a User-Agent header.
$Headers = @{ "User-Agent" = "qa-agent-installer" }

function Resolve-ReleaseAsset {
    param(
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$Pattern
    )
    $uri = "https://api.github.com/repos/$Repo/releases/latest"
    Write-Host "  querying $Repo ..." -ForegroundColor DarkGray
    $release = Invoke-RestMethod -Uri $uri -Headers $Headers -TimeoutSec 60
    $asset = $release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No asset matching '$Pattern' in $Repo release $($release.tag_name)."
    }
    [pscustomobject]@{
        Version = $release.tag_name
        Name    = $asset.name
        Url     = $asset.browser_download_url
    }
}

function Install-Tool {
    param(
        [Parameter(Mandatory)][string]$Repo,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$ExeName
    )

    $target = Join-Path $VendorBin $ExeName
    if ((Test-Path $target) -and -not $Force) {
        Write-Host "  $ExeName already present, skipping (use -Force to reinstall)" -ForegroundColor Yellow
        return
    }

    $asset = Resolve-ReleaseAsset -Repo $Repo -Pattern $Pattern
    Write-Host "  downloading $($asset.Name) ($($asset.Version))" -ForegroundColor DarkGray

    $staging = Join-Path ([IO.Path]::GetTempPath()) ("qa-agent-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        $download = Join-Path $staging $asset.Name
        Invoke-WebRequest -Uri $asset.Url -OutFile $download -Headers $Headers -TimeoutSec 600

        if ($asset.Name -like "*.zip") {
            $extracted = Join-Path $staging "extracted"
            Expand-Archive -Path $download -DestinationPath $extracted -Force
            $exe = Get-ChildItem -Path $extracted -Filter $ExeName -Recurse | Select-Object -First 1
            if (-not $exe) { throw "$ExeName not found inside $($asset.Name)." }
            Copy-Item -Path $exe.FullName -Destination $target -Force
        }
        else {
            Copy-Item -Path $download -Destination $target -Force
        }

        Write-Host "  installed $ExeName $($asset.Version)" -ForegroundColor Green
    }
    finally {
        Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

New-Item -ItemType Directory -Path $VendorBin -Force | Out-Null
$VendorBin = (Resolve-Path $VendorBin).Path
Write-Host "Installing scanner binaries into $VendorBin" -ForegroundColor Cyan

Write-Host "`n[1/2] Trivy" -ForegroundColor Cyan
Install-Tool -Repo "aquasecurity/trivy" -Pattern "windows-64bit\.zip$" -ExeName "trivy.exe"

Write-Host "`n[2/2] OSV-Scanner" -ForegroundColor Cyan
Install-Tool -Repo "google/osv-scanner" -Pattern "windows_amd64\.exe$" -ExeName "osv-scanner.exe"

Write-Host "`nDone. Verify with: python -m qa_agent check_env" -ForegroundColor Cyan
