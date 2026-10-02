<#
.SYNOPSIS
    Export everything an air-gapped host needs into one folder.

.DESCRIPTION
    Run on a CONNECTED machine after `docker compose build` and after pulling
    the model into the compose Ollama volume. The resulting folder is copied to
    the offline host and loaded there with the commands printed at the end.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/export_bundle.ps1 -Output D:\qa-agent-bundle
#>
[CmdletBinding()]
param(
    [string]$Output = "qa-agent-bundle",
    [string]$Model = "qwen2.5-coder:3b"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$Output = (Resolve-Path $Output).Path

$images = @("qa-agent:0.1.0", "ollama/ollama:0.34.1", "zaproxy/zap-stable")
foreach ($image in $images) {
    docker image inspect $image *> $null
    if ($LASTEXITCODE -ne 0) { throw "Image $image is missing; build or pull it first." }
}

Write-Host "Saving container images (several GB)..." -ForegroundColor Cyan
docker save -o (Join-Path $Output "images.tar") @images
if ($LASTEXITCODE -ne 0) { throw "docker save failed" }

Write-Host "Saving the model volume..." -ForegroundColor Cyan
# The agent image is used for tar because it is in the bundle; a helper image
# such as alpine would not exist on the offline host.
docker run --rm --entrypoint tar -v qa-agent_ollama-models:/models -v "${Output}:/out" `
    qa-agent:0.1.0 -czf /out/ollama-models.tgz -C /models .
if ($LASTEXITCODE -ne 0) { throw "could not archive the model volume (did you pull $Model?)" }

Copy-Item docker-compose.yml $Output -Force

Write-Host "`nBundle ready in $Output" -ForegroundColor Green
Write-Host @"

On the air-gapped host:
  docker load -i images.tar
  docker volume create qa-agent_ollama-models
  docker run --rm --entrypoint tar -v qa-agent_ollama-models:/models -v `${PWD}:/in qa-agent:0.1.0 -xzf /in/ollama-models.tgz -C /models
  docker compose up        # no build: the image is already loaded
"@
