# -----------------------------------------------------------------------------
# Build & push the Trivy Image Scanner container to a private/public Docker
# registry. All sensitive values are passed in as parameters or env vars — no
# values are hard-coded, so this script is safe to commit.
#
# Usage (parameters):
#   .\scripts\push.ps1 -Registry registry.example.com `
#                      -Namespace team-name `
#                      -Image trivy-scan-app `
#                      -Version 1.0.0
#
# Usage (env vars):
#   $env:REGISTRY  = "registry.example.com"
#   $env:NAMESPACE = "team-name"
#   $env:IMAGE     = "trivy-scan-app"
#   $env:VERSION   = "1.0.0"
#   .\scripts\push.ps1
# -----------------------------------------------------------------------------

[CmdletBinding()]
param(
    [string]$Registry  = $env:REGISTRY,
    [string]$Namespace = $env:NAMESPACE,
    [string]$Image     = $env:IMAGE,
    [string]$Version   = $env:VERSION
)

$ErrorActionPreference = "Stop"

foreach ($p in 'Registry','Namespace','Image','Version') {
    if (-not (Get-Variable -Name $p -ValueOnly)) {
        Write-Error "Missing required parameter or env var: $p"
        exit 1
    }
}

# Strip any accidental scheme / trailing slash from the registry
$Registry = $Registry -replace '^https?://', '' -replace '/+$', ''

$Full = "$Registry/$Namespace/$Image"

Write-Host "==> Building $Full`:$Version  (also tagging :latest)" -ForegroundColor Cyan
docker build -t "$Full`:$Version" -t "$Full`:latest" .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> Pushing $Full`:$Version" -ForegroundColor Cyan
docker push "$Full`:$Version"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> Pushing $Full`:latest" -ForegroundColor Cyan
docker push "$Full`:latest"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "Done. Pull with:" -ForegroundColor Green
Write-Host "  docker pull $Full`:$Version"
Write-Host "  docker pull $Full`:latest"
