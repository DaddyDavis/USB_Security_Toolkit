<#
.SYNOPSIS
    Downloads and prepares portable, standalone Python 3.12 for USB deployment.
#>

$DestDir = Join-Path $PSScriptRoot "python_embed"
$ZipPath = Join-Path $PSScriptRoot "python_embed.zip"
$Url = "https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip"

if (-not (Test-Path $DestDir)) {
    New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
}

Write-Host "[*] Downloading official Python 3.12 Embeddable package (11 MB)..." -ForegroundColor Cyan
curl.exe -L -o $ZipPath $Url

Write-Host "[*] Unpacking into $DestDir..." -ForegroundColor Cyan
Expand-Archive -Path $ZipPath -DestinationPath $DestDir -Force

Remove-Item $ZipPath -Force
Write-Host "[+] Portable Python ready at: $DestDir\python.exe" -ForegroundColor Green
