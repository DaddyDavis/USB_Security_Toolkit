<#
.SYNOPSIS
    Downloads and prepares portable, standalone Python 3.12 for USB deployment.
#>

$DestDir = Join-Path $PSScriptRoot "python_embed"
$ZipPath = Join-Path $PSScriptRoot "python_embed.zip"
$Url = "https://www.python.org/ftp/python/3.12.8/python-3.12.8-embed-amd64.zip"
$ExpectedSha256 = "8d3f33be9eb810f23c102f08475af2854e50484b8e4e06275e937be61ce3d2fb"

if (-not (Test-Path $DestDir)) {
    New-Item -ItemType Directory -Path $DestDir -Force | Out-Null
}

Write-Host "[*] Downloading official Python 3.12 Embeddable package via TLS 1.2+ HTTPS (11 MB)..." -ForegroundColor Cyan
& curl.exe --proto '=https' --tlsv1.2 --fail --show-error -L -s -o $ZipPath $Url
$curlExit = $LASTEXITCODE

if ($curlExit -ne 0 -or -not (Test-Path $ZipPath) -or (Get-Item $ZipPath).Length -eq 0) {
    Write-Host "[!] Download failed (curl exit code: $curlExit). Verify HTTPS connectivity and TLS stack." -ForegroundColor Red
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    exit 1
}

Write-Host "[*] Verifying cryptographic SHA-256 integrity..." -ForegroundColor Cyan
$actualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()

if ($actualHash -ne $ExpectedSha256) {
    Write-Host "[!] SECURITY ALERT: SHA-256 checksum mismatch! Possible corrupt or tampered download." -ForegroundColor Red
    Write-Host "    Expected: $ExpectedSha256" -ForegroundColor Yellow
    Write-Host "    Actual:   $actualHash" -ForegroundColor Red
    Remove-Item $ZipPath -Force
    exit 1
}

Write-Host "[+] SHA-256 Verified authentic ($actualHash)" -ForegroundColor Green
Write-Host "[*] Unpacking into $DestDir..." -ForegroundColor Cyan
Expand-Archive -Path $ZipPath -DestinationPath $DestDir -Force

Remove-Item $ZipPath -Force
Write-Host "[+] Portable Python ready at: $DestDir\python.exe" -ForegroundColor Green

