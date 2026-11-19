$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "         Nino High-Assurance Language Installer" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$InstallDir = Join-Path $HOME ".nino"
$BinDir = Join-Path $InstallDir "bin"
$ZipUrl = "https://github.com/jefmextra/nino-lang/releases/download/v1.2.5/nino-v1.2.5-windows-x64.zip"
$TempZip = Join-Path $env:TEMP "nino-package.zip"

Write-Host "[*] Target directory: $InstallDir" -ForegroundColor Yellow
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

Write-Host "[*] Downloading Nino v1.2.5 toolchain package..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $ZipUrl -OutFile $TempZip -UseBasicParsing

Write-Host "[*] Extracting package files..." -ForegroundColor Cyan
$ExtractTemp = Join-Path $env:TEMP "nino-extracted"
if (Test-Path $ExtractTemp) { Remove-Item -Path $ExtractTemp -Recurse -Force }
Expand-Archive -Path $TempZip -DestinationPath $ExtractTemp -Force

Get-ChildItem -Path $ExtractTemp -Recurse | Unblock-File -ErrorAction SilentlyContinue

$NinocSrc = Join-Path $ExtractTemp "ninoc.exe"
$NinoSrc = Join-Path $ExtractTemp "nino.exe"
if (Test-Path $NinocSrc) {
    Copy-Item -Path $NinocSrc -Destination (Join-Path $BinDir "ninoc.exe") -Force
    Copy-Item -Path $NinocSrc -Destination (Join-Path $BinDir "nino.exe") -Force
} elseif (Test-Path $NinoSrc) {
    Copy-Item -Path $NinoSrc -Destination (Join-Path $BinDir "nino.exe") -Force
    Copy-Item -Path $NinoSrc -Destination (Join-Path $BinDir "ninoc.exe") -Force
} else {
    throw "Archive did not contain ninoc.exe or nino.exe"
}

foreach ($sub in @("std", "runtime", "compiler", "tools", "formal")) {
    $SubSrc = Join-Path $ExtractTemp $sub
    if (Test-Path $SubSrc) {
        Copy-Item -Path $SubSrc -Destination $InstallDir -Recurse -Force
    }
}

Remove-Item -Path $TempZip -Force -ErrorAction SilentlyContinue
Remove-Item -Path $ExtractTemp -Recurse -Force -ErrorAction SilentlyContinue

$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$BinDir*") {
    $NewPath = if ($UserPath) { "$UserPath;$BinDir" } else { $BinDir }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::User)
    $env:PATH = "$env:PATH;$BinDir"
    Write-Host "[*] Successfully added $BinDir to User PATH." -ForegroundColor Green
} else {
    Write-Host "[*] $BinDir is already in User PATH." -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  [OK] Nino v1.2.5 installed successfully!" -ForegroundColor Green
Write-Host "  Open a new PowerShell or CMD and type: ninoc version" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Green
Write-Host ""
