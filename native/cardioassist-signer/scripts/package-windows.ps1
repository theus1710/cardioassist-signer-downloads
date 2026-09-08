<#
Builds a per-user, self-contained Windows installer.  Run from this directory
on Windows with JDK 17 (jpackage) and Inno Setup 6 installed.
#>
[CmdletBinding()]
param(
  [string]$Version = "0.0.0",
  [string]$OutputDir = "dist",
  [string]$CertificatePath,
  [string]$CertificatePassword
)

$ErrorActionPreference = "Stop"
$Version = $Version -replace '^signer-v', ''
if ($Version -notmatch '^[0-9]+(\.[0-9]+){1,2}$') {
  throw "Version must contain two or three numeric components, for example 1.0.0"
}

function Find-SignTool {
  $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
  $candidate = Get-ChildItem -Path $kitsRoot -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
  if (-not $candidate) { throw "signtool.exe was not found in PATH or the Windows SDK" }
  return $candidate.FullName
}

$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root $OutputDir
$imageDir = Join-Path $output "image"
$installerDir = Join-Path $output "installer"
$iss = Join-Path $output "CardioAssistSigner.iss"
New-Item -ItemType Directory -Force -Path $imageDir, $installerDir | Out-Null

Push-Location $root
try {
  if (-not (Test-Path "target/cardioassist-signer.jar")) { mvn package }
  jpackage --type app-image --name CardioAssistSigner --app-version $Version `
    --input target --main-jar cardioassist-signer.jar --main-class br.com.cardioassist.signer.Main `
    --dest $imageDir --java-options "-Dcardioassist.baseUrl=https://cardioassistant.top"

  $appExe = Join-Path $imageDir "CardioAssistSigner\CardioAssistSigner.exe"
  $signed = $false
  if ($CertificatePath -and $CertificatePassword) {
    $signtool = Find-SignTool
    & $signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f $CertificatePath /p $CertificatePassword $appExe
    if ($LASTEXITCODE -ne 0) { throw "signtool failed while signing application executable" }
    $signed = $true
  }

  @"
[Setup]
AppId={{9A9D289E-968B-499B-9A9A-D7C513CFB0DA}
AppName=CardioAssist Signer
AppVersion=$Version
AppPublisher=CardioAssist
DefaultDirName={localappdata}\CardioAssist Signer
DefaultGroupName=CardioAssist Signer
DisableProgramGroupPage=yes
UninstallDisplayName=CardioAssist Signer
UninstallDisplayIcon={app}\CardioAssistSigner.exe
OutputDir=$installerDir
OutputBaseFilename=CardioAssistSigner-Windows-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
Compression=lzma2
SolidCompression=yes

[Files]
Source: "$imageDir\CardioAssistSigner\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\CardioAssist Signer"; Filename: "{app}\CardioAssistSigner.exe"
Name: "{autodesktop}\CardioAssist Signer"; Filename: "{app}\CardioAssistSigner.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Registry]
Root: HKCU; Subkey: "Software\Classes\cardioassist-signer"; ValueType: string; ValueName: ""; ValueData: "URL:CardioAssist Signer"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\cardioassist-signer"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Flags: uninsdeletevalue
Root: HKCU; Subkey: "Software\Classes\cardioassist-signer\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\CardioAssistSigner.exe"" ""%1"""; Flags: uninsdeletekey
"@ | Set-Content -Path $iss -Encoding utf8

  $iscc = (Get-Command ISCC.exe -ErrorAction Stop).Source
  & $iscc $iss
  if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed" }
  $installer = Join-Path $installerDir "CardioAssistSigner-Windows-x64.exe"
  if ($signed) {
    & $signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f $CertificatePath /p $CertificatePassword $installer
    if ($LASTEXITCODE -ne 0) { throw "signtool failed while signing installer" }
  }
  @{ platform = "windows-x64"; asset = "CardioAssistSigner-Windows-x64.exe"; signed = $signed; notarized = $false } |
    ConvertTo-Json -Compress | Set-Content -Path (Join-Path $output "build-metadata.json") -Encoding utf8
} finally {
  Pop-Location
}