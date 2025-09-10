<#
Packages the Thunderbird extension into an .xpi including _locales.

Usage (from repo root):
  powershell -ExecutionPolicy Bypass -File scripts/package.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
Set-Location $repoRoot

if (-not (Test-Path 'manifest.json')) {
  throw 'Run this script from the repository root (manifest.json not found).'
}

# Read version from manifest.json
$manifest = Get-Content -Raw -Path 'manifest.json' | ConvertFrom-Json
$version = $manifest.version
if (-not $version) { $version = '0.0.0' }

$distDir = Join-Path $repoRoot 'dist'
$stageDir = Join-Path $distDir 'unpacked'
$zipPath = Join-Path $distDir ("PixelGuard-$version.zip")
$xpiPath = Join-Path $distDir ("PixelGuard-$version.xpi")

# Prepare staging directory
if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

# Files and folders to include
$include = @(
  'manifest.json',
  'background.js',
  'content',
  'options',
  'popup',
  '_locales',
  'icons',
  'experiments'
)

# Copy included items if they exist
foreach ($item in $include) {
  if (Test-Path $item) {
    Copy-Item $item -Destination $stageDir -Recurse -Force
  }
}

# Basic validation
if (-not (Test-Path (Join-Path $stageDir '_locales/en/messages.json'))) {
  throw "Missing _locales/en/messages.json in staging. Ensure locales exist before packaging."
}
if (-not (Test-Path (Join-Path $stageDir 'manifest.json'))) {
  throw 'Missing manifest.json in staging.'
}

# Create dist directory
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

# Create XPI using .NET ZipArchive and forward-slash paths
if (Test-Path $xpiPath) { Remove-Item $xpiPath -Force }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$fileStream = [System.IO.File]::Open($xpiPath, [System.IO.FileMode]::Create)
try {
  $zip = New-Object System.IO.Compression.ZipArchive($fileStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
  try {
    Get-ChildItem -Path $stageDir -Recurse -File | ForEach-Object {
      $full = $_.FullName
      # Compute relative path and normalize to forward slashes
      $rel = $full.Substring($stageDir.Length).TrimStart('\','/')
      $rel = $rel -replace '\\','/'
      [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $full, $rel, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
  }
  finally {
    $zip.Dispose()
  }
}
finally {
  $fileStream.Dispose()
}

Write-Host "Packaged: $xpiPath"
