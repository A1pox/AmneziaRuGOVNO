[CmdletBinding()]
param(
    [string]$Version = (Get-Date -Format "yyyyMMdd-HHmmss"),
    [string]$OutputRoot = (Join-Path $PSScriptRoot "..\\local-releases"),
    [string]$WindowsBundle = "C:\\src\\Amnezia-unpacked",
    [string]$WindowsExe = "C:\\src\\Amnezia-build\\client\\Release\\AmneziaVPN.exe",
    [string]$WindowsServiceExe = "C:\\src\\Amnezia-build\\service\\server\\Release\\AmneziaVPN-service.exe",
    [string]$AndroidApk = "C:\\src\\Amnezia-android-build\\client\\android-build\\build\\outputs\\apk\\debug\\AmneziaVPN-arm64-v8a-debug.apk"
)

$ErrorActionPreference = "Stop"

function Ensure-Directory {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination,
        [switch]$Directory
    )

    if (-not (Test-Path -LiteralPath $Source)) {
        Write-Warning "Skip missing path: $Source"
        return $null
    }

    if ($Directory) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
    } else {
        $parent = Split-Path -Parent $Destination
        if ($parent) {
            Ensure-Directory -Path $parent | Out-Null
        }
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }

    return $Destination
}

$outputRootPath = Ensure-Directory -Path $OutputRoot
$releaseRoot = Ensure-Directory -Path (Join-Path $outputRootPath $Version)
$windowsRoot = Ensure-Directory -Path (Join-Path $releaseRoot "windows")
$androidRoot = Ensure-Directory -Path (Join-Path $releaseRoot "android")

$copied = @()

$windowsBundleCopy = Copy-IfExists -Source $WindowsBundle -Destination (Join-Path $windowsRoot "unpacked") -Directory
if ($windowsBundleCopy) {
    $copied += "windows_bundle=$windowsBundleCopy"
}

$windowsExeCopy = Copy-IfExists -Source $WindowsExe -Destination (Join-Path $windowsRoot "AmneziaVPN.exe")
if ($windowsExeCopy) {
    $copied += "windows_exe=$windowsExeCopy"
}

$windowsServiceCopy = Copy-IfExists -Source $WindowsServiceExe -Destination (Join-Path $windowsRoot "AmneziaVPN-service.exe")
if ($windowsServiceCopy) {
    $copied += "windows_service=$windowsServiceCopy"
}

$androidApkCopy = Copy-IfExists -Source $AndroidApk -Destination (Join-Path $androidRoot "AmneziaVPN-arm64-v8a-debug.apk")
if ($androidApkCopy) {
    $copied += "android_apk=$androidApkCopy"
}

$manifestPath = Join-Path $releaseRoot "manifest.txt"
$manifest = @(
    "version=$Version"
    "created_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    "source_repo=$((Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path)"
)

if ($copied.Count -gt 0) {
    $manifest += $copied
} else {
    $manifest += "artifacts=none"
}

Set-Content -LiteralPath $manifestPath -Value $manifest

Write-Output "Release staging created at: $releaseRoot"
Get-ChildItem -LiteralPath $releaseRoot -Recurse | Select-Object FullName, Length
