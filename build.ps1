<#
.SYNOPSIS
  Build jksextract on Windows.

.EXAMPLE
  .\build.ps1                # build jksextract.exe for this machine
  .\build.ps1 -All           # cross-compile every release target into bin\
  .\build.ps1 -Version 1.2.0 # stamp a version into the binary
#>
param(
    [switch]$All,
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go is not installed or not on PATH. Install it from https://go.dev/dl/"
}

if (-not $Version) {
    $Version = (git describe --tags --always --dirty 2>$null)
    if (-not $Version) { $Version = "dev" }
}

$ldflags = "-s -w -X main.version=$Version"
$env:CGO_ENABLED = "0"

function Build($goos, $goarch, $out) {
    Write-Host "Building $out ($goos/$goarch)"
    $env:GOOS = $goos
    $env:GOARCH = $goarch
    go build -trimpath -ldflags $ldflags -o $out .
    if ($LASTEXITCODE -ne 0) { throw "build failed for $goos/$goarch" }
}

try {
    if ($All) {
        New-Item -ItemType Directory -Force -Path bin | Out-Null
        Build windows amd64 bin\jksextract-windows-amd64.exe
        Build windows arm64 bin\jksextract-windows-arm64.exe
        Build darwin  arm64 bin\jksextract-darwin-arm64
        Build darwin  amd64 bin\jksextract-darwin-amd64
        Build linux   amd64 bin\jksextract-linux-amd64
        Build linux   arm64 bin\jksextract-linux-arm64
    } else {
        Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
        go build -trimpath -ldflags $ldflags -o jksextract.exe .
        if ($LASTEXITCODE -ne 0) { throw "build failed" }
        Write-Host "Built jksextract.exe"
    }
} finally {
    Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
}
