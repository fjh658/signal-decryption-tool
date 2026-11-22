# Build the Windows binaries of SignalDecryption natively, on Windows (MSVC ABI).
#
# signal-sqlite embeds SQLCipher, whose crypto is RustCrypto
# (crates/sqlcipher-rustcrypto), so only the MSVC tools are needed;
# build_windows.sh cross-compiles the same binaries from macOS/Linux with
# cargo-xwin. Unlike macOS there is no "universal" container on Windows, so one
# .exe is written per architecture.
#
# Prerequisites (once):
#   Visual Studio 2022 Build Tools with the C++ workload (ARM64 and x64 tools)
#   rustup target add aarch64-pc-windows-msvc x86_64-pc-windows-msvc
#
# Output: target\windows\<bin>-<arch>.exe plus built-from.txt (the commit they
# were built from), which package.sh checks before it ships them.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File build_windows.ps1

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# ---- Configuration (named constants) ----------------------------------------

$OutputDir = 'target\windows'
$Profile = 'release'
# Table of "<rust-target>:<output-suffix>" to build.
$Targets = @('aarch64-pc-windows-msvc:arm64', 'x86_64-pc-windows-msvc:x64')
# Both binaries; signal-sqlite needs the `sqlite` feature (bundled SQLCipher).
$Binaries = @('SignalDecryption', 'signal-sqlite')

# ---- Guarded actions (I/O at the edges) -------------------------------------

function Assert-Tools {
    foreach ($tool in 'cargo', 'git') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool not found on PATH" }
    }
}

function Invoke-Build([string]$Target) {
    Write-Output "Building for $Target..."
    & cargo build "--$Profile" --features sqlite --target $Target
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed for $Target" }
}

# Copy every binary built for a target to its suffixed output name.
function Copy-Output([string]$Target, [string]$Suffix) {
    foreach ($bin in $Binaries) {
        $src = "target\$Target\$Profile\$bin.exe"
        if (-not (Test-Path $src)) { throw "expected binary not found: $src" }
        $dst = "$OutputDir\$bin-$Suffix.exe"
        Copy-Item $src $dst -Force
        Write-Output "  -> $dst"
    }
}

# The commit the binaries come from, and whether the tree had local changes.
function Write-BuiltFrom {
    $rev = (& git rev-parse HEAD).Trim()
    $dirty = if (& git status --porcelain --untracked-files=no) { 'dirty' } else { 'clean' }
    Set-Content -Path "$OutputDir\built-from.txt" -Value "$rev $dirty" -Encoding ascii
}

# ---- Composition ------------------------------------------------------------

function Invoke-Main {
    Assert-Tools
    New-Item -ItemType Directory -Force $OutputDir | Out-Null
    foreach ($entry in $Targets) {
        $target, $suffix = $entry -split ':'
        Invoke-Build $target
        Copy-Output $target $suffix
    }
    Write-BuiltFrom
    Write-Output "Windows binaries created in $OutputDir\"
}

Invoke-Main
