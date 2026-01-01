# TAK Wireshark Plugin Installer for Windows
# Run: powershell -ExecutionPolicy Bypass -File install.ps1

param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TakPlugin = Join-Path $ScriptDir "tak.lua"
$OmniPlugin = Join-Path $ScriptDir "omni.lua"

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# Check if plugin files exist
if (-not (Test-Path $TakPlugin)) {
    Write-Err "Plugin file not found: $TakPlugin"
}
if (-not (Test-Path $OmniPlugin)) {
    Write-Err "Plugin file not found: $OmniPlugin"
}

# Get Wireshark version
function Get-WiresharkVersion {
    $version = $null

    # Try Wireshark
    $wsPath = Get-Command wireshark -ErrorAction SilentlyContinue
    if ($wsPath) {
        $output = & wireshark --version 2>&1 | Select-Object -First 1
        if ($output -match '(\d+\.\d+)') {
            $version = $Matches[1]
        }
    }

    # Try tshark
    if (-not $version) {
        $tsPath = Get-Command tshark -ErrorAction SilentlyContinue
        if ($tsPath) {
            $output = & tshark --version 2>&1 | Select-Object -First 1
            if ($output -match '(\d+\.\d+)') {
                $version = $Matches[1]
            }
        }
    }

    # Try registry
    if (-not $version) {
        $regPaths = @(
            "HKLM:\SOFTWARE\Wireshark",
            "HKLM:\SOFTWARE\WOW6432Node\Wireshark"
        )
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $ver = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).CurrentVersion
                if ($ver -match '(\d+\.\d+)') {
                    $version = $Matches[1]
                    break
                }
            }
        }
    }

    return $version
}

# Get plugin directories
function Get-PluginDirectories {
    $dirs = @()

    # User plugin directory (preferred)
    $userDir = Join-Path $env:APPDATA "Wireshark\plugins"
    $dirs += $userDir

    # Program Files directories
    $programDirs = @(
        "C:\Program Files\Wireshark\plugins",
        "C:\Program Files (x86)\Wireshark\plugins",
        (Join-Path $env:ProgramFiles "Wireshark\plugins"),
        (Join-Path ${env:ProgramFiles(x86)} "Wireshark\plugins")
    )

    foreach ($dir in $programDirs) {
        if ($dir -and (Test-Path (Split-Path $dir -Parent))) {
            $dirs += $dir
        }
    }

    return $dirs | Select-Object -Unique
}

# Install plugins
function Install-Plugin {
    param($TargetDir, $Version)

    # Add version subdirectory if known
    if ($Version) {
        $TargetDir = Join-Path $TargetDir $Version
    }

    Write-Info "Installing to: $TargetDir"

    # Create directory
    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }

    # Copy plugins
    Copy-Item $TakPlugin -Destination $TargetDir -Force
    Copy-Item $OmniPlugin -Destination $TargetDir -Force

    $takInstalled = Join-Path $TargetDir "tak.lua"
    $omniInstalled = Join-Path $TargetDir "omni.lua"
    return ((Test-Path $takInstalled) -and (Test-Path $omniInstalled))
}

# Uninstall plugins
function Uninstall-Plugin {
    Write-Host "Uninstalling TAK/OMNI plugins..." -ForegroundColor Cyan

    $version = Get-WiresharkVersion
    $dirs = Get-PluginDirectories

    foreach ($dir in $dirs) {
        $plugins = @("tak.lua", "omni.lua")
        foreach ($plugin in $plugins) {
            $targets = @(
                (Join-Path $dir $plugin)
            )
            if ($version) {
                $targets += (Join-Path $dir "$version\$plugin")
            }

            foreach ($target in $targets) {
                if (Test-Path $target) {
                    Remove-Item $target -Force
                    Write-Info "Removed: $target"
                }
            }
        }
    }

    Write-Info "Uninstallation complete"
}

# Main
function Main {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  TAK Wireshark Plugin Installer" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host

    $version = Get-WiresharkVersion

    if ($version) {
        Write-Info "Detected Wireshark version: $version"
    } else {
        Write-Warn "Could not detect Wireshark version"
    }

    $dirs = Get-PluginDirectories

    # Try each directory
    foreach ($dir in $dirs) {
        try {
            if (Install-Plugin -TargetDir $dir -Version $version) {
                Write-Host
                Write-Info "Installation complete!"
                Write-Info "Restart Wireshark to load the plugin."
                Write-Host
                $finalPath = if ($version) { Join-Path $dir $version } else { $dir }
                Write-Host "Plugin location: $finalPath" -ForegroundColor Gray
                return
            }
        } catch {
            Write-Warn "Could not install to $dir"
        }
    }

    Write-Err "Installation failed. Try running as Administrator."
}

# Entry point
if ($Uninstall) {
    Uninstall-Plugin
} else {
    Main
}
