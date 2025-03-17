# Windows 11 Hardware Readiness Checker

## Overview

This PowerShell script verifies hardware compliance with Windows 11 requirements. It performs comprehensive checks on your system and returns detailed compatibility information including:

- Storage capacity and free space
- Memory (RAM)
- TPM version and status
- Processor compatibility (including special case CPUs)
- CPU instruction set support (SSE4.2 and PopCnt)
- Secure Boot capability
- Graphics (DirectX 12 and WDDM 2.0)
- Display resolution and size
- OS version compatibility

The script requires elevated privileges (Run as Administrator) for complete hardware checks.

## Requirements

Windows 11 requires:
- TPM 2.0, Secure Boot, UEFI firmware
- 1 GHz+ 64-bit CPU with 2+ cores (with SSE4.2 and PopCnt support for 24H2+)
- 4 GB RAM minimum
- 64 GB storage minimum
- DirectX 12 compatible graphics with WDDM 2.0 driver
- 720p display (9" or larger diagonal)
- Windows 10 version 2004 or later with September 2021 update

## Important Note

This script requires elevated privileges (Run as Administrator) for complete hardware checks. Always run the script from an elevated PowerShell prompt or as local system.

## Installation

Install the script to your PowerShell Scripts folder (similar to PowerShell Gallery modules):

```powershell
# Run in an elevated PowerShell prompt
$ScriptsFolder = if ($PSVersionTable.PSVersion.Major -ge 6) { 
    "$env:USERPROFILE\Documents\PowerShell\Scripts" 
} else { 
    "$env:USERPROFILE\Documents\WindowsPowerShell\Scripts" 
}

# Create Scripts folder if it doesn't exist
if (!(Test-Path $ScriptsFolder)) { New-Item -Path $ScriptsFolder -ItemType Directory -Force }

# Download and save the script
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1' -OutFile "$ScriptsFolder\HardwareReadiness.ps1"

# Verify the script was downloaded
if (Test-Path "$ScriptsFolder\HardwareReadiness.ps1") {
    Write-Host "Script installed successfully to $ScriptsFolder\HardwareReadiness.ps1" -ForegroundColor Green
    Write-Host "You can now run it using: HardwareReadiness" -ForegroundColor Green
} else {
    Write-Host "Failed to install script" -ForegroundColor Red
}
```

## Basic Usage

Run the script in an elevated PowerShell prompt:

```powershell
# If installed to Scripts folder
HardwareReadiness

# Or if running from current directory
.\HardwareReadiness.ps1
```

For detailed progress information, use the `-Verbose` parameter:

```powershell
HardwareReadiness -Verbose
```

## Execution Policy

To run the script without changing global execution policy, use the following command to bypass the execution policy for the current process only:

```powershell
# In an elevated PowerShell prompt
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\HardwareReadiness.ps1
```

## Remote Execution

### Run directly from GitHub:

```powershell
# In an elevated PowerShell prompt
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1'))
```

### One-liner with Invoke-WebRequest:

```powershell
# In an elevated PowerShell prompt
& ([scriptblock]::Create((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1').Content))
```

## JSON Output

### Output as JSON:

```powershell
# In an elevated PowerShell prompt
HardwareReadiness -AsJson

# Or if running from current directory
.\HardwareReadiness.ps1 -AsJson
```

### Save JSON output to file with timestamp:

```powershell
# In an elevated PowerShell prompt
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputPath = "Win11Readiness_$timestamp.json"
HardwareReadiness -AsJson | Out-File -FilePath $outputPath
Write-Host "Results saved to $outputPath"
```

### Save JSON output to file with current date:

```powershell
# In an elevated PowerShell prompt
$date = Get-Date -Format "yyyy-MM-dd"
HardwareReadiness -AsJson | Out-File -FilePath "$date.json"
```

### Output as JSON and copy to clipboard:

```powershell
# In an elevated PowerShell prompt
HardwareReadiness -AsJson | Set-Clipboard
Write-Host "Results copied to clipboard"
```

### Output as JSON, save to file, and copy to clipboard in one command:

```powershell
# In an elevated PowerShell prompt
$result = HardwareReadiness -AsJson
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputPath = "Win11Readiness_$timestamp.json"
$result | Out-File -FilePath $outputPath
$result | Set-Clipboard
Write-Host "Results saved to $outputPath and copied to clipboard"
```

### One-liner for support: Download, run as JSON, and copy to clipboard:

```powershell
# In an elevated PowerShell prompt
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1')) -AsJson | Set-Clipboard; Write-Host 'Windows 11 compatibility results copied to clipboard'
```

## Advanced Usage

### Run with verbose output and save results:

```powershell
# In an elevated PowerShell prompt
$result = HardwareReadiness -Verbose
$result | ConvertTo-Json -Depth 10 | Out-File -FilePath "DetailedResults.json"
```

### Check compatibility and take action based on result:

```powershell
# In an elevated PowerShell prompt
$result = HardwareReadiness
if ($result.compatible) {
    Write-Host "System is compatible with Windows 11" -ForegroundColor Green
} else {
    Write-Host "System is not compatible with Windows 11" -ForegroundColor Red
    Write-Host "Fail reasons: $($result.failReasons -join ', ')"
}
```

## License

This script is distributed under the MIT license.

- Copyright (C) 2021 Microsoft Corporation
- Copyright (C) 2025 Christian Pedersen @ Zentura A/S
