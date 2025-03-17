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

## Basic Usage

Run the script in PowerShell:

```powershell
.\HardwareReadiness.ps1
```

For detailed progress information, use the `-Verbose` parameter:

```powershell
.\HardwareReadiness.ps1 -Verbose
```

## Execution Policy

To run the script without changing global execution policy, use the following command to bypass the execution policy for the current process only:

```powershell
powershell -ExecutionPolicy Bypass -File .\HardwareReadiness.ps1
```

Or within an existing PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\HardwareReadiness.ps1
```

## Remote Execution

### Run directly from GitHub (similar to Chocolatey):

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1'))"
```

### One-liner with Invoke-WebRequest:

```powershell
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1').Content))"
```

## JSON Output

### Output as JSON:

```powershell
.\HardwareReadiness.ps1 -AsJson
```

### Save JSON output to file with timestamp:

```powershell
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputPath = "Win11Readiness_$timestamp.json"
.\HardwareReadiness.ps1 -AsJson | Out-File -FilePath $outputPath
Write-Host "Results saved to $outputPath"
```

### Save JSON output to file with current date:

```powershell
$date = Get-Date -Format "yyyy-MM-dd"
.\HardwareReadiness.ps1 -AsJson | Out-File -FilePath "$date.json"
```

### Output as JSON and copy to clipboard:

```powershell
.\HardwareReadiness.ps1 -AsJson | Set-Clipboard
Write-Host "Results copied to clipboard"
```

### Output as JSON, save to file, and copy to clipboard in one command:

```powershell
$result = .\HardwareReadiness.ps1 -AsJson
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputPath = "Win11Readiness_$timestamp.json"
$result | Out-File -FilePath $outputPath
$result | Set-Clipboard
Write-Host "Results saved to $outputPath and copied to clipboard"
```

### One-liner for support: Download, run as JSON, and copy to clipboard:

```powershell
powershell -ExecutionPolicy Bypass -Command "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1')) -AsJson | Set-Clipboard; Write-Host 'Windows 11 compatibility results copied to clipboard'"
```

## Advanced Usage

### Run with verbose output and save results:

```powershell
$result = .\HardwareReadiness.ps1 -Verbose
$result | ConvertTo-Json -Depth 10 | Out-File -FilePath "DetailedResults.json"
```

### Check compatibility and take action based on result:

```powershell
$result = .\HardwareReadiness.ps1
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
