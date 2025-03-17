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

## Usage

Run this single command in an elevated PowerShell prompt to download and execute the script:

```powershell
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/zenturait/Win11Readiness/main/HardwareReadiness.ps1')
```

## License

This script is distributed under the MIT license.

- Copyright (C) 2021 Microsoft Corporation
- Copyright (C) 2025 Christian Pedersen @ Zentura A/S
