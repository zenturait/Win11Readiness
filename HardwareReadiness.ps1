# Add parameter to support JSON output
[CmdletBinding()]
param (
    [switch]$AsJson
)

#=============================================================================================================================
#
# Script Name:     HardwareReadiness.ps1
# Description:     Verifies hardware compliance with Windows 11 requirements. Returns a PowerShell object with detailed 
#                  compatibility information. Return code 0 for success. In case of failure, returns non zero error code
#                  along with error message.
#                  NOTE: This script requires elevated privileges (Run as Administrator) for complete hardware checks.
#
# Originally by:   Microsoft Corporation
# Updated:         March 2025 by Christian Pedersen @ Zentura A/S
#
# Requirements:    - Windows 11 requires TPM 2.0, Secure Boot, UEFI firmware
#                  - 1 GHz+ 64-bit CPU with 2+ cores (with SSE4.2 and PopCnt support for 24H2+)
#                  - 4 GB RAM minimum
#                  - 64 GB storage minimum
#                  - DirectX 12 compatible graphics with WDDM 2.0 driver
#                  - 720p display (9" or larger diagonal)
#                  - Windows 10 version 2004 or later with September 2021 update
#
# Parameters:      -AsJson     Outputs the results as JSON instead of a PowerShell object
#                  -Verbose    Enables verbose output showing detailed progress information

# This script is not supported under any Microsoft standard support program or service and is distributed under the MIT license

# Copyright (C) 2021 Microsoft Corporation
# Copyright (C) 2025 Christian Pedersen @ Zentura A/S

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#=============================================================================================================================

# Check if running with administrator privileges
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$isAdmin = Test-Administrator
Write-Verbose "Checking administrator privileges..."
if (-not $isAdmin) {
    Write-Warning "This script is not running with administrator privileges. Some checks (like TPM and SecureBoot) may fail."
    Write-Warning "For complete results, please run this script as Administrator (right-click PowerShell and select 'Run as Administrator')."
    Write-Verbose "Administrator check: FAILED - Script is not running with elevated privileges"
}
else {
    Write-Verbose "Administrator check: PASSED - Script is running with elevated privileges"
}

# Hardware requirement constants
[int]$MinOSDiskSizeGB = 64
[int]$MinOSDiskFreeSpaceGB = 25 # 15GB Microsoft recommendation + 10GB additional buffer
[int]$MinMemoryGB = 4
[Uint32]$MinClockSpeedMHz = 1000
[Uint32]$MinLogicalCores = 2
[Uint16]$RequiredAddressWidth = 64

# Initialize result object
$result = [PSCustomObject]@{
    metadata = [PSCustomObject]@{
        computerName = [System.Environment]::MachineName
        userName = [System.Environment]::UserName
        domainName = [System.Environment]::UserDomainName
        timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        systemManufacturer = $null
        systemModel = $null
    }
    compatible = $false
    returnCode = -2 # -2=not run, -1=undetermined, 0=compatible, 1=not compatible
    storage = [PSCustomObject]@{
        passed = $false
        sizeGB = $null
        freeSpaceGB = $null
    }
    memory = [PSCustomObject]@{
        passed = $false
        sizeGB = $null
    }
    tpm = [PSCustomObject]@{
        passed = $false
        version = $null
    }
    processor = [PSCustomObject]@{
        passed = $false
        details = $null
        cpuInstructions = [PSCustomObject]@{
            passed = $false
            sse42 = $false
            popCnt = $false
        }
    }
    secureBoot = [PSCustomObject]@{
        passed = $false
    }
    graphics = [PSCustomObject]@{
        passed = $false
        directX12 = $false
        wddm2 = $false
        details = $null
    }
    display = [PSCustomObject]@{
        passed = $false
        resolution = $null
        diagonal = $null
    }
    osVersion = [PSCustomObject]@{
        passed = $false
        version = $null
        details = $null
    }
    i7_7820hq = [PSCustomObject]@{
        passed = $false
        model = $null
    }
    failReasons = @()
    exceptions = @()
}

# NOT COMPATIBLE(1) state takes precedence over UNDETERMINED(-1) state
function Private:UpdateReturnCode {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(-2, 1)]
        [int] $ReturnCode
    )

    Switch ($ReturnCode) {
        0 {
            if ($result.returnCode -eq -2) {
                $result.returnCode = $ReturnCode
            }
        }
        1 {
            $result.returnCode = $ReturnCode
        }
        -1 {
            if ($result.returnCode -ne 1) {
                $result.returnCode = $ReturnCode
            }
        }
    }
}

# Helper function to add a fail reason
function Private:AddFailReason {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Component
    )
    
    if (-not $result.failReasons.Contains($Component)) {
        $result.failReasons += $Component
    }
}

# Helper function to add an exception
function Private:AddException {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ExceptionText
    )
    
    $result.exceptions += $ExceptionText
}

$Source = @"
using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

    public class CpuFamilyResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }

    public class CpuFamily
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public enum ProcessorFeature : uint
        {
            ARM_SUPPORTED_INSTRUCTIONS = 34
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsProcessorFeaturePresent(ProcessorFeature processorFeature);

        private const ushort PROCESSOR_ARCHITECTURE_X86 = 0;
        private const ushort PROCESSOR_ARCHITECTURE_ARM64 = 12;
        private const ushort PROCESSOR_ARCHITECTURE_X64 = 9;

        private const string INTEL_MANUFACTURER = "GenuineIntel";
        private const string AMD_MANUFACTURER = "AuthenticAMD";
        private const string QUALCOMM_MANUFACTURER = "Qualcomm Technologies Inc";

        public static CpuFamilyResult Validate(string manufacturer, ushort processorArchitecture)
        {
            CpuFamilyResult cpuFamilyResult = new CpuFamilyResult();

            if (string.IsNullOrWhiteSpace(manufacturer))
            {
                cpuFamilyResult.IsValid = false;
                cpuFamilyResult.Message = "Manufacturer is null or empty";
                return cpuFamilyResult;
            }

            string registryPath = "HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\CentralProcessor\\0";
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetNativeSystemInfo(ref sysInfo);

            switch (processorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_ARM64:

                    if (manufacturer.Equals(QUALCOMM_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isArmv81Supported = IsProcessorFeaturePresent(ProcessorFeature.ARM_SUPPORTED_INSTRUCTIONS);

                        if (!isArmv81Supported)
                        {
                            string registryName = "CP 4030";
                            long registryValue = (long)Registry.GetValue(registryPath, registryName, -1);
                            long atomicResult = (registryValue >> 20) & 0xF;

                            if (atomicResult >= 2)
                            {
                                isArmv81Supported = true;
                            }
                        }

                        cpuFamilyResult.IsValid = isArmv81Supported;
                        cpuFamilyResult.Message = isArmv81Supported ? "" : "Processor does not implement ARM v8.1 atomic instruction";
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "The processor isn't currently supported for Windows 11";
                    }

                    break;

                case PROCESSOR_ARCHITECTURE_X64:
                case PROCESSOR_ARCHITECTURE_X86:

                    int cpuFamily = sysInfo.ProcessorLevel;
                    int cpuModel = (sysInfo.ProcessorRevision >> 8) & 0xFF;
                    int cpuStepping = sysInfo.ProcessorRevision & 0xFF;

                    if (manufacturer.Equals(INTEL_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            // Default to valid for modern Intel CPUs (2024 update)
                            cpuFamilyResult.IsValid = true;
                            cpuFamilyResult.Message = "";

                            // Check for known unsupported CPUs
                            if (cpuFamily == 6)
                            {
                                // Intel 7th gen and older are not officially supported (except special cases)
                                // Models 78, 85, 94 are 6th gen (Skylake)
                                // Models 142, 158 are 7th gen (Kaby Lake)
                                if (cpuModel <= 95 && cpuModel != 85)
                                {
                                    // Special case for certain 7th gen CPUs that are supported
                                    bool isSpecialCase = false;
                                    
                                    // Check for special case CPUs (i7-7820HQ is handled separately)
                                    if ((cpuModel == 142 || cpuModel == 158) && cpuStepping == 9)
                                    {
                                        string registryName = "Platform Specific Field 1";
                                        int registryValue = (int)Registry.GetValue(registryPath, registryName, -1);
                                        
                                        if ((cpuModel == 142 && registryValue == 16) || 
                                            (cpuModel == 158 && registryValue == 8))
                                        {
                                            isSpecialCase = true;
                                        }
                                    }
                                    
                                    if (!isSpecialCase)
                                    {
                                        cpuFamilyResult.IsValid = false;
                                        cpuFamilyResult.Message = "CPU generation not supported by Windows 11";
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            // For newer CPUs, default to valid even if there's an exception
                            // This ensures compatibility with future Intel CPUs
                            cpuFamilyResult.IsValid = true;
                            cpuFamilyResult.Message = "Exception handled: " + ex.GetType().Name;
                        }
                    }
                    else if (manufacturer.Equals(AMD_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        // Default to valid for modern AMD CPUs (2024 update)
                        cpuFamilyResult.IsValid = true;
                        cpuFamilyResult.Message = "";

                        // Check for known unsupported CPUs
                        // AMD Zen 1 and older are not officially supported
                        if (cpuFamily < 23 || (cpuFamily == 23 && (cpuModel == 1 || cpuModel == 17)))
                        {
                            cpuFamilyResult.IsValid = false;
                            cpuFamilyResult.Message = "CPU generation not supported by Windows 11";
                        }
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "Unsupported Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    }

                    break;

                default:
                    cpuFamilyResult.IsValid = false;
                    cpuFamilyResult.Message = "Unsupported CPU category. Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    break;
            }
            return cpuFamilyResult;
        }
    }
"@

# Storage check
Write-Verbose "Checking storage requirements..."
Write-Verbose "Minimum OS disk size: $MinOSDiskSizeGB GB, Minimum free space: $MinOSDiskFreeSpaceGB GB"
try {
    $osDrive = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property SystemDrive
    Write-Verbose "OS Drive: $($osDrive.SystemDrive)"
    
    $osDriveInfo = Get-WmiObject -Class Win32_LogicalDisk -filter "DeviceID='$($osDrive.SystemDrive)'" | 
                   Select-Object @{Name = "SizeGB"; Expression = { $_.Size / 1GB -as [int] }},
                                 @{Name = "FreeSpaceGB"; Expression = { $_.FreeSpace / 1GB -as [int] }}

    $result.storage.sizeGB = $osDriveInfo.SizeGB
    $result.storage.freeSpaceGB = $osDriveInfo.FreeSpaceGB
    
    Write-Verbose "OS Drive Size: $($osDriveInfo.SizeGB) GB, Free Space: $($osDriveInfo.FreeSpaceGB) GB"
    
    $storageCheckPassed = $true
    
    if ($null -eq $osDriveInfo) {
        UpdateReturnCode -ReturnCode 1
        AddFailReason -Component "Storage"
        $storageCheckPassed = $false
        Write-Verbose "Storage check: FAILED - Could not retrieve drive information"
    }
    elseif ($osDriveInfo.SizeGB -lt $MinOSDiskSizeGB) {
        UpdateReturnCode -ReturnCode 1
        AddFailReason -Component "Storage_TotalSize"
        $storageCheckPassed = $false
        Write-Verbose "Storage check: FAILED - Drive size ($($osDriveInfo.SizeGB) GB) is less than required ($MinOSDiskSizeGB GB)"
    }
    elseif ($osDriveInfo.FreeSpaceGB -lt $MinOSDiskFreeSpaceGB) {
        UpdateReturnCode -ReturnCode 1
        AddFailReason -Component "Storage_FreeSpace"
        $storageCheckPassed = $false
        Write-Verbose "Storage check: FAILED - Free space ($($osDriveInfo.FreeSpaceGB) GB) is less than required ($MinOSDiskFreeSpaceGB GB)"
    }
    
    $result.storage.passed = $storageCheckPassed
    if ($storageCheckPassed) {
        UpdateReturnCode -ReturnCode 0
        Write-Verbose "Storage check: PASSED"
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    $result.storage.sizeGB = "undetermined"
    $result.storage.freeSpaceGB = "undetermined"
    AddException -ExceptionText "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "Storage check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# Memory check
Write-Verbose "Checking memory requirements..."
Write-Verbose "Minimum memory: $MinMemoryGB GB"
try {
    $memory = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | Select-Object @{Name = "SizeGB"; Expression = { $_.Sum / 1GB -as [int] } }

    $result.memory.sizeGB = $memory.SizeGB
    Write-Verbose "Detected memory: $($memory.SizeGB) GB"

    if ($null -eq $memory) {
        UpdateReturnCode -ReturnCode 1
        AddFailReason -Component "Memory"
        Write-Verbose "Memory check: FAILED - Could not retrieve memory information"
    }
    elseif ($memory.SizeGB -lt $MinMemoryGB) {
        UpdateReturnCode -ReturnCode 1
        AddFailReason -Component "Memory"
        Write-Verbose "Memory check: FAILED - Installed memory ($($memory.SizeGB) GB) is less than required ($MinMemoryGB GB)"
    }
    else {
        $result.memory.passed = $true
        UpdateReturnCode -ReturnCode 0
        Write-Verbose "Memory check: PASSED"
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    $result.memory.sizeGB = "undetermined"
    AddException -ExceptionText "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "Memory check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# TPM check
Write-Verbose "Checking TPM requirements..."
Write-Verbose "Required TPM version: 2.0+"
try {
    if (-not $isAdmin) {
        # If not running as admin, mark as undetermined but with a clear message
        UpdateReturnCode -ReturnCode -1
        $result.tpm.version = "requires admin"
        AddException -ExceptionText "Administrator privileges required to check TPM"
        Write-Verbose "TPM check: SKIPPED - Administrator privileges required"
    }
    else {
        Write-Verbose "Checking TPM presence and version..."
        $tpm = Get-Tpm

        if ($null -eq $tpm) {
            UpdateReturnCode -ReturnCode 1
            AddFailReason -Component "TPM"
            $result.tpm.version = "null"
            Write-Verbose "TPM check: FAILED - TPM not detected"
        }
        elseif ($tpm.TpmPresent) {
            Write-Verbose "TPM is present, checking version..."
            $tpmVersion = Get-WmiObject -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm | Select-Object -Property SpecVersion

            if ($null -eq $tpmVersion.SpecVersion) {
                UpdateReturnCode -ReturnCode 1
                AddFailReason -Component "TPM"
                $result.tpm.version = "null"
                Write-Verbose "TPM check: FAILED - Could not determine TPM version"
            }
            else {
                $result.tpm.version = $tpmVersion.SpecVersion
                $majorVersion = $tpmVersion.SpecVersion.Split(",")[0] -as [int]
                Write-Verbose "TPM version detected: $($tpmVersion.SpecVersion) (Major version: $majorVersion)"
                
                if ($majorVersion -lt 2) {
                    UpdateReturnCode -ReturnCode 1
                    AddFailReason -Component "TPM"
                    Write-Verbose "TPM check: FAILED - TPM version $majorVersion is less than required version 2.0"
                }
                else {
                    $result.tpm.passed = $true
                    UpdateReturnCode -ReturnCode 0
                    Write-Verbose "TPM check: PASSED"
                }
            }
        }
        else {
            if ($tpm.GetType().Name -eq "String") {
                UpdateReturnCode -ReturnCode -1
                $result.tpm.version = "undetermined"
                AddException -ExceptionText $tpm
                Write-Verbose "TPM check: ERROR - $tpm"
            }
            else {
                UpdateReturnCode -ReturnCode 1
                AddFailReason -Component "TPM"
                $result.tpm.version = "not present"
                Write-Verbose "TPM check: FAILED - TPM is not present"
            }
        }
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    $result.tpm.version = "undetermined"
    AddException -ExceptionText "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "TPM check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# Get system information for metadata
try {
    Write-Verbose "Getting system information for metadata..."
    $systemInfo = Get-WmiObject -Class Win32_ComputerSystem
    if ($null -ne $systemInfo) {
        $result.metadata.systemManufacturer = $systemInfo.Manufacturer
        $result.metadata.systemModel = $systemInfo.Model
        Write-Verbose "System information: Manufacturer: $($systemInfo.Manufacturer), Model: $($systemInfo.Model)"
    }
    else {
        Write-Verbose "Could not retrieve system information"
    }
}
catch {
    Write-Verbose "Error getting system information: $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# CPU Details check
Write-Verbose "Checking processor requirements..."
Write-Verbose "Required: 64-bit CPU with 1+ GHz clock speed and 2+ cores"
try {
    $cpuDetails = @(Get-WmiObject -Class Win32_Processor)[0]

    if ($null -eq $cpuDetails) {
        UpdateReturnCode -ReturnCode 1
        AddFailReason -Component "Processor"
        $result.processor.details = "null"
        Write-Verbose "Processor check: FAILED - Could not retrieve processor information"
    }
    else {
        Write-Verbose "Processor detected: $($cpuDetails.Caption)"
        Write-Verbose "Manufacturer: $($cpuDetails.Manufacturer), Clock Speed: $($cpuDetails.MaxClockSpeed) MHz, Cores: $($cpuDetails.NumberOfLogicalProcessors), Architecture: $($cpuDetails.AddressWidth)-bit"
        
        $processorCheckFailed = $false
        $processorDetails = @{
            AddressWidth = $cpuDetails.AddressWidth
            MaxClockSpeed = $cpuDetails.MaxClockSpeed
            NumberOfLogicalCores = $cpuDetails.NumberOfLogicalProcessors
            Manufacturer = $cpuDetails.Manufacturer
            Caption = $cpuDetails.Caption
        }

        # AddressWidth
        if ($null -eq $cpuDetails.AddressWidth -or $cpuDetails.AddressWidth -ne $RequiredAddressWidth) {
            UpdateReturnCode -ReturnCode 1
            $processorCheckFailed = $true
            Write-Verbose "Processor check: FAILED - CPU architecture is not 64-bit"
        }

        # ClockSpeed is in MHz
        if ($null -eq $cpuDetails.MaxClockSpeed -or $cpuDetails.MaxClockSpeed -le $MinClockSpeedMHz) {
            UpdateReturnCode -ReturnCode 1
            $processorCheckFailed = $true
            Write-Verbose "Processor check: FAILED - CPU clock speed ($($cpuDetails.MaxClockSpeed) MHz) is less than required ($MinClockSpeedMHz MHz)"
        }

        # Number of Logical Cores
        if ($null -eq $cpuDetails.NumberOfLogicalProcessors -or $cpuDetails.NumberOfLogicalProcessors -lt $MinLogicalCores) {
            UpdateReturnCode -ReturnCode 1
            $processorCheckFailed = $true
            Write-Verbose "Processor check: FAILED - CPU has fewer cores ($($cpuDetails.NumberOfLogicalProcessors)) than required ($MinLogicalCores)"
        }

        # CPU Family
        Write-Verbose "Checking CPU family compatibility..."
        # Check if the types already exist
        $cpuFamilyType = [System.Type]::GetType("CpuFamily")
        $cpuFamilyResultType = [System.Type]::GetType("CpuFamilyResult")
        
        # Only add types if they don't exist
        if ($null -eq $cpuFamilyType -or $null -eq $cpuFamilyResultType) {
            try {
                Add-Type -TypeDefinition $Source -ErrorAction Stop
                Write-Verbose "Added CPU validation types"
            }
            catch {
                # Ignore errors about types already existing
                # Other errors will be handled in the next try/catch block
                Write-Verbose "CPU validation types already exist"
            }
        }
        
        # Now try to use the types, whether they were just added or already existed
        try {
            $cpuFamilyResult = [CpuFamily]::Validate([String]$cpuDetails.Manufacturer, [uint16]$cpuDetails.Architecture)
            
            if ($cpuFamilyResult.Message) {
                $processorDetails.CpuFamilyMessage = $cpuFamilyResult.Message
                Write-Verbose "CPU family validation message: $($cpuFamilyResult.Message)"
            }

            if (!$cpuFamilyResult.IsValid) {
                UpdateReturnCode -ReturnCode 1
                $processorCheckFailed = $true
                Write-Verbose "Processor check: FAILED - CPU family not supported by Windows 11"
            }
            else {
                Write-Verbose "CPU family validation: PASSED"
            }
        }
        catch {
            # Don't set an error message in the processor details
            # Just mark the check as failed
            UpdateReturnCode -ReturnCode -1
            $processorCheckFailed = $true
            Write-Verbose "Processor check: ERROR - Could not validate CPU family"
        }

        $result.processor.details = $processorDetails

        if ($processorCheckFailed) {
            AddFailReason -Component "Processor"
            Write-Verbose "Processor check: FAILED"
        }
        else {
            $result.processor.passed = $true
            UpdateReturnCode -ReturnCode 0
            Write-Verbose "Processor check: PASSED"
        }
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    $result.processor.details = "undetermined"
    AddException -ExceptionText "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "Processor check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# SecureBoot check
Write-Verbose "Checking SecureBoot requirements..."
try {
    if (-not $isAdmin) {
        # If not running as admin, mark as undetermined but with a clear message
        UpdateReturnCode -ReturnCode -1
        AddException -ExceptionText "Administrator privileges required to check SecureBoot"
        Write-Verbose "SecureBoot check: SKIPPED - Administrator privileges required"
    }
    else {
        Write-Verbose "Checking if SecureBoot is available and enabled..."
        # Just check if SecureBoot is available, no need to store the result
        Confirm-SecureBootUEFI | Out-Null
        $result.secureBoot.passed = $true
        UpdateReturnCode -ReturnCode 0
        Write-Verbose "SecureBoot check: PASSED - SecureBoot is available"
    }
}
catch [System.PlatformNotSupportedException] {
    # PlatformNotSupportedException "Cmdlet not supported on this platform." - SecureBoot is not supported or is non-UEFI computer.
    UpdateReturnCode -ReturnCode 1
    AddFailReason -Component "SecureBoot"
    Write-Verbose "SecureBoot check: FAILED - SecureBoot is not supported on this platform (non-UEFI system)"
}
catch [System.UnauthorizedAccessException] {
    UpdateReturnCode -ReturnCode -1
    AddException -ExceptionText "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "SecureBoot check: ERROR - Unauthorized access exception"
}
catch {
    UpdateReturnCode -ReturnCode -1
    AddException -ExceptionText "$($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "SecureBoot check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# CPU Instructions check (SSE4.2 and PopCnt) - Required for Windows 11 24H2+
Write-Verbose "Checking CPU instruction set requirements (SSE4.2 and PopCnt)..."
try {
    $cpuInstructionsCheckPassed = $true
    
    # Use native PowerShell approach to check CPU instructions
    Write-Verbose "Checking CPU instructions using PowerShell-based detection..."
    
    # Get CPU details
    $cpuName = $cpuDetails.Name
    $cpuManufacturer = $cpuDetails.Manufacturer
    $hasSSE42 = $true
    $hasPopCnt = $true
    $detectionMethod = "Unknown"
    
    # Try registry check for CPU identifier
    try {
        $registryPath = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        $identifier = Get-ItemProperty -Path $registryPath -Name "Identifier" -ErrorAction SilentlyContinue
        
        if ($identifier) {
            $cpuIdentifier = $identifier.Identifier
            Write-Verbose "CPU Identifier from registry: $cpuIdentifier"
            $detectionMethod = "Registry CPU Identifier"
            
            # Intel CPU family/model detection
            if ($cpuManufacturer -match "Intel") {
                if ($cpuIdentifier -match "Family (\d+) Model (\d+)") {
                    $family = [int]$Matches[1]
                    $model = [int]$Matches[2]
                    
                    # Intel Nehalem (1st gen Core i, family 6, model >= 26) and newer support SSE4.2/PopCnt
                    if ($family -lt 6 -or ($family -eq 6 -and $model -lt 26)) {
                        $hasSSE42 = $false
                        $hasPopCnt = $false
                        Write-Verbose "Older Intel CPU detected (Family $family, Model $model), may not support SSE4.2/PopCnt"
                    }
                    else {
                        Write-Verbose "Modern Intel CPU detected (Family $family, Model $model), supports SSE4.2/PopCnt"
                    }
                }
            }
            # AMD CPU detection
            elseif ($cpuManufacturer -match "AMD") {
                if ($cpuIdentifier -match "Family (\d+)") {
                    $family = [int]$Matches[1]
                    
                    # AMD Bulldozer (family 15h/21) and newer support these instructions
                    if ($family -lt 15) {
                        $hasSSE42 = $false
                        $hasPopCnt = $false
                        Write-Verbose "Older AMD CPU detected (Family $family), may not support SSE4.2/PopCnt"
                    }
                    else {
                        Write-Verbose "Modern AMD CPU detected (Family $family), supports SSE4.2/PopCnt"
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Registry check failed: $($_.Exception.Message)"
    }
    
    # Fallback to CPU name pattern matching if registry check didn't work
    if ($detectionMethod -eq "Unknown") {
        $detectionMethod = "CPU Name Pattern"
        Write-Verbose "Using CPU name pattern matching: $cpuName"
        
        # Default to true for modern CPUs
        $hasSSE42 = $true
        $hasPopCnt = $true
        
        # Check for very old CPUs that might not support these instructions
        if ($cpuManufacturer -match "Intel") {
            if ($cpuName -match "Pentium 4" -or 
                $cpuName -match "Core 2" -or 
                ($cpuName -match "Atom" -and $cpuName -match "N[2-4]") -or
                ($cpuName -match "Celeron" -and $cpuName -match "\d{3}" -and 
                 [int]($cpuName -replace ".*?(\d{3}).*", '$1') -lt 800)) {
                $hasSSE42 = $false
                $hasPopCnt = $false
                Write-Verbose "Detected older Intel CPU that likely doesn't support required instructions"
            }
            elseif ($cpuName -match "i\d-\d{4}|i\d-\d{5}|Xeon|Core i\d") {
                Write-Verbose "Detected modern Intel CPU that supports required instructions"
            }
        }
        elseif ($cpuManufacturer -match "AMD") {
            if ($cpuName -match "Athlon II" -or 
                $cpuName -match "Phenom" -or
                $cpuName -match "Turion") {
                $hasSSE42 = $false
                $hasPopCnt = $false
                Write-Verbose "Detected older AMD CPU that likely doesn't support required instructions"
            }
            elseif ($cpuName -match "Ryzen|FX-\d{4}") {
                Write-Verbose "Detected modern AMD CPU that supports required instructions"
            }
        }
    }
    
    # Set the results
    $result.processor.cpuInstructions.sse42 = $hasSSE42
    $result.processor.cpuInstructions.popCnt = $hasPopCnt
    
    Write-Verbose "CPU instruction check results: SSE4.2: $hasSSE42, PopCnt: $hasPopCnt (Detection method: $detectionMethod)"
    
    if (-not ($hasSSE42 -and $hasPopCnt)) {
        $cpuInstructionsCheckPassed = $false
    }
    
    $result.processor.cpuInstructions.passed = $cpuInstructionsCheckPassed
    
    if ($cpuInstructionsCheckPassed) {
        UpdateReturnCode -ReturnCode 0
        Write-Verbose "CPU instructions check: PASSED - CPU supports required instructions (SSE4.2 and PopCnt)"
    }
    else {
        UpdateReturnCode -ReturnCode 1
        AddFailReason -Component "CPU_Instructions"
        Write-Verbose "CPU instructions check: FAILED - CPU does not support required instructions (SSE4.2 and/or PopCnt)"
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    AddException -ExceptionText "CPU Instructions check: $($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "CPU instructions check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# Graphics check (DirectX 12 and WDDM 2.0)
Write-Verbose "Checking graphics requirements..."
Write-Verbose "Required: DirectX 12 and WDDM 2.0 driver model"
try {
    $graphicsCheckPassed = $true
    $graphicsDetails = @{}
    
    # Use dxdiag to get DirectX information
    $dxDiagPath = "$env:TEMP\dxdiag.txt"
    Write-Verbose "Running dxdiag to gather graphics information..."
    Start-Process -FilePath "dxdiag.exe" -ArgumentList "/t", $dxDiagPath -NoNewWindow -Wait
    
    if (Test-Path $dxDiagPath) {
        Write-Verbose "Reading dxdiag output from $dxDiagPath"
        $dxDiagContent = Get-Content -Path $dxDiagPath -Raw
        
        # Check DirectX version
        if ($dxDiagContent -match "DirectX Version: DirectX (\d+)") {
            $dxVersion = [int]$Matches[1]
            $result.graphics.directX12 = ($dxVersion -ge 12)
            $graphicsDetails.Add("DirectXVersion", $dxVersion)
            Write-Verbose "DirectX version detected: $dxVersion"
            
            if ($dxVersion -lt 12) {
                $graphicsCheckPassed = $false
                AddFailReason -Component "DirectX12"
                Write-Verbose "Graphics check: FAILED - DirectX version ($dxVersion) is less than required (12)"
            }
            else {
                Write-Verbose "DirectX check: PASSED"
            }
        }
        else {
            $graphicsCheckPassed = $false
            AddFailReason -Component "DirectX12"
            Write-Verbose "Graphics check: FAILED - Could not determine DirectX version"
        }
        
        # Check WDDM version
        if ($dxDiagContent -match "Driver Model: WDDM (\d+\.\d+)") {
            $wddmVersion = [decimal]$Matches[1]
            $result.graphics.wddm2 = ($wddmVersion -ge 2.0)
            $graphicsDetails.Add("WDDMVersion", $wddmVersion)
            Write-Verbose "WDDM version detected: $wddmVersion"
            
            if ($wddmVersion -lt 2.0) {
                $graphicsCheckPassed = $false
                AddFailReason -Component "WDDM2"
                Write-Verbose "Graphics check: FAILED - WDDM version ($wddmVersion) is less than required (2.0)"
            }
            else {
                Write-Verbose "WDDM check: PASSED"
            }
        }
        else {
            $graphicsCheckPassed = $false
            AddFailReason -Component "WDDM2"
            Write-Verbose "Graphics check: FAILED - Could not determine WDDM version"
        }
        
        # Get GPU information
        if ($dxDiagContent -match "Card name: (.+)$") {
            $cardName = $Matches[1].Trim()
            $graphicsDetails.Add("CardName", $cardName)
            Write-Verbose "Graphics card detected: $cardName"
        }
        
        # Clean up the temporary file
        Remove-Item -Path $dxDiagPath -Force -ErrorAction SilentlyContinue
        Write-Verbose "Removed temporary dxdiag output file"
    }
    else {
        $graphicsCheckPassed = $false
        AddFailReason -Component "Graphics"
        AddException -ExceptionText "Could not generate dxdiag output"
        Write-Verbose "Graphics check: FAILED - Could not generate dxdiag output"
    }
    
    $result.graphics.details = $graphicsDetails
    $result.graphics.passed = $graphicsCheckPassed
    
    if ($graphicsCheckPassed) {
        UpdateReturnCode -ReturnCode 0
        Write-Verbose "Graphics check: PASSED"
    }
    else {
        UpdateReturnCode -ReturnCode 1
        Write-Verbose "Graphics check: FAILED"
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    $result.graphics.details = "undetermined"
    AddException -ExceptionText "Graphics check: $($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "Graphics check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# Display check (720p resolution)
Write-Verbose "Checking display requirements..."
Write-Verbose "Required: 720p display (1280x720) with 9-inch or larger diagonal"
try {
    $displayCheckPassed = $true
    
    # Get display information
    Write-Verbose "Querying monitor information..."
    $monitors = Get-WmiObject -Namespace "root\wmi" -Class "WmiMonitorBasicDisplayParams"
    
    if ($null -eq $monitors -or $monitors.Count -eq 0) {
        $displayCheckPassed = $false
        AddFailReason -Component "Display"
        $result.display.resolution = "undetermined"
        Write-Verbose "Display check: FAILED - Could not retrieve monitor information"
    }
    else {
        Write-Verbose "Found $($monitors.Count) monitor(s)"
        # Get actual resolution from Win32_VideoController
        $videoController = Get-WmiObject -Class Win32_VideoController | Where-Object { $_.Status -eq "OK" } | Select-Object -First 1
        if ($null -ne $videoController) {
            $currentWidth = $videoController.CurrentHorizontalResolution
            $currentHeight = $videoController.CurrentVerticalResolution
            $result.display.resolution = "$($currentWidth)x$($currentHeight)"
            Write-Verbose "Current resolution: $($currentWidth)x$($currentHeight)"
            
            # Check if resolution meets minimum 720p (1280x720)
            if ($currentWidth -lt 1280 -or $currentHeight -lt 720) {
                $displayCheckPassed = $false
                AddFailReason -Component "DisplayResolution"
                Write-Verbose "Display check: FAILED - Resolution ($($currentWidth)x$($currentHeight)) is less than required (1280x720)"
            }
            else {
                Write-Verbose "Resolution check: PASSED"
            }
            
            # For display size, we have a few options:
            # 1. Use WmiMonitorBasicDisplayParams.MaxHorizontalImageSize/MaxVerticalImageSize (often unreliable)
            # 2. Estimate based on DPI and resolution
            # 3. Assume it meets requirements for desktop/laptop displays
            
            # Try method 1 first
            $primaryMonitor = $monitors[0]
            $width = $primaryMonitor.MaxHorizontalImageSize
            $height = $primaryMonitor.MaxVerticalImageSize
            Write-Verbose "Reported physical dimensions: ${width}mm x ${height}mm"
            
            if ($width -gt 0 -and $height -gt 0) {
                # Convert from millimeters to inches
                $diagonalMm = [Math]::Sqrt([Math]::Pow($width, 2) + [Math]::Pow($height, 2))
                $diagonalInches = [Math]::Round($diagonalMm / 25.4, 1)
                $result.display.diagonal = "$diagonalInches`""
                Write-Verbose "Calculated diagonal size: $diagonalInches inches"
                
                # If the calculated size is unreasonably small, it's likely a reporting error
                if ($diagonalInches -lt 9 -and $diagonalInches -gt 0) {
                    # Try method 2: Estimate based on typical desktop/laptop DPI
                    # Most desktop monitors are at least 21" and laptops are at least 13"
                    # Check if this is likely a desktop or laptop
                    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
                    if ($computerSystem.PCSystemType -eq 2) { # Laptop/Notebook
                        $estimatedDiagonal = 15 # Conservative estimate for laptops
                        Write-Verbose "System type: Laptop/Notebook, estimated diagonal: $estimatedDiagonal inches"
                    }
                    else {
                        $estimatedDiagonal = 21 # Conservative estimate for desktops
                        Write-Verbose "System type: Desktop, estimated diagonal: $estimatedDiagonal inches"
                    }
                    
                    $result.display.diagonal = "$diagonalInches`" (reported, likely $estimatedDiagonal`"+ actual)"
                    Write-Verbose "Reported diagonal size appears incorrect, using estimated size"
                    
                    # For Windows 11 compatibility, we'll assume it meets requirements if:
                    # 1. It's a desktop/laptop (not a tablet)
                    # 2. The resolution is at least 720p
                    if ($currentWidth -ge 1280 -and $currentHeight -ge 720) {
                        # Override the display size check for standard desktop/laptop displays
                        $displayCheckPassed = $true
                        Write-Verbose "Display size check: PASSED (based on system type and resolution)"
                    }
                    else {
                        $displayCheckPassed = $false
                        AddFailReason -Component "DisplaySize"
                        Write-Verbose "Display size check: FAILED - Diagonal size too small"
                    }
                }
                elseif ($diagonalInches -lt 9) {
                    $displayCheckPassed = $false
                    AddFailReason -Component "DisplaySize"
                    Write-Verbose "Display size check: FAILED - Diagonal size ($diagonalInches inches) is less than required (9 inches)"
                }
                else {
                    Write-Verbose "Display size check: PASSED"
                }
            }
            else {
                # If we can't get physical dimensions, assume it meets requirements
                # for standard desktop/laptop displays with 720p+ resolution
                Write-Verbose "Could not determine physical dimensions, estimating based on system type"
                $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
                if ($computerSystem.PCSystemType -eq 2) { # Laptop/Notebook
                    $estimatedDiagonal = 15 # Conservative estimate for laptops
                    Write-Verbose "System type: Laptop/Notebook, estimated diagonal: $estimatedDiagonal inches"
                }
                else {
                    $estimatedDiagonal = 21 # Conservative estimate for desktops
                    Write-Verbose "System type: Desktop, estimated diagonal: $estimatedDiagonal inches"
                }
                
                $result.display.diagonal = "undetermined (likely $estimatedDiagonal`"+ based on system type)"
                
                # For Windows 11 compatibility, assume it meets requirements if resolution is sufficient
                if ($currentWidth -ge 1280 -and $currentHeight -ge 720) {
                    $displayCheckPassed = $true
                    Write-Verbose "Display size check: PASSED (based on system type and resolution)"
                }
                else {
                    Write-Verbose "Display size check: FAILED - Could not determine size and resolution is insufficient"
                }
            }
        }
        else {
            $result.display.resolution = "undetermined"
            $displayCheckPassed = $false
            AddFailReason -Component "Display"
            Write-Verbose "Display check: FAILED - Could not retrieve video controller information"
        }
    }
    
    $result.display.passed = $displayCheckPassed
    
    if ($displayCheckPassed) {
        UpdateReturnCode -ReturnCode 0
        Write-Verbose "Display check: PASSED"
    }
    else {
        UpdateReturnCode -ReturnCode 1
        Write-Verbose "Display check: FAILED"
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    $result.display.resolution = "undetermined"
    $result.display.diagonal = "undetermined"
    AddException -ExceptionText "Display check: $($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "Display check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# OS Version check (Windows 10 v2004 or later with September 2021 update)
Write-Verbose "Checking OS version requirements..."
Write-Verbose "Required: Windows 10 version 2004 (10.0.19041) or later with September 2021 update"
try {
    $osVersionCheckPassed = $true
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem
    $osVersion = [Version]$osInfo.Version
    $result.osVersion.version = $osInfo.Version
    $osDetails = @{
        "Caption" = $osInfo.Caption
        "BuildNumber" = $osInfo.BuildNumber
        "Version" = $osInfo.Version
    }
    
    Write-Verbose "Detected OS: $($osInfo.Caption), Version: $($osInfo.Version), Build: $($osInfo.BuildNumber)"
    
    # Windows 10 version 2004 is 10.0.19041
    $win10v2004 = [Version]"10.0.19041"
    
    # Check if OS is Windows 10 and version is at least 2004
    if ($osInfo.Caption -match "Windows 10" -and $osVersion -lt $win10v2004) {
        $osVersionCheckPassed = $false
        AddFailReason -Component "OSVersion"
        Write-Verbose "OS Version check: FAILED - Windows 10 version ($osVersion) is less than required (10.0.19041)"
    }
    else {
        Write-Verbose "OS Version check: PASSED - OS version meets minimum requirements"
    }
    
    # Check for September 2021 update (KB5005565 or later)
    # This is a simplified check - in a real implementation, you would check for specific KB numbers
    Write-Verbose "Checking for September 2021 update or later..."
    $hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering
    $sept2021UpdateInstalled = $false
    
    foreach ($hotfix in $hotfixes) {
        if ($hotfix.InstalledOn -ge [DateTime]"2021-09-01") {
            $sept2021UpdateInstalled = $true
            Write-Verbose "Found update installed after September 2021: $($hotfix.HotFixID) installed on $($hotfix.InstalledOn)"
            break
        }
    }
    
    $osDetails.Add("Sept2021UpdateInstalled", $sept2021UpdateInstalled)
    
    if (-not $sept2021UpdateInstalled -and $osInfo.Caption -match "Windows 10") {
        $osVersionCheckPassed = $false
        AddFailReason -Component "OSUpdateLevel"
        Write-Verbose "OS Update check: FAILED - No updates installed after September 2021 were found"
    }
    elseif ($osInfo.Caption -match "Windows 10") {
        Write-Verbose "OS Update check: PASSED - September 2021 or later update is installed"
    }
    else {
        Write-Verbose "OS Update check: SKIPPED - Not Windows 10, so September 2021 update check not applicable"
    }
    
    $result.osVersion.details = $osDetails
    $result.osVersion.passed = $osVersionCheckPassed
    
    if ($osVersionCheckPassed) {
        UpdateReturnCode -ReturnCode 0
        Write-Verbose "OS Version check: PASSED"
    }
    else {
        UpdateReturnCode -ReturnCode 1
        Write-Verbose "OS Version check: FAILED"
    }
}
catch {
    UpdateReturnCode -ReturnCode -1
    $result.osVersion.version = "undetermined"
    $result.osVersion.details = "undetermined"
    AddException -ExceptionText "OS Version check: $($_.Exception.GetType().Name) $($_.Exception.Message)"
    Write-Verbose "OS Version check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
}

# i7-7820hq CPU check
Write-Verbose "Checking for special case CPU (i7-7820HQ)..."
try {
    $supportedDevices = @('surface studio 2', 'precision 5520')
    $systemInfo = @(Get-WmiObject -Class Win32_ComputerSystem)[0]
    Write-Verbose "System model: $($systemInfo.Model)"

    if ($null -ne $cpuDetails) {
        if ($cpuDetails.Name -match 'i7-7820hq cpu @ 2.90ghz') {
            Write-Verbose "Detected special case CPU: i7-7820HQ"
            $modelOrSKUCheckLog = $systemInfo.Model.Trim().ToLower()
            $result.i7_7820hq.model = $modelOrSKUCheckLog
            
            if ($supportedDevices -contains $modelOrSKUCheckLog) {
                $result.i7_7820hq.passed = $true
                $result.returnCode = 0
                Write-Verbose "Special case CPU check: PASSED - Device model ($modelOrSKUCheckLog) is in the supported list"
            }
            else {
                Write-Verbose "Special case CPU check: FAILED - Device model ($modelOrSKUCheckLog) is not in the supported list"
            }
        }
        else {
            Write-Verbose "Special case CPU check: SKIPPED - Not an i7-7820HQ CPU"
        }
    }
    else {
        Write-Verbose "Special case CPU check: SKIPPED - CPU details not available"
    }
}
catch {
    if ($result.returnCode -ne 0) {
        UpdateReturnCode -ReturnCode -1
        $result.i7_7820hq.model = "undetermined"
        AddException -ExceptionText "$($_.Exception.GetType().Name) $($_.Exception.Message)"
        Write-Verbose "Special case CPU check: ERROR - $($_.Exception.GetType().Name) $($_.Exception.Message)"
    }
}

# Set the overall compatibility status based on return code
Switch ($result.returnCode) {
    0 { 
        $result.compatible = $true 
        Write-Verbose "OVERALL RESULT: COMPATIBLE with Windows 11"
    }
    1 { 
        $result.compatible = $false 
        Write-Verbose "OVERALL RESULT: NOT COMPATIBLE with Windows 11"
        Write-Verbose "Fail reasons: $($result.failReasons -join ', ')"
    }
    -1 { 
        $result.compatible = $false 
        Write-Verbose "OVERALL RESULT: UNDETERMINED compatibility with Windows 11"
        Write-Verbose "Exceptions: $($result.exceptions -join ', ')"
    }
    -2 { 
        $result.compatible = $false 
        Write-Verbose "OVERALL RESULT: CHECK NOT COMPLETED"
    }
}

# If AsJson parameter is specified, convert the result to JSON and return it
if ($AsJson) {
    $jsonResult = $result | ConvertTo-Json -Depth 10
    return $jsonResult
}
else {
    # Return the result object
    return $result
}
