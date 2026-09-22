# WER ALPC Port Enumerator
# Scans \RPC Control and \BaseNamedObjects for the WerSvc ALPC endpoint

$signature = @"
using System;
using System.Runtime.InteropServices;

public class AlpcEnum {
    [DllImport("ntdll.dll")]
    public static extern uint NtQueryDirectoryObject(
        IntPtr Handle,
        IntPtr Buffer,
        uint Length,
        bool ReturnSingleEntry,
        uint Index,
        ref uint Context,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern uint NtOpenDirectoryObject(
        out IntPtr Handle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryObject(
        IntPtr Handle,
        uint ObjectInformationClass,
        IntPtr Buffer,
        uint Length,
        out uint ReturnLength);

    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)]
    public static extern uint NtOpenSymbolicLinkObject(
        out IntPtr Handle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJDIR_INFORMATION {
        public OBJDIR_INFORMATION Next;
        public uint Index;
        public uint NameType;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)]
        public string Name;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)]
        public string Type;
    }
}
"@

Add-Type -TypeDefinition $signature

# Method 1: Scan directory objects for ALPC ports
function Scan-DirectoryObject {
    param([string]$Path, [IntPtr]$Root = [IntPtr]::Zero)

    $oa = New-Object AlpcEnum+OBJECT_ATTRIBUTES
    $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
    $oa.Attributes = 0x40 # OBJ_CASE_INSENSITIVE

    $uni = New-Object AlpcEnum+UNICODE_STRING
    $uni.Length = [System.Runtime.InteropServices.Marshal]::SizeOf([type][uint16]) * $Path.Length
    $uni.MaximumLength = $uni.Length + 2
    $uni.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Path)
    $oa.ObjectName = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($uni))
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($uni, $oa.ObjectName, $false)

    $hDir = [IntPtr]::Zero
    $status = [AlpcEnum]::NtOpenDirectoryObject([ref]$hDir, 0x3, [ref]$oa)

    if ($status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($uni.Buffer)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($oa.ObjectName)
        return
    }

    $bufSize = 0x10000
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufSize)
    $ctx = [uint32]0
    $retLen = [uint32]0

    do {
        $status = [AlpcEnum]::NtQueryDirectoryObject($hDir, $buf, $bufSize, $false, 0, [ref]$ctx, [ref]$retLen)
        if ($status -ne 0 -and $status -ne 0x80000005) { break }

        $offset = $buf.ToInt64()
        while ($offset -ne 0) {
            $entry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($offset, [type][AlpcEnum+OBJDIR_INFORMATION])
            $name = $entry.Name
            $type = $entry.Type

            if ($type -eq "ALPC Port" -or $type -eq "Port") {
                if ($name -match "Wer" -or $name -match "Error" -or $name -match "Reporting") {
                    Write-Host "[+] FOUND: \$Path\$name (Type: $type)" -ForegroundColor Green
                }
            }

            if ($type -eq "Directory") {
                Write-Host "[*] Subdir: \$Path\$name" -ForegroundColor Cyan
                Scan-DirectoryObject -Path "$Path\$name"
            }

            $offset = if ($entry.Next -ne $null) { $entry.Next.ToInt64() } else { 0 }
        }
    } while ($status -eq 0x80000005)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($uni.Buffer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($oa.ObjectName)
}

# Method 2: Scan wersvc.dll for embedded port name string
function Scan-WerSvcBinary {
    $wersvcPath = Join-Path $env:WINDIR "System32\wersvc.dll"
    if (-not (Test-Path $wersvcPath)) {
        Write-Host "[-] wersvc.dll not found" -ForegroundColor Red
        return
    }

    $bytes = [System.IO.File]::ReadAllBytes($wersvcPath)
    $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
    $unicode = [System.Text.Encoding]::Unicode.GetString($bytes)

    # Look for ALPC port name patterns
    $patterns = @(
        "WindowsErrorReporting",
        "WerSvcPort",
        "WerPort",
        "WerAlpc",
        "ErrorReportingPort",
        "WerFaultPort",
        "WER_",
        "WindowsError"
    )

    Write-Host "`n[*] Scanning wersvc.dll for embedded port strings..." -ForegroundColor Yellow

    foreach ($pat in $patterns) {
        $idx = 0
        while (($idx = $ascii.IndexOf($pat, $idx)) -ge 0) {
            $context = $ascii.Substring([Math]::Max(0, $idx - 20), [Math]::Min(80, $ascii.Length - [Math]::Max(0, $idx - 20)))
            $clean = ($context -replace '[^\x20-\x7E]', '.').Trim()
            Write-Host "[+] ASCII match '$pat' at offset 0x$($idx.ToString('X')): $clean" -ForegroundColor Green
            $idx++
        }

        $uIdx = 0
        while (($uIdx = $unicode.IndexOf($pat, $uIdx)) -ge 0) {
            $start = [Math]::Max(0, $uIdx - 10)
            $len = [Math]::Min(60, $unicode.Length - $start)
            $context = $unicode.Substring($start, $len)
            $clean = ($context -replace '[^\x20-\x7E]', '.').Trim()
            Write-Host "[+] UNICODE match '$pat' at char offset $uIdx`: $clean" -ForegroundColor Green
            $uIdx++
        }
    }

    # Extract wide strings near "Port" keyword
    $portIdx = 0
    while (($portIdx = $unicode.IndexOf("Port", $portIdx)) -ge 0) {
        $start = [Math]::Max(0, $portIdx - 30)
        $len = [Math]::Min(50, $unicode.Length - $start)
        $ctx = $unicode.Substring($start, $len)
        $clean = ($ctx -replace '[^\x20-\x7E]', '').Trim()
        if ($clean.Length -gt 2) {
            Write-Host "[?] Wide string near 'Port': $clean" -ForegroundColor Magenta
        }
        $portIdx++
    }
}

# Method 3: Inspect WerSvc service for ALPC creation via ETW or handle table
function Get-WerSvcAlpcHandles {
    $proc = Get-Process -Name "WerSvc" -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Host "[-] WerSvc not running" -ForegroundColor Red
        return
    }

    Write-Host "`n[*] WerSvc PID: $($proc.Id)" -ForegroundColor Yellow
    Write-Host "[*] Scanning handle table for ALPC port objects..." -ForegroundColor Yellow

    # Use NtQuerySystemInformation with SystemHandleInformation
    $ntdll = Add-Type -Name "NtQuery" -Namespace "Win32" -PassThru -MemberDefinition @"
    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(
        uint SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);
"@

    $size = 0x100000
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    $retLen = [uint32]0

    # SystemHandleInformation = 16, SystemExtendedHandleInformation = 64
    $status = $ntdll::NtQuerySystemInformation(64, $ptr, $size, [ref]$retLen)

    if ($status -eq 0xC0000004) {
        # Buffer too small, resize
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        $size = $retLen
        $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
        $status = $ntdll::NtQuerySystemInformation(64, $ptr, $size, [ref]$retLen)
    }

    if ($status -ne 0) {
        Write-Host "[-] NtQuerySystemInformation failed: 0x$($status.ToString('X'))" -ForegroundColor Red
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        return
    }

    # Parse SYSTEM_HANDLE_INFORMATION_EX
    $count = [System.Runtime.InteropServices.Marshal]::ReadInt64($ptr)
    Write-Host "[*] Total system handles: $count" -ForegroundColor Cyan

    $entrySize = 32  # sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX) on x64
    $baseOffset = $ptr.ToInt64() + 8

    $alpcTypeIndex = -1

    # First pass: find the ALPC Port type index by checking WerSvc's handles
    for ($i = 0; $i -lt $count; $i++) {
        $offset = $baseOffset + ($i * $entrySize)
        $obj = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($offset)
        $pid = [System.Runtime.InteropServices.Marshal]::ReadInt32($offset + 8)
        $handleVal = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($offset + 12)
        $typeIdx = [System.Runtime.InteropServices.Marshal]::ReadInt32($offset + 20)

        if ($pid -eq $proc.Id) {
            # Query object type
            $typeBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x100)
            $tLen = [uint32]0
            $qStatus = [AlpcEnum]::NtQueryObject($handleVal, 2, $typeBuf, 0x100, [ref]$tLen)

            if ($qStatus -eq 0) {
                # ObjectTypeInformation class = 2
                $typeNameLen = [System.Runtime.InteropServices.Marshal]::ReadUInt16($typeBuf)
                $typeNameBuf = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($typeBuf, 16)
                $typeName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($typeNameBuf, $typeNameLen / 2)

                if ($typeName -match "ALPC" -or $typeName -match "Port") {
                    Write-Host "[+] WerSvc handle 0x$($handleVal.ToString('X')) is type: $typeName (TypeIdx: $typeIdx)" -ForegroundColor Green
                    $alpcTypeIndex = $typeIdx
                }
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($typeBuf)
        }
    }

    if ($alpcTypeIndex -ge 0) {
        Write-Host "`n[+] ALPC Type Index: $alpcTypeIndex" -ForegroundColor Green
        Write-Host "[*] All handles of this type in WerSvc:" -ForegroundColor Yellow

        for ($i = 0; $i -lt $count; $i++) {
            $offset = $baseOffset + ($i * $entrySize)
            $pid = [System.Runtime.InteropServices.Marshal]::ReadInt32($offset + 8)
            $handleVal = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($offset + 12)
            $typeIdx = [System.Runtime.InteropServices.Marshal]::ReadInt32($offset + 20)

            if ($pid -eq $proc.Id -and $typeIdx -eq $alpcTypeIndex) {
                # Query object name
                $nameBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x1000)
                $nLen = [uint32]0
                $nStatus = [AlpcEnum]::NtQueryObject($handleVal, 1, $nameBuf, 0x1000, [ref]$nLen)

                if ($nStatus -eq 0) {
                    $nameLen = [System.Runtime.InteropServices.Marshal]::ReadUInt16($nameBuf)
                    $namePtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($nameBuf, 16)
                    $objName = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($namePtr, $nameLen / 2)
                    Write-Host "    Handle 0x$($handleVal.ToString('X')): $objName" -ForegroundColor Green
                } else {
                    Write-Host "    Handle 0x$($handleVal.ToString('X')): (name query failed)" -ForegroundColor Yellow
                }
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($nameBuf)
            }
        }
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
}

# Method 4: Brute-force common naming patterns via NtAlpcConnectPort
function Try-AlpcConnect {
    param([string[]]$PortNames)

    $connectSig = @"
using System;
using System.Runtime.InteropServices;

public class AlpcConnect {
    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)]
    public static extern uint NtAlpcConnectPort(
        out IntPtr PortHandle,
        IntPtr PortName,
        IntPtr ObjectAttributes,
        IntPtr PortAttributes,
        IntPtr SectionHandle,
        IntPtr ConnectionInfo,
        ref uint ConnectionInfoLength,
        IntPtr Timeout,
        IntPtr ConnectionMessage,
        ref uint ConnectionMessageLength);

    [DllImport("ntdll.dll", CharSet=CharSet.Unicode)]
    public static extern uint NtAlpcConnectPortEx(
        out IntPtr PortHandle,
        IntPtr ConnectionPort,
        IntPtr PortName,
        IntPtr PortAttributes,
        IntPtr SectionHandle,
        IntPtr ConnectionInfo,
        ref uint ConnectionInfoLength,
        IntPtr Timeout,
        IntPtr ConnectionMessage,
        ref uint ConnectionMessageLength);

    [DllImport("ntdll.dll")]
    public static extern uint NtClose(IntPtr Handle);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ALPC_PORT_ATTRIBUTES {
        public uint Flags;
        public uint MaxMessageLength;
        public uint MaxPoolUsage;
        public uint MaxSectionSize;
        public uint MaxViewSize;
        public uint MaxTotalSectionSize;
        public uint DupObjectTypes;
        public uint Reserved;
    }
}
"@

    Add-Type -TypeDefinition $connectSig -ErrorAction SilentlyContinue

    $candidates = @(
        "\WindowsErrorReportingServicePort",
        "\WindowsErrorReportingService",
        "\WerSvcPort",
        "\WerSvc",
        "\WindowsErrorReporting",
        "\ErrorReportingPort",
        "\WerFaultPort",
        "\WerPort",
        "\RPC Control\WindowsErrorReportingServicePort",
        "\RPC Control\WerSvcPort",
        "\RPC Control\WindowsErrorReporting",
        "\RPC Control\WerSvc",
        "\RPC Control\WerPort",
        "\RPC Control\ErrorReportingPort",
        "\BaseNamedObjects\WindowsErrorReportingServicePort",
        "\BaseNamedObjects\WerSvcPort",
        "\BaseNamedObjects\WerPort",
        "\BaseNamedObjects\WindowsErrorReporting",
        "\BaseNamedObjects\WerSvc"
    )

    Write-Host "`n[*] Attempting NtAlpcConnectPort against $($candidates.Count) candidates..." -ForegroundColor Yellow

    foreach ($port in $candidates) {
        $uni = New-Object AlpcConnect+UNICODE_STRING
        $uni.Length = [System.Runtime.InteropServices.Marshal]::SizeOf([type][uint16]) * $port.Length
        $uni.MaximumLength = $uni.Length + 2
        $uni.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($port)
        $uniPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($uni))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($uni, $uniPtr, $false)

        $oa = New-Object AlpcConnect+OBJECT_ATTRIBUTES
        $oa.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($oa)
        $oa.ObjectName = $uniPtr
        $oa.Attributes = 0x40

        $oaPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($oa.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($oa, $oaPtr, $false)

        $portAttr = New-Object AlpcConnect+ALPC_PORT_ATTRIBUTES
        $portAttr.MaxMessageLength = 0x600
        $portAttrPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf($portAttr))
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($portAttr, $portAttrPtr, $false)

        $hPort = [IntPtr]::Zero
        $connInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(0x100)
        $connInfoLen = [uint32]0x100

        $status = [AlpcConnect]::NtAlpcConnectPort(
            [ref]$hPort,
            $uniPtr,
            $oaPtr,
            $portAttrPtr,
            [IntPtr]::Zero,
            $connInfo,
            [ref]$connInfoLen,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [ref]$connInfoLen
        )

        if ($status -eq 0 -and $hPort -ne [IntPtr]::Zero) {
            Write-Host "[+] CONNECTED: $port (Handle: 0x$($hPort.ToString('X')))" -ForegroundColor Green
            [AlpcConnect]::NtClose($hPort) | Out-Null
        } elseif ($status -eq 0xC0000034) {
            # STATUS_OBJECT_NAME_NOT_FOUND
            Write-Host "[-] Not found: $port" -ForegroundColor DarkGray
        } elseif ($status -eq 0xC0000022) {
            # STATUS_ACCESS_DENIED - port exists but we can't connect
            Write-Host "[!] EXISTS (access denied): $port (0x$($status.ToString('X')))" -ForegroundColor Yellow
        } else {
            Write-Host "[?] $port -> 0x$($status.ToString('X'))" -ForegroundColor Magenta
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($uni.Buffer)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($uniPtr)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($oaPtr)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($portAttrPtr)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($connInfo)
    }
}

# Main execution
Write-Host "=== WER ALPC Port Enumerator ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1] Scanning \RPC Control..." -ForegroundColor Yellow
Scan-DirectoryObject -Path "RPC Control"

Write-Host "`n[2] Scanning \BaseNamedObjects..." -ForegroundColor Yellow
Scan-DirectoryObject -Path "BaseNamedObjects"

Write-Host "`n[3] Scanning wersvc.dll binary..." -ForegroundColor Yellow
Scan-WerSvcBinary

Write-Host "`n[4] Inspecting WerSvc handle table..." -ForegroundColor Yellow
Get-WerSvcAlpcHandles

Write-Host "`n[5] Brute-force ALPC connection attempts..." -ForegroundColor Yellow
Try-AlpcConnect

Write-Host "`n[*] Enumeration complete." -ForegroundColor Cyan