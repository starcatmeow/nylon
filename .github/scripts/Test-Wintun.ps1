param(
    [Parameter(Mandatory = $true)][string]$DllPath,
    [Parameter(Mandatory = $true)][string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$result = [ordered]@{
    os = [Environment]::OSVersion.VersionString
    process64Bit = [Environment]::Is64BitProcess
    identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    dllLoad = 'not attempted'
    createAdapter = 'not attempted'
    driverVersion = $null
    startSession = 'not attempted'
    failedStage = $null
    error = $null
}
$library = [IntPtr]::Zero
$adapter = [IntPtr]::Zero
$session = [IntPtr]::Zero
$stage = 'setup'

try {
    if (-not [Environment]::Is64BitProcess) { throw 'The amd64 DLL requires a 64-bit process' }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class WintunProbe {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryExW(string name, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr module);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate IntPtr CreateAdapter(string name, string tunnelType, IntPtr guid);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void CloseAdapter(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    public delegate uint GetRunningDriverVersion();
    [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
    public delegate IntPtr StartSession(IntPtr adapter, uint capacity);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void EndSession(IntPtr session);
    public static Delegate Export(IntPtr module, string name, Type type) {
        IntPtr address = GetProcAddress(module, name);
        if (address == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), name);
        return Marshal.GetDelegateForFunctionPointer(address, type);
    }
    public static void CheckHandle(IntPtr value, string operation) {
        if (value == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), operation);
    }
}
'@
    $stage = 'dllLoad'
    # Restrict dependencies to the DLL directory and System32.
    $library = [WintunProbe]::LoadLibraryExW((Resolve-Path $DllPath).Path, [IntPtr]::Zero, 0x900)
    [WintunProbe]::CheckHandle($library, 'LoadLibraryExW')
    $result.dllLoad = 'passed'
    Write-Host 'PASS: LoadLibraryExW(wintun.dll)'

    $stage = 'resolveExports'
    $create = [WintunProbe]::Export($library, 'WintunCreateAdapter', [WintunProbe+CreateAdapter])
    $close = [WintunProbe]::Export($library, 'WintunCloseAdapter', [WintunProbe+CloseAdapter])
    $version = [WintunProbe]::Export($library, 'WintunGetRunningDriverVersion', [WintunProbe+GetRunningDriverVersion])
    $start = [WintunProbe]::Export($library, 'WintunStartSession', [WintunProbe+StartSession])
    $end = [WintunProbe]::Export($library, 'WintunEndSession', [WintunProbe+EndSession])

    $stage = 'createAdapter'
    $adapter = $create.Invoke('NylonProbe', 'Nylon', [IntPtr]::Zero)
    [WintunProbe]::CheckHandle($adapter, 'WintunCreateAdapter')
    $result.createAdapter = 'passed'
    Write-Host 'PASS: WintunCreateAdapter (driver initialization)'

    $stage = 'driverVersion'
    $driverVersion = $version.Invoke()
    if ($driverVersion -eq 0) {
        throw [ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $result.driverVersion = '{0}.{1}' -f ($driverVersion -shr 16), ($driverVersion -band 0xffff)

    $stage = 'startSession'
    $session = $start.Invoke($adapter, 0x400000)
    [WintunProbe]::CheckHandle($session, 'WintunStartSession')
    $result.startSession = 'passed'
    Write-Host 'PASS: WintunStartSession'
} catch {
    $result.failedStage = $stage
    if ($result.Contains($stage)) { $result[$stage] = 'failed' }
    $exception = $_.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    $result.error = $exception.Message
    if ($exception -is [ComponentModel.Win32Exception]) {
        $result.errorCode = $exception.NativeErrorCode
    }
    Write-Host "FAIL at ${stage}: $($result.error)"
} finally {
    if ($session -ne [IntPtr]::Zero) { $end.Invoke($session) }
    if ($adapter -ne [IntPtr]::Zero) { $close.Invoke($adapter) }
    if ($library -ne [IntPtr]::Zero) { [void][WintunProbe]::FreeLibrary($library) }
    $json = $result | ConvertTo-Json
    $json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    Write-Host $json
}

if ($result.failedStage) { exit 1 }
