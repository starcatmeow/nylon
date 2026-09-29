param(
    [Parameter(Mandatory = $true)][string]$DllPath,
    [Parameter(Mandatory = $true)][string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$ResultPath = [IO.Path]::GetFullPath($ResultPath)
$diagnosticsDir = Split-Path -Parent $ResultPath
New-Item -ItemType Directory -Force $diagnosticsDir | Out-Null

function Save-Diagnostics([string]$Phase) {
    # Missing services/logs are diagnostic evidence, not a reason to lose the probe result.
    $report = Join-Path $diagnosticsDir "system-$Phase.txt"
    "Captured at $([DateTime]::UtcNow.ToString('o'))" | Set-Content $report -Encoding UTF8
    foreach ($service in @('PlugPlay', 'DeviceInstall', 'DsmSvc', 'RpcSs', 'wintun')) {
        foreach ($operation in @('query', 'qc')) {
            "`n> sc.exe $operation $service" | Add-Content $report -Encoding UTF8
            & sc.exe $operation $service 2>&1 | Out-File $report -Append -Encoding UTF8
            "Exit code: $LASTEXITCODE" | Add-Content $report -Encoding UTF8
        }
    }
    & whoami.exe /all 2>&1 | Out-File $report -Append -Encoding UTF8
    foreach ($log in @('setupapi.dev.log', 'setupapi.app.log')) {
        $source = Join-Path $env:windir "INF\$log"
        try {
            Copy-Item -LiteralPath $source -Destination (Join-Path $diagnosticsDir "$Phase-$log")
        } catch {
            "Could not copy ${source}: $_" | Add-Content $report -Encoding UTF8
        }
    }
}

try { Save-Diagnostics 'before' } catch { Write-Warning "Pre-probe diagnostics: $_" }
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
$loggerEnabled = $false

try {
    if (-not [Environment]::Is64BitProcess) { throw 'The amd64 DLL requires a 64-bit process' }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
public static class WintunProbe {
    // Wintun can call its logger from native worker threads without a PowerShell runspace.
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    public delegate void LoggerCallback(int level, ulong timestamp, string message);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate void SetLogger(LoggerCallback callback);
    private static readonly object LogLock = new object();
    private static readonly LoggerCallback Callback = Log;
    private static StreamWriter LogFile;
    public static void EnableLogger(SetLogger setter, string path) {
        LogFile = new StreamWriter(path, false, System.Text.Encoding.UTF8);
        LogFile.AutoFlush = true;
        setter(Callback); // Keep the delegate rooted for the lifetime of native callbacks.
    }
    private static void Log(int level, ulong timestamp, string message) {
        // Never allow a managed exception to cross the native callback boundary.
        try {
            lock (LogLock) {
                if (LogFile != null)
                    LogFile.WriteLine("{0:o} level={1} {2}", DateTime.FromFileTimeUtc((long)timestamp), level, message);
            }
        } catch { }
    }
    public static void DisableLogger(SetLogger setter) {
        setter(null);
        lock (LogLock) {
            if (LogFile != null) LogFile.Dispose();
            LogFile = null;
        }
    }
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
    $setLogger = [WintunProbe]::Export($library, 'WintunSetLogger', [WintunProbe+SetLogger])
    [WintunProbe]::EnableLogger($setLogger, (Join-Path $diagnosticsDir 'wintun.log'))
    $loggerEnabled = $true
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
        $result.errorHex = '0x{0:X8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$exception.NativeErrorCode), 0)
        $result.errorDescription = [ComponentModel.Win32Exception]::new($exception.NativeErrorCode).Message
    }
    Write-Host "FAIL at ${stage}: $($result.error)"
} finally {
    try {
        if ($session -ne [IntPtr]::Zero) { $end.Invoke($session) }
        if ($adapter -ne [IntPtr]::Zero) { $close.Invoke($adapter) }
    } catch { $result.cleanupError = "$_" }
    try {
        if ($loggerEnabled) { [WintunProbe]::DisableLogger($setLogger) }
        if ($library -ne [IntPtr]::Zero) { [void][WintunProbe]::FreeLibrary($library) }
    } catch { $result.loggerCleanupError = "$_" }
    $json = $result | ConvertTo-Json
    $json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
    Write-Host $json
    try { Save-Diagnostics 'after' } catch { Write-Warning "Post-probe diagnostics: $_" }
    if (Test-Path (Join-Path $diagnosticsDir 'wintun.log')) {
        Write-Host '--- Wintun internal log ---'
        Get-Content (Join-Path $diagnosticsDir 'wintun.log') | ForEach-Object { Write-Host $_ }
    }
}

if ($result.failedStage) { exit 1 }
