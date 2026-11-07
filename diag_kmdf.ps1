$ErrorActionPreference = 'Continue'
function L($t) { Write-Host $t }

L '=== KMDF RUNTIME INSTALLED ==='
foreach ($p in 'C:\Windows\System32\drivers\Wdf01000.sys','C:\Windows\System32\drivers\wdfldr.sys') {
    if (Test-Path -LiteralPath $p) {
        $v = (Get-Item -LiteralPath $p).VersionInfo
        L ('  ' + $p)
        L ('    FileVersion    = ' + $v.FileVersion)
        L ('    ProductVersion = ' + $v.ProductVersion)
        L ('    ProductName    = ' + $v.ProductName)
    } else { L ('  MISSING: ' + $p) }
}

L ''
L '=== WDF KMDF LIB VERSIONS PRESENT ON DISK ==='
$base = 'C:\Program Files (x86)\Windows Kits\10\Lib'
if (Test-Path $base) {
    Get-ChildItem $base -Directory | ForEach-Object { L ('  SDK Lib: ' + $_.Name) }
    $wl = Join-Path $base 'wdf\kmdf\x64'
    if (Test-Path $wl) {
        $vers = (Get-ChildItem $wl -Directory | Select-Object -ExpandProperty Name) -join ', '
        L ('  kmdf x64 available: ' + $vers)
    } else { L ('  NOT FOUND: ' + $wl) }
    $wi = Join-Path $base 'wdf\kmdf\Include'
    if (Test-Path $wi) { L ('  kmdf Include ver : ' + ((Get-ChildItem $wi -Directory | Select-Object -ExpandProperty Name) -join ', ')) }
} else { L ('  NOT FOUND: ' + $base) }

L ''
L '=== WDK INCLUDE ROOTS ==='
$inc = 'C:\Program Files (x86)\Windows Kits\10\Include'
if (Test-Path $inc) {
    Get-ChildItem $inc -Directory | ForEach-Object { L ('  ' + $_.Name) }
    $w = Join-Path $inc 'wdf'
    if (Test-Path $w) { L ('  wdf present: yes') } else { L '  wdf present: NO' }
} else { L ('  NOT FOUND: ' + $inc) }

L ''
L '=== OS BUILD ==='
$os = Get-CimInstance Win32_OperatingSystem
$ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
L ('  ' + $os.Caption + ' | ' + $os.BuildNumber + '.' + $ubr + ' | ' + $os.OSArchitecture)

L ''
L '=== WDF RUNTIME REGISTRY ==='
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF',
               'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WDF',
               'HKLM:\SYSTEM\CurrentControlSet\Services\Wdf01000') {
    if (Test-Path $k) {
        L ('  KEY: ' + $k)
        Get-ChildItem $k -Recurse -ErrorAction SilentlyContinue | ForEach-Object { L ('    sub: ' + $_.Name) }
        (Get-ItemProperty $k) | Out-String -Width 200 | ForEach-Object { $_.Trim() -split "`r|`n" } | Where-Object { $_ } | ForEach-Object { L ('    ' + $_) }
    } else { L ('  absent: ' + $k) }
}

L ''
L '=== Wdf01000 / wdfldr SERVICE STATE ==='
foreach ($n in 'Wdf01000','wdfldr','WUDFPf') {
    $r = & sc.exe query $n 2>&1 | Out-String
    L ('  ' + $n + ' -> ' + (($r -replace "`r|`n", ' | ').Trim()))
}

L ''
L '=== KMDF VERSION BINDING DEBUG (WdfLdr trace) ==='
$log = 'C:\Windows\INF\setupapi.dev.log'
if (Test-Path $log) {
    $tail = Select-String -Path $log -Pattern 'AntiCheatDriver|Wdf|wdfldr|0x57|87' -ErrorAction SilentlyContinue |
            Select-Object -Last 20
    if ($tail) { $tail | ForEach-Object { L ('  ' + $_.Line.Trim()) } } else { L '  no KMDF-related entries' }
} else { L '  setupapi.dev.log absent' }
