$ErrorActionPreference = 'Continue'
function L($t) { Write-Host $t }

L '=== WDF KMDF LIB VERSIONS ON DISK ==='
$wdfRoot = 'C:\Program Files (x86)\Windows Kits\10\Lib\wdf\kmdf\x64'
if (Test-Path -LiteralPath $wdfRoot) {
    Get-ChildItem -LiteralPath $wdfRoot -Directory | ForEach-Object {
        $de = Join-Path $_.FullName 'wdfdriverentry.lib'
        $dl = Join-Path $_.FullName 'wdfldr.lib'
        $se = if (Test-Path -LiteralPath $de) { (Get-Item -LiteralPath $de).Length } else { 'MISSING' }
        $sl = if (Test-Path -LiteralPath $dl) { (Get-Item -LiteralPath $dl).Length } else { 'MISSING' }
        L ('  v' + $_.Name + '  wdfdriverentry.lib=' + $se + '  wdfldr.lib=' + $sl)
    }
} else { L ('  NOT FOUND: ' + $wdfRoot) }

L ''
L '=== HOST KMDF RUNTIME VERSION ==='
$wdf = 'C:\Windows\System32\drivers\Wdf01000.sys'
if (Test-Path -LiteralPath $wdf) {
    $vi = (Get-Item -LiteralPath $wdf).VersionInfo
    L ('  Wdf01000.sys FileVersion = ' + $vi.FileVersion)
    L ('  Wdf01000.sys ProdVersion = ' + $vi.ProductVersion)
}
$wl = 'C:\Windows\System32\drivers\wdfldr.sys'
if (Test-Path -LiteralPath $wl) {
    L ('  wdfldr.sys   FileVersion = ' + (Get-Item -LiteralPath $wl).VersionInfo.FileVersion)
}
$path = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue)
L ('  OS Build = ' + $path.CurrentBuildNumber + '.' + $path.UBR + '  (' + $path.DisplayVersion + ')')

L ''
L '=== SERVICE CONFIG ==='
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\AntiCheatDriver'
if (Test-Path $key) {
    $p = Get-ItemProperty $key
    foreach ($n in 'ImagePath','Start','Type','ErrorControl','DisplayName','Group','ObjectName') {
        L ('  ' + $n.PadRight(13) + ' = ' + $p.$n)
    }
    L ('  Params subkey: ' + (Test-Path (Join-Path $key 'Parameters')))
} else { L '  SERVICE KEY ABSENT' }

L ''
L '=== IMAGEPATH TARGET RESOLUTION ==='
$raw = (Get-ItemProperty $key -ErrorAction SilentlyContinue).ImagePath
if ($raw) {
    $clean = $raw -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\','C:\Windows\' -replace '^system32\\','C:\Windows\system32\'
    L ('  resolved  : ' + $clean)
    L ('  exists    : ' + (Test-Path -LiteralPath $clean))
    if (Test-Path -LiteralPath $clean) {
        $it = Get-Item -LiteralPath $clean
        L ('  size/mtime: ' + $it.Length + ' / ' + $it.LastWriteTime)
        $s = Get-AuthenticodeSignature -LiteralPath $clean
        L ('  signature : ' + $s.Status + '  signer=' + $s.SignerCertificate.Subject)
    }
}

L ''
L '=== LIVE START ATTEMPT (capture exact error) ==='
& sc.exe stop AntiCheatDriver 2>&1 | Out-Null
Start-Sleep -Milliseconds 400
$out = & sc.exe start AntiCheatDriver 2>&1 | Out-String
L ($out.Trim())
L '--- state after ---'
L ((& sc.exe query AntiCheatDriver 2>&1 | Out-String).Trim())

L ''
L '=== SYSTEM EVENT LOG (last 15 relevant) ==='
try {
    Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=(Get-Date).AddMinutes(-30) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'AntiCheat|Wdf|KMDF|driver' -or $_.ProviderName -match 'Service Control Manager|Kernel-PnP|Wdf' } |
        Select-Object -First 15 |
        ForEach-Object {
            L ('  [' + $_.TimeCreated.ToString('HH:mm:ss') + '] ' + $_.ProviderName + ' id=' + $_.Id + ' level=' + $_.LevelDisplayName)
            L ('      ' + (($_.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' | '))
        }
} catch { L ('  eventlog error: ' + $_.Exception.Message) }

L ''
L '=== CODE INTEGRITY EVENT LOG ==='
try {
    Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 12 -ErrorAction Stop |
        ForEach-Object {
            L ('  [' + $_.TimeCreated.ToString('HH:mm:ss') + '] id=' + $_.Id + ' ' + (($_.Message -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' | '))
        }
} catch { L ('  none / ' + $_.Exception.Message) }
