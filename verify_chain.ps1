$ErrorActionPreference = 'Continue'
function L($t) { Write-Host $t }

$sys   = 'D:\Mythos\Driver\AntiCheatDriver.signed.sys'
$plain = 'D:\Mythos\Driver\build\AntiCheatDriver.sys'

L '=== BUILD ARTIFACTS PRESENT ==='
foreach ($f in $sys, $plain) {
    if (Test-Path -LiteralPath $f) {
        $i = Get-Item -LiteralPath $f
        L ('  OK   ' + $f)
        L ('       Size=' + $i.Length + '  Modified=' + $i.LastWriteTime)
        $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        L ('       SHA256=' + $h)
    } else { L ('  MISS  ' + $f) }
}

L ''
L '=== SIGNATURE SUMMARY (signed file) ==='
if (Test-Path -LiteralPath $sys) {
    $s = Get-AuthenticodeSignature -LiteralPath $sys
    L ('  Status      : ' + $s.Status)
    L ('  StatusMsg   : ' + $s.StatusMessage)
    L ('  SignerCert  : ' + $s.SignerCertificate.Subject)
    L ('  Issuer      : ' + $s.SignerCertificate.Issuer)
    L ('  Thumbprint  : ' + $s.SignerCertificate.Thumbprint)
    L ('  NotAfter    : ' + $s.SignerCertificate.NotAfter)
    L ('  HasEKU      : ' + (($s.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }).Format($false)))
    L ('  TimestampCN : ' + $s.TimeStamperCertificate.Subject)
}

L ''
L '=== CERT IN TRUSTED STORES ==='
foreach ($store in 'Root','TrustedPublisher','My') {
    $dkPath = 'Cert:\LocalMachine\' + $store
    L ('  --- LocalMachine\' + $store + ' ---')
    $certs = Get-ChildItem $dkPath -ErrorAction SilentlyContinue
    if (-not $certs) { L '    (empty)' }
    foreach ($c in $certs) {
        if ($c.Subject -match 'AntiCheat|Mythos|Morlsara|Driver' -or $c.NotAfter -gt (Get-Date)) {
            L ('    ' + $c.Thumbprint + ' | ' + $c.Subject + ' | exp ' + $c.NotAfter.ToString('yyyy-MM-dd') + ' | EKU=' + (($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join '/'))
        }
    }
}

L ''
L '=== USER STORES (CurrentUser) ==='
foreach ($store in 'Root','TrustedPublisher','My') {
    $dkPath = 'Cert:\CurrentUser\' + $store
    $certs = Get-ChildItem $dkPath -ErrorAction SilentlyContinue
    L ('  --- CurrentUser\' + $store + ' : ' + (@($certs).Count) + ' certs ---')
    foreach ($c in $certs) {
        if ($c.Subject -match 'AntiCheat|Mythos|Morlsara|Driver') {
            L ('    ' + $c.Thumbprint + ' | ' + $c.Subject + ' | exp ' + $c.NotAfter.ToString('yyyy-MM-dd'))
        }
    }
}

L ''
L '=== DRIVER SERVICE STATE ==='
$svc = 'AntiCheatDriver'
$q = & sc.exe query $svc 2>&1 | Out-String
L ($q.Trim())

L ''
L '=== CI REGISTRY (driver signing policy) ==='
$ci = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI'
if (Test-Path $ci) {
    foreach ($name in 'VulnerableDriverBlocklistEnable','UMCI','Policies','WhqlEnforcement','DebugFlags') {
        $p = Join-Path $ci $name
        if (Test-Path $p) {
            $v = (Get-ItemProperty $p -ErrorAction SilentlyContinue)
            L ('  ' + $name + ' : ' + (($v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' '))
        }
    }
    $bl = Join-Path $ci 'SiPolicy'
    L ('  SiPolicy present: ' + (Test-Path $bl))
}

L ''
L '=== SECTION COMPARISON: ours vs Microsoft KMDF driver ==='
function Secs($path) {
    if (-not (Test-Path -LiteralPath $path)) { return 'missing' }
    $b = [System.IO.File]::ReadAllBytes($path)
    $e = [BitConverter]::ToInt32($b, 0x3C)
    $n = [BitConverter]::ToUInt16($b, $e + 6)
    $os = [BitConverter]::ToUInt16($b, $e + 20)
    $sh = $e + 24 + $os
    $out = @()
    for ($i = 0; $i -lt $n; $i++) {
        $o = $sh + 40 * $i
        $out += ([System.Text.Encoding]::ASCII.GetString($b, $o, 8)).Trim([char]0)
    }
    return ($out -join ' ')
}
L ('  AntiCheatDriver.signed.sys : ' + (Secs $sys))
L ('  Wdf01000.sys              : ' + (Secs 'C:\Windows\System32\drivers\Wdf01000.sys'))
L ('  wdfldr.sys                : ' + (Secs 'C:\Windows\System32\drivers\wdfldr.sys'))
L ('  acpi.sys                  : ' + (Secs 'C:\Windows\System32\drivers\acpi.sys'))

L ''
L '=== KERNEL DEBUG / LOADER TRACE ==='
$kd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter' -ErrorAction SilentlyContinue
if ($kd) { L ('  DebugPrintFilter Default=' + $kd.DEFAULT) }
L ('  BootLogging enabled: ' + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootLogging'))
