$ErrorActionPreference = 'Continue'
function Line($t){ Write-Host $t }

Line "=== BCD / DSE STATE ==="
$bcd = & bcdedit /enum '{current}' 2>&1
if ($LASTEXITCODE -ne 0) { Line "  bcdedit failed (exit $LASTEXITCODE): $bcd" }
else {
  foreach ($k in 'testsigning','nointegritychecks','integrityservices','hypervisorlaunchtype','bootmenupolicy') {
    $m = $bcd | Select-String -Pattern ("^\s*" + $k + "\s+(.*)$")
    if ($m) { Line ("  {0,-22} = {1}" -f $k, $m.Matches[0].Groups[1].Value.Trim()) }
    else    { Line ("  {0,-22} = <absent>" -f $k) }
  }
}

Line ""
Line "=== SECURE BOOT ==="
try { Line ("  SecureBoot UEFI = " + (Confirm-SecureBootUEFI)) }
catch { Line ("  SecureBoot query error: " + $_.Exception.Message) }

Line ""
Line "=== TESTSIGNING CERT IN STORES ==="
foreach ($store in 'Root','TrustedPublisher') {
  $c = Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction SilentlyContinue |
       Where-Object { $_.Subject -match 'WDKTestCert|Mythos|Morlsara|Test' }
  if ($c) { foreach ($x in $c) { Line ("  [$store] " + $x.Thumbprint + "  " + $x.Subject) } }
  else { Line "  [$store] no test cert found" }
}

Line ""
Line "=== SIGNATURE STATUS OF BINARIES ==="
$targets = @(
  'D:\Mythos\Driver\AntiCheatDriver.signed.sys',
  'D:\Mythos\Driver\AntiCheatDriver\build\Release\AntiCheatDriver.sys',
  'D:\Mythos\Driver\BasicTest\bin\Release\net8.0\BasicTest.signed.sys'
)
foreach ($t in $targets) {
  if (Test-Path -LiteralPath $t) {
    $s = Get-AuthenticodeSignature -LiteralPath $t
    Line ("  " + $t)
    Line ("    Status      = " + $s.Status)
    Line ("    StatusMsg   = " + ($s.StatusMessage -replace "`r|`n",' '))
    if ($s.SignerCertificate) {
      Line ("    Signer      = " + $s.SignerCertificate.Subject)
      Line ("    Thumbprint  = " + $s.SignerCertificate.Thumbprint)
      Line ("    NotAfter    = " + $s.SignerCertificate.NotAfter)
    } else { Line "    Signer      = <none>" }
  } else { Line ("  MISSING: " + $t) }
}

Line ""
Line "=== LOADED DRIVER SERVICE STATE ==="
$svc = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
       Where-Object { $_.Name -match 'AntiCheat|BasicTest|Mythos' }
if ($svc) { foreach ($s in $svc) { Line ("  " + $s.Name + " | State=" + $s.State + " | Started=" + $s.Started + " | Path=" + $s.PathName) } }
else { Line "  no matching driver service registered" }

$sc = & sc.exe query AntiCheat 2>&1
Line ("  sc query AntiCheat -> " + (($sc | Out-String).Trim() -replace "`r|`n",' | '))

Line ""
Line "=== KERNEL / DSE BOOT FLAGS FROM WINLOGON/CI ==="
try {
  $ci = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 12 -ErrorAction Stop
  foreach ($e in $ci) { Line ("  " + $e.TimeCreated.ToString('MM-dd HH:mm:ss') + " id=" + $e.Id + "  " + (($e.Message -replace "`r|`n",' ').Substring(0,[Math]::Min(140,($e.Message -replace "`r|`n",' ').Length)))) }
} catch { Line ("  CI log error: " + $_.Exception.Message) }
