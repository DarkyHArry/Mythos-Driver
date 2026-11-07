$ErrorActionPreference = 'Continue'
function L($t) { Write-Host $t }
$root = 'D:\Mythos\Driver'

L '=== BUILD DIRECTORIES / GENERATED BUILD FILES ==='
$pats = @('CMakeCache.txt','build.ninja','link.txt','*.vcxproj','*.sln','AntiCheatDriver.sys','AntiCheatDriver.signed.sys')
foreach ($p in $pats) {
    Get-ChildItem -LiteralPath $root -Recurse -Filter $p -File -ErrorAction SilentlyContinue |
        Select-Object -First 15 |
        ForEach-Object { L ('  ' + $_.FullName + '  [' + $_.Length + ' B  ' + $_.LastWriteTime + ']') }
}

L ''
L '=== CMakeCache KMDF / WDK VARS ==='
Get-ChildItem -LiteralPath $root -Recurse -Filter 'CMakeCache.txt' -File -ErrorAction SilentlyContinue | ForEach-Object {
    L ('  FILE: ' + $_.FullName)
    Select-String -Path $_.FullName -Pattern 'KMDF_VERSION|WDK_VERSION|CMAKE_LINKER|CMAKE_GENERATOR:|CMAKE_BUILD_TYPE' -ErrorAction SilentlyContinue |
        ForEach-Object { L ('    ' + $_.Line.Trim()) }
}

L ''
L '=== LINK COMMAND (which wdfdriverentry.lib was bound) ==='
Get-ChildItem -LiteralPath $root -Recurse -Filter 'link.txt' -File -ErrorAction SilentlyContinue | ForEach-Object {
    L ('  FILE: ' + $_.FullName)
    (Get-Content -LiteralPath $_.FullName -Raw) | ForEach-Object {
        ($_ -split '\s+') | Where-Object { $_ -match 'wdf|kmdf|Wdf|ntoskrnl|\.lib|\.def|\.obj|/ENTRY|/SUBSYSTEM|/DRIVER|/INCREMENTAL' } |
            ForEach-Object { L ('    ' + $_) }
    }
}
Get-ChildItem -LiteralPath $root -Recurse -Filter 'build.ninja' -File -ErrorAction SilentlyContinue | ForEach-Object {
    L ('  NINJA: ' + $_.FullName)
    Select-String -Path $_.FullName -Pattern 'wdfdriverentry|wdfldr\.lib|kmdf|/INCREMENTAL|/DRIVER' -ErrorAction SilentlyContinue |
        Select-Object -First 12 | ForEach-Object { L ('    ' + $_.Line.Trim()) }
}

L ''
L '=== PE IMPORT TABLE of AntiCheatDriver.signed.sys ==='
$sys = Join-Path $root 'AntiCheatDriver.signed.sys'
if (Test-Path -LiteralPath $sys) {
    $b = [System.IO.File]::ReadAllBytes($sys)
    $e  = [BitConverter]::ToInt32($b, 0x3C)
    $opt = $e + 24
    $magic = [BitConverter]::ToUInt16($b, $opt)
    $ddOff = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }
    $impRva = [BitConverter]::ToInt32($b, $ddOff + 8)
    $impSz  = [BitConverter]::ToInt32($b, $ddOff + 12)
    L ('  ImportDir RVA=0x' + $impRva.ToString('X') + ' Size=' + $impSz)

    $nsec = [BitConverter]::ToUInt16($b, $e + 6)
    $osz  = [BitConverter]::ToUInt16($b, $e + 20)
    $sho  = $e + 24 + $osz
    $secs = @()
    for ($i = 0; $i -lt $nsec; $i++) {
        $o = $sho + 40 * $i
        $secs += [pscustomobject]@{
            Name = ([System.Text.Encoding]::ASCII.GetString($b, $o, 8)).Trim([char]0)
            VSize= [BitConverter]::ToInt32($b, $o + 8)
            VA   = [BitConverter]::ToInt32($b, $o + 12)
            RawSz= [BitConverter]::ToInt32($b, $o + 16)
            Raw  = [BitConverter]::ToInt32($b, $o + 20)
            Flags= [BitConverter]::ToInt32($b, $o + 36)
        }
    }
    function R2O($rva) {
        foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt ($s.VA + [Math]::Max($s.VSize,$s.RawSz))) { return $s.Raw + ($rva - $s.VA) } }
        return -1
    }
    L '  SECTIONS:'
    foreach ($s in $secs) {
        L ('    ' + $s.Name.PadRight(9) + ' VA=0x' + $s.VA.ToString('X6') + ' VSize=' + $s.VSize + ' RawSz=' + $s.RawSz + ' Flags=0x' + $s.Flags.ToString('X8'))
    }

    if ($impRva -gt 0) {
        $io = R2O $impRva
        $n = 0
        while ($n -lt 30) {
            $d = $io + 20 * $n
            $nameRva = [BitConverter]::ToInt32($b, $d + 12)
            if ($nameRva -eq 0) { break }
            $no = R2O $nameRva
            $dll = ''
            $k = $no
            while ($b[$k] -ne 0) { $dll += [char]$b[$k]; $k++ }
            L ('  DLL: ' + $dll)

            $oftRva = [BitConverter]::ToInt32($b, $d)
            if ($oftRva -eq 0) { $oftRva = [BitConverter]::ToInt32($b, $d + 16) }
            $t = R2O $oftRva
            $fn = 0
            while ($fn -lt 80) {
                $hintRva = [BitConverter]::ToInt32($b, $t + 8 * $fn)
                if ($hintRva -eq 0) { break }
                $fo = R2O $hintRva
                $nm = ''
                $j = $fo + 2
                while ($b[$j] -ne 0) { $nm += [char]$b[$j]; $j++ }
                L ('      ' + $nm)
                $fn++
            }
            $n++
        }
    }
} else { L ('  MISSING ' + $sys) }

L ''
L '=== VERSION-LIKE STRINGS IN BINARY ==='
if (Test-Path -LiteralPath $sys) {
    $b = [System.IO.File]::ReadAllBytes($sys)
    $txt = [System.Text.Encoding]::ASCII.GetString($b)
    $hits = [regex]::Matches($txt, 'Wdf[A-Za-z_]{2,30}|\b1\.(1[5-9]|2[0-9]|3[0-9])\b|KMDF|WDFVERIFY|fothk|WdfVersionBind')
    $u = @{}
    foreach ($h in $hits) { $u[$h.Value] = 1 }
    L ('  distinct: ' + (($u.Keys | Sort-Object) -join '  '))
}

L ''
L '=== DRIVER FILES PRESENT (any .sys anywhere in tree) ==='
Get-ChildItem -LiteralPath $root -Recurse -Filter '*.sys' -File -ErrorAction SilentlyContinue |
    ForEach-Object { L ('  ' + $_.FullName + '  [' + $_.Length + ' B  ' + $_.LastWriteTime + ']') }
