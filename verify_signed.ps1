$sig = Get-AuthenticodeSignature -FilePath 'D:/Mythos/Driver/BasicTest/bin/Release/net8.0/BasicTest.signed.sys'
Write-Output "Status: $($sig.Status)"
Write-Output "StatusMessage: $($sig.StatusMessage)"
Write-Output "SignatureType: $($sig.SignatureType)"
Write-Output "IsOSBinary: $($sig.IsOSBinary)"