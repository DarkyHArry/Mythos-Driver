$sig = Get-AuthenticodeSignature -FilePath 'D:/Mythos/Driver/BasicTest/bin/Release/net8.0/BasicTest.signed.sys'
$sig.SignerCertificate | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint