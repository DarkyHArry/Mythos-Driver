$pwd = ConvertTo-SecureString -String 'TestPass123' -Force -AsPlainText
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('TestDriverCert.pfx', $pwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

Write-Host "=== Certificate Details ==="
Write-Host "Subject: " $cert.Subject
Write-Host "Thumbprint: " $cert.Thumbprint
Write-Host "NotAfter: " $cert.NotAfter
Write-Host "NotBefore: " $cert.NotBefore
Write-Host "HasPrivateKey: " $cert.HasPrivateKey
Write-Host "Issuer: " $cert.Issuer
Write-Host "SerialNumber: " $cert.SerialNumber
Write-Host "Version: " $cert.Version

Write-Host "`n=== Extensions ==="
foreach ($ext in $cert.Extensions) {
    Write-Host "OID: $($ext.Oid.Value) FriendlyName: $($ext.Oid.FriendlyName) Critical: $($ext.Critical)"
    if ($ext.Oid.Value -eq "2.5.29.37") {  # EKU
        $eku = [System.Security.Cryptography.AsnEncodedData]::new($ext.Oid, $ext.RawData)
        Write-Host "  EKU: $($eku.Format($true))"
    }
    if ($ext.Oid.Value -eq "2.5.29.15") {  # Key Usage
        $ku = [System.Security.Cryptography.AsnEncodedData]::new($ext.Oid, $ext.RawData)
        Write-Host "  KeyUsage: $($ku.Format($true))"
    }
}

Write-Host "`n=== Private Key Details ==="
$pk = $cert.PrivateKey
if ($pk) {
    Write-Host "KeyAlgorithm: $($pk.KeyExchangeAlgorithm)"
    Write-Host "KeySize: $($pk.KeySize) bits"
    Write-Host "SignatureAlgorithm: $($pk.SignatureAlgorithm)"
}

Write-Host "`n=== Chain Validation ==="
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
$valid = $chain.Build($cert)
Write-Host "Chain Valid: $valid"
foreach ($element in $chain.ChainElements) {
    Write-Host "  $($element.Certificate.Subject) - $($element.Certificate.Thumbprint)"
}
foreach ($status in $chain.ChainStatus) {
    Write-Host "  Status: $($status.Status) - $($status.StatusInformation)"
}