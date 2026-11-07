$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('D:\Mythos\Driver\DriverSigner\TestDriverCert.pfx', 'TestPass123')
$cert | Select-Object Subject, Issuer, Thumbprint, NotAfter
[System.IO.File]::WriteAllBytes('D:\Mythos\Driver\DriverSigner\TestDriverCert.cer', $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
Write-Host "Certificate extracted to CER file"