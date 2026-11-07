$pwd = ConvertTo-SecureString -String 'TestPass123' -Force -AsPlainText
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('TestDriverCert.pfx', $pwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
Write-Host "Subject: " $cert.Subject
Write-Host "Thumbprint: " $cert.Thumbprint
Write-Host "NotAfter: " $cert.NotAfter
Write-Host "HasPrivateKey: " $cert.HasPrivateKey
$cert.PrivateKey