Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like '*TestDriverCert*'}
Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like '*TestDriverCert*'}
Get-ChildItem Cert:\CurrentUser\Root | Where-Object {$_.Subject -like '*TestDriverCert*'}
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like '*TestDriverCert*'}