Param(
    [string]$domain,
    [string]$EmailAddress,
    [string]$STResourceGroupName,
    [string]$storageName,
    [string]$AGResourceGroupName,
    [string]$AGName,
    [string]$AGOldCertName,
    [bool]$Debug = $false
)

Import-Module ACME-PS

# Ensures that no login info is saved after the runbook is done
Disable-AzContextAutosave

# Log in as the service principal from the Runbook
$connection = Get-AutomationConnection -Name AzureRunAsConnection
Login-AzAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationId $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

# Create a state object and save it to the harddrive
$state = New-ACMEState -Path $env:TEMP
$serviceName = 'LetsEncrypt'

# Fetch the service directory and save it in the state
Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru;

# Get the first anti-replay nonce
New-ACMENonce $state;

# Create an account key. The state will make sure it's stored.
New-ACMEAccountKey $state -PassThru;

# Register the account key with the acme service. The account key will automatically be read from the state
New-ACMEAccount $state -EmailAddresses $EmailAddress -AcceptTOS;

# Load an state object to have service directory and account keys available
$state = Get-ACMEState -Path $env:TEMP;

# It might be neccessary to acquire a new nonce, so we'll just do it for the sake of the example.
New-ACMENonce $state -PassThru;

# Create the identifier for the DNS name
$identifier = New-ACMEIdentifier $domain;

# Create the order object at the ACME service.
$order = New-ACMEOrder $state -Identifiers $identifier;

# Fetch the authorizations for that order
$authZ = Get-ACMEAuthorization -State $state -Order $order;

# Select a challenge to fullfill
$challenge = Get-ACMEChallenge $state $authZ "http-01";

# Inspect the challenge data
$challenge.Data;

# Create the file requested by the challenge
$fileName = $env:TMP + '\' + $challenge.Token;
Set-Content -Path $fileName -Value $challenge.Data.Content -NoNewline;


$blobName = $domain + "/.well-known/acme-challenge/" + $challenge.Token
$storageAccount = Get-AzStorageAccount -ResourceGroupName $STResourceGroupName -Name $storageName
$ctx = $storageAccount.Context

Set-AzStorageBlobContent -File $fileName -Container "public" -Context $ctx -Blob $blobName -Confirm:$false

# Signal the ACME server that the challenge is ready
$challenge | Complete-ACMEChallenge $state;

# Wait a little bit and update the order, until we see the states
while($order.Status -notin ("ready","invalid")) {
    Start-Sleep -Seconds 10;
    $order | Update-ACMEOrder $state -PassThru;
}

# We should have a valid order now and should be able to complete it
# Therefore we need a certificate key
$certKey = New-ACMECertificateKey -Path "$env:TEMP\$domain.key.xml";

# Complete the order - this will issue a certificate singing request
Complete-ACMEOrder $state -Order $order -CertificateKey $certKey;

# Now we wait until the ACME service provides the certificate url
while(-not $order.CertificateUrl) {
    Start-Sleep -Seconds 15
    $order | Update-Order $state -PassThru
}

# As soon as the url shows up we can create the PFX
$password = ConvertTo-SecureString -String "933491341" -Force -AsPlainText
Export-ACMECertificate $state -Order $order -CertificateKey $certKey -Path "$env:TEMP\$domain.pfx" -Password $password;

#
# DEBUG - sabe the certificate
#
switch ($Debug)
{
    $true { 
        
        $blobName_tmp = $domain + "/.well-known/acme-challenge/" + "$domain.pfx"

		try {
			Remove-AzStorageBlob -Container "public" -Context $ctx -Blob $blobName_tmp -Confirm:$false
		}
		catch {}


        Set-AzStorageBlobContent -File $fileName -Container "public" -Context $ctx -Blob $blobName_tmp -Confirm:$false
		Write-Host ("Password: {0}" -f $password) 
        ;break 
	}
    default { ;break }
}

$blobName_tmp = $domain + "/.well-known/acme-challenge/" + "$domain.pfx"
Set-AzStorageBlobContent -File $fileName -Container "public" -Context $ctx -Blob $blobName_tmp


# Delete blob to check DNS
Remove-AzStorageBlob -Container "public" -Context $ctx -Blob $blobName


$appgw = Get-AzApplicationGateway -ResourceGroupName $AGResourceGroupName -Name $AGName

### CHECK IF THE CERT EXISTS

$Cert = Get-AzApplicationGatewaySslCertificate -Name $AGOldCertName -ApplicationGateway $appgw
if ($Cert) 
{
	### RENEW APPLICATION GATEWAY CERTIFICATE ###
	Write-Host "Renewing the certificate ...."
    Set-AzApplicationGatewaySSLCertificate -Name $AGOldCertName -ApplicationGateway $appgw -CertificateFile "$env:TEMP\$domain.pfx" -Password $password
}
else 
{
	### ADD APPLICATION GATEWAY CERTIFICATE ###
	Write-Host "Creating a new certificate ...."
	Add-AzApplicationGatewaySslCertificate -Name $AGOldCertName -ApplicationGateway $appgw -CertificateFile "$env:TEMP\$domain.pfx" -Password $password
}



Set-AzApplicationGateway -ApplicationGateway $appgw
