#Description: This function will obtain an OAuth token to use in connecting to the Microsoft Graph API.
# Notes: This function requires you provide either the thumbprint of a certificate stored in the certificate store on the local machine or an app password string.
Function Get-MsGraphAuthToken ([Parameter(Mandatory=$True)][String]$TenantID,[Parameter(Mandatory=$True)][String]$AppID, [String]$AppSecret = $Null, [String]$AppCertThumbprint = $Null)
{
   #Make sure certificate thumbprint or app secret was provided; not both
   If (($AppCertThumbprint -eq $Null -or $AppCertThumbprint -eq "") -and ($AppSecret -eq $Null -or $AppSecret -eq "")) {Write-Error -Message "You must specify AppCertThumbprint or AppSecret parameters."; Return $Null}
   If ($AppCertThumbprint -ne $Null -and $AppCertThumbprint -ne "" -and $AppSecret -ne $Null -and $AppSecret -ne "") {Write-Error -Message "You cannot specify values for both AppCertThumbprint and AppSecret parameters."; Return $Null}

   #If AppCertThumbprint parameter specified obtain token using certificate
   If ($AppCertThumbprint -ne $Null -and $AppCertThumbprint -ne "")
   {
      #Set expiration timestamp for token that will be returned to caller
      $TokenExpirationTimestamp = (Get-Date).AddHours(1)

      #Get certificate from local cert store and build JWT used for authentication; valid for 1 hour
      $AppCertificate = Get-ChildItem -Path Cert:\LocalMachine\My\$AppCertThumbprint
      If ($AppCertificate.Count -ne 1) {Write-Error "Certificate not found in local machine certificate store. Check to make sure certificate exists and you are using the correct thumbprint."; Return $Null}
      If ($AppCertificate.PrivateKey -eq $Null) {Write-Error "Certificate private key not available. Check to make sure private key exists and you have permission to access it."; Return $Null}

      #Build JWT used for authentication; valid for 1 hour
      $AppCertHash = [System.Convert]::ToBase64String($AppCertificate.GetCertHash())  -Replace '\+','-' -Replace '/','_' -Replace '='
      $AuthTokenExp = ([System.DateTimeOffset](Get-Date).AddHours(1).ToUniversalTime()).ToUnixTimeSeconds()
      $AuthTokenStart = ([System.DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeSeconds()
      $AuthJti = New-Guid
      $AuthJwtHeader = @{alg="RS256"; typ="JWT"; x5t=$AppCertHash} | ConvertTo-Json -Compress
      $AuthJwtPayload = @{aud="https://login.microsoftonline.com/$TenantID/oauth2/token"; iss=$AppID; sub=$AppID; jti=$AuthJti; exp=$AuthTokenExp; Nbf=$AuthTokenStart} | ConvertTo-Json -Compress
      $AuthJwtHeaderBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($AuthJwtHeader)).Split('=')[0].Replace('+', '-').Replace('/', '_')
      $AuthJwtPayloadBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($AuthJwtPayload)).Split('=')[0].Replace('+', '-').Replace('/', '_')
      $AuthJwtToSign = [System.Text.Encoding]::UTF8.GetBytes($AuthJwtHeaderBase64 + "." + $AuthJwtPayloadBase64)
      $AppCertKey = $AppCertificate.PrivateKey -as [System.Security.Cryptography.RSACryptoServiceProvider]
      $Signature = [System.Convert]::ToBase64String($AppCertKey.SignData($AuthJwtToSign,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) -Replace '\+','-' -Replace '/','_' -Replace '='
      $JWT = "$AuthJwtHeaderBase64.$AuthJwtPayloadBase64.$Signature"

      #Build body of auth request
      $Scope = "https://graph.microsoft.com/.default"
      $RequestBody = @{grant_type="client_credentials"; scope=$Scope; client_id=$AppID; client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"; client_assertion=$JWT}
   }

   #If AppSecret parameter specified obtain token using app secret
   If ($AppSecret -ne $Null -and $AppSecret -ne "") {$RequestBody = @{grant_type="client_credentials";scope="https://graph.microsoft.com/.default";client_id=$AppID;client_secret=$AppSecret}}

   #Send auth token request
   $RequestResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoft.com/$TenantID/oauth2/v2.0/token" -Body $RequestBody

   #Return object containing auth token and token expiration timestamp
   If ($RequestResponse.Token_Type -eq $Null -and $Request.Access_Token -eq $Null) {$TokenObject = $Null}
   Else {
      $AuthToken = @{Authorization="$($RequestResponse.Token_Type) $($RequestResponse.Access_Token)"}
      If ($Options -contains "AddConsistencyLevelEventualHeader") {$AuthToken.Add("ConsistencyLevel","eventual")}
      $TokenObject = New-Object PSObject
      $TokenObject | Add-Member -Type NoteProperty -Name AuthToken -Value $AuthToken -Force
      $TokenObject | Add-Member -Type NoteProperty -Name ExpirationTimestamp -Value $TokenExpirationTimestamp -Force
   }
   Return $TokenObject
}