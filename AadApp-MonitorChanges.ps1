#AadApp-MonitorChanges.ps1
#This is an example of a script which could be used to monitor for enterprise apps that been added to or removed from your AAD tenant.

#Notes:
# - Make sure to load the Get-MsGraphAuthToken somewhere in this script or prior to running.
# - Make sure to add your tenant ID, app ID, and app secret in the Get-MsGraphAuthToken call.
# - This example script uses cert thumbprint to authenticate but you can use the less secure app secret option as well.
# - Monitoring data is stored in located defined by AppMonitoringFile.  Adjust file path as needed.
# - You will need to define the appropriate settings in the "Send notification" section of the script.

#Get enterprise app info from previous run
$AppMonitoringFile = "C:\Temp\AadAppMonitoring.csv"
$PreviousAadAppsTable = @{}
$PreviousAadAppIDs = @()
If (Test-Path $AppMonitoringFile)
{
   $TempArray = Import-Csv -Path $AppMonitoringFile
   ForEach ($Entry in $TempArray) {$PreviousAadAppsTable.Add($Entry.AppID,$Entry); $PreviousAadAppIDs += @($Entry.AppID)}
}

#Initialize OAuth token
$AuthObject = Get-MsGraphAuthToken -TenantID "Your Tenant ID" -AppID "ID of AAD app" -AppCertThumbprint "Thumbprint of cert used for authentication"
$TokenHeaderParams = $AuthObject.AuthToken
$TokenExpTimestamp = $AuthObject.ExpirationTimestamp

#Get list of current enterprise apps
$CurrentAadAppIDs = @()
$CurrentAadAppsTable = @{}
[uri]$URL = "https://graph.microsoft.com/beta/servicePrincipals?&`$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
$RestResults = Invoke-RestMethod -Method Get -Headers $TokenHeaderParams -Uri $URL.AbsoluteUri
ForEach ($AadApp in $RestResults.Value) {$CurrentAadAppIDs += @($AadApp.AppID); If ($CurrentAadAppsTable.ContainsKey($AadApp.AppID) -eq $False) {$CurrentAadAppsTable.Add($AadApp.AppID, $AadApp)}}
$NextUri = $RestResults.'@odata.nextlink'
While ($NextUri -ne $Null)
{
   If ($TokenHeaderParams -eq $Null -or (Get-Date) -ge $TokenExpTimestamp)
   {
      $AuthObject = Get-MsGraphAuthToken -TenantID "Your Tenant ID" -AppID "ID of AAD app" -AppCertThumbprint "Thumbprint of cert used for authentication"
      $TokenHeaderParams = $AuthObject.AuthToken
      $TokenExpTimestamp = $AuthObject.ExpirationTimestamp
   }
   Start-Sleep -Seconds 1
   $RestResults = Invoke-RestMethod -Method Get -Headers $TokenHeaderParams -Uri $NextUri
   ForEach ($AadApp in $RestResults.Value) {$CurrentAadAppIDs += @($AadApp.AppID); If ($CurrentAadAppsTable.ContainsKey($AadApp.AppID) -eq $False) {$CurrentAadAppsTable.Add($AadApp.AppID, $AadApp)}}
   $NextUri = $RestResults.'@odata.nextlink'
}
$AuthObject = $Null
$TokenHeaderParams = $Null

#Initialize variable used to record changes
$AppChanges = @()

#Look for apps added since last run
ForEach ($AppID in $CurrentAadAppIDs)
{
   If ($PreviousAadAppIDs -notcontains $AppID)
   {
      $TempObject = New-Object PSObject
      $TempObject | Add-Member -Type NoteProperty -Name AppID -Value $AppID -Force
      $TempObject | Add-Member -Type NoteProperty -Name AppDisplayName -Value $CurrentAadAppsTable[$AppID].AppDisplayName -Force
      $TempObject | Add-Member -Type NoteProperty -Name Action -Value "App has been recently added to tenant." -Force
      $AppChanges += @($TempObject)
   }
}

#Look for apps removed since last run
ForEach ($AppID in $PreviousAadAppIDs)
{
   If ($CurrentAadAppIDs -notcontains $AppID)
   {
      $TempObject = New-Object PSObject
      $TempObject | Add-Member -Type NoteProperty -Name AppID -Value $AppID -Force
      $TempObject | Add-Member -Type NoteProperty -Name AppDisplayName -Value $PreviousAadAppsTable[$AppID].AppDisplayName -Force
      $TempObject | Add-Member -Type NoteProperty -Name Action -Value "App has been recently removed from tenant." -Force
      $AppChanges += @($TempObject)
   }
}

#Update monitoring file with current app info
New-Item -ItemType File -Path $AppMonitoringFile -Force
Add-Content -Path $AppMonitoringFile -Value "AppID,AppDisplayName"
ForEach ($Key in $CurrentAadAppsTable.Keys) {Add-Content -Path $AppMonitoringFile -Value "$($CurrentAadAppsTable[$Key].AppID),$($CurrentAadAppsTable[$Key].AppDisplayName.Replace(","," "))"}


#Send notification if changes detected
If ($AppChanges.Count -gt 0)
{
   #Build notification message body
   $MsgBody = "<p>Please review the following summary of changes to Azure AD enterprise apps.</p>"
   $MsgBody += "<table border=""1"">"
   $MsgBody += "<tr><td><b>App ID</b></td><td><b>App Name</b></td><td><b>Change Description</b></td></tr>"
   ForEach ($Change in $AppChanges) {$MsgBody += "<tr><td>$($Change.AppID)</td><td>$($Change.AppDisplayName)</td><td>$($Change.Action)</td></tr>"}
   $MsgBody += "</table>"

   #Send notification
   $MsgSender = "Enter sender address here"
   $MsgRecipients = @("MailRecipient1","MailRecipient2")
   $MsgSubject = "AAD Enterprise Apps - Changes Detected"
   $SmtpServer = "Enter your SMTP server FQDN here"
   $SmtpServerPort = "Enter your SMTP server port here"
   Send-MailMessage -From $MsgSender -To $MsgRecipients -Subject $MsgSubject -Body $MsgBody -BodyAsHtml -SmtpServer $SmtpServer -Port $SmtpServerPort -UseSsl
}