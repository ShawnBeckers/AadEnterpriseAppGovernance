#AadApp-UpdateTrackingFile.ps1
#This is an example of a script which could be used to track long term AAD enterprise basic app usage in your tenant.
#The idea is to use the LastActivityDate recorded in the tracking file to determine if an app is a candidate to be disabled/removed.

#Notes:
# - The script updates LastActivityDate based upon activity within the past day. So ideally this script would be scheduled to run on a daily basis.
# - Make sure to load the Get-MsGraphAuthToken somewhere in this script or prior to running.
# - Make sure to add your tenant ID, app ID, and app secret in the Get-MsGraphAuthToken call.
# - This example script uses cert thumbprint to authenticate but you can use the less secure app secret option as well.
# - Usage data is stored in located defined by AppUsageTrackingFile.  Adjust location as needed.

#Load contents of AppUsageTrackingFile into AppUsageTrackingTable
$AppUsageTrackingFile = "C:\Temp\AadAppUsageTracking.csv"
$AppUsageTrackingTable = @{}
If (Test-Path $AppUsageTrackingFile)
{
   $TempArray = Import-Csv -Path $AppUsageTrackingFile
   ForEach ($Entry in $TempArray) {$AppUsageTrackingTable.Add($Entry.AppID,$Entry)}
}

#Initialize OAuth token
$AuthObject = Get-MsGraphAuthToken -TenantID "Your Tenant ID" -AppID "ID of AAD app" -AppCertThumbprint "Thumbprint of cert used for authentication"
$TokenHeaderParams = $AuthObject.AuthToken
$TokenExpTimestamp = $AuthObject.ExpirationTimestamp

#Get list of all enterprise apps
$AadApps = @()
[uri]$URL = "https://graph.microsoft.com/beta/servicePrincipals?&`$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
$RestResults = Invoke-RestMethod -Method Get -Headers $TokenHeaderParams -Uri $URL.AbsoluteUri
$AadApps += @($RestResults.Value)
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
   $AadApps += @($RestResults.Value)
   $NextUri = $RestResults.'@odata.nextlink'
}

#Get last usage date for each enterprise app
$RetryCount = 0
$RetryIntervalInSeconds = 60
$MaxRetryCount = 6
ForEach ($App in $AadApps)
{
   #Make sure we still have valid OAuth token
   If ($TokenHeaderParams -eq $Null -or (Get-Date) -ge $TokenExpTimestamp)
   {
      $AuthObject = Get-MsGraphAuthToken -TenantID "Your Tenant ID" -AppID "ID of AAD app" -AppCertThumbprint "Thumbprint of cert used for authentication"
      $TokenHeaderParams = $AuthObject.AuthToken
      $TokenExpTimestamp = $AuthObject.ExpirationTimestamp
   }

   #Check if app has been used in the past day
   $StartDate = (Get-Date).AddDays(-1).ToString("yyyy-MM-dd")
   $EndDate = (Get-Date).ToString("yyyy-MM-dd")
   [uri]$URL = "https://graph.microsoft.com/beta/auditLogs/signIns?&`$filter=(signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser' or t eq 'servicePrincipal' or t eq 'managedIdentity')) and appID eq '$($App.AppID)' and createdDateTime ge $($StartDate)T00:00:00Z and createdDateTime le $($EndDate)T00:00:00Z&`$top=5"
   Do
   {
      $Throttling = $False
      Try {$RestResults = Invoke-RestMethod -Method Get -Headers $TokenHeaderParams -Uri $URL.AbsoluteUri -ErrorAction Stop}
      Catch
      {
         If ($_.Exception.Message -like "*429*" -or $_.Exception.Message -like "*throttle*" -or $_.Exception.Message -like "*try again*")
         {
            $Throttling = $True
            $RetryCount++
            Start-Sleep -Seconds $RetryIntervalInSeconds
         }
      }
   }
   While ($Throttling -eq $True -and $RetryCount -lt $MaxRetryCount)
   If ($RetryCount -ge $MaxRetryCount) {Write-Error "Retry count exceeded. The remote server is throttling requests."}
   
   #Update tracking table if activity found
   If ($RestResults.Value.Count -gt 0) {$LastActiveDate = $StartDate} Else {$LastActiveDate = "None"}
   If ($AppUsageTrackingTable.ContainsKey($App.AppID) -eq $True -and $LastActiveDate -ne "None") {$AppUsageTrackingTable[$App.AppID].LastActiveDate = $LastActiveDate}
   Else {
      If ($AppUsageTrackingTable.ContainsKey($App.AppID) -eq $False)
      {
         $TempObject = New-Object PSObject
         $TempObject | Add-Member -Type NoteProperty -Name AppID -Value $App.AppID -Force
         $TempObject | Add-Member -Type NoteProperty -Name AppDisplayName -Value $App.AppDisplayName -Force
         $TempObject | Add-Member -Type NoteProperty -Name LastActiveDate -Value $StartDate -Force
         $AppUsageTrackingTable.Add($App.AppID,@($TempObject))
      }
   }   
   Start-Sleep -Seconds 1
}

#Remove from tracking table any apps that no longer exist in tenant
$CurrentAppIDs = $AadApps | Select-Object -ExpandProperty AppID
$TrackingTableAppIDs = $AppUsageTrackingTable.Keys
ForEach($AppID in $TrackingTableAppIDs) {If ($CurrentAppIDs -notcontains $AppID) {$AppUsageTrackingTable.Remove($AppID)}}

#Update AppUsageTrackingFile
New-Item -ItemType File -Path $AppUsageTrackingFile -Force
Add-Content -Path $AppUsageTrackingFile -Value "AppID,AppDisplayName,LastActiveDate"
ForEach ($Key in $AppUsageTrackingTable.Keys) {Add-Content -Path $AppUsageTrackingFile -Value "$($AppUsageTrackingTable[$Key].AppID),$($AppUsageTrackingTable[$Key].AppDisplayName.Replace(","," ")),$($AppUsageTrackingTable[$Key].LastActiveDate)"}

#Clear Oauth token variables
$AuthObject = $Null
$TokenHeaderParams = $Null