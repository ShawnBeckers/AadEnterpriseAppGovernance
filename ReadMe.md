The scripts published here are meant to be used as examples of managing/monitoring AAD enterprise apps via the MS Graph API.

Prior to using any of these scripts you will need to create an AAD service principle with the appropriate application permissions assigned to it. More info on how to create a service principle can be found at https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal.
Required MS graph application permissions to assign to service principle:
- Application.Read.All

The scripts also rely upon the the Get-MsGraphAuthToken function. You will need to make this function available to your scripts prior to running them.
