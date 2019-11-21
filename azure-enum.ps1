### 
# Azure AD enumeration
# Taken from: https://hunter2.gitbook.io/darthsidious/enumeration/azure-enumeration
#
###

#Connect to Azure AD using Powershell
install-module azuread
import-module azuread
get-module azuread
connect-azuread

# Get list of users with role global admins# Note that role =! group
$role = Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Company Administrator'}
Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId

# Get all groups and an example using filter
Get-AzureADGroup
Get-AzureADGroup -Filter "DisplayName eq 'Intune Administrators'"

# Get Azure AD policy
Get-AzureADPolicy

# Get Azure AD roles with some examples
Get-AzureADDirectoryRole
Get-AzureADDirectoryRole | Where-Object {$_.displayName -eq 'Security Reader'}
Get-AzureADDirectoryRoleTemplate

#Get Azure AD SPNs
Get-AzureADServicePrincipal

# Log in using Azure CLI (this is not powershell)
az login --allow-no-subscriptions

#Get member list using Azure CLI
az ad group member list --output=json --query='[].{Created:createdDateTime,UPN:userPrincipalName,Name:displayName,Title:jobTitle,Department:department,Email:mail,UserId:mailNickname,Phone:telephoneNumber,Mobile:mobile,Enabled:accountEnabled}' --group='Company Administrators'

#Get user list
az ad user list --output=json --query='[].{Created:createdDateTime,UPN:userPrincipalName,Name:displayName,Title:jobTitle,Department:department,Email:mail,UserId:mailNickname,Phone:telephoneNumber,Mobile:mobile,Enabled:accountEnabled}' --upn='username@domain.com'

#PS script to get array of users / roles
$roleUsers = @() 
$roles=Get-AzureADDirectoryRole
 
ForEach($role in $roles) {
  $users=Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId
  ForEach($user in $users) {
    write-host $role.DisplayName,$user.DisplayName
    $obj = New-Object PSCustomObject
    $obj | Add-Member -type NoteProperty -name RoleName -value ""
    $obj | Add-Member -type NoteProperty -name UserDisplayName -value ""
    $obj | Add-Member -type NoteProperty -name IsAdSynced -value false
    $obj.RoleName=$role.DisplayName
    $obj.UserDisplayName=$user.DisplayName
    $obj.IsAdSynced=$user.DirSyncEnabled -eq $true
    $roleUsers+=$obj
  }
}
$roleUsers

### Enumeration using Microburst
https://github.com/NetSPI/MicroBurst

Import-Module .\MicroBurst.psm1

#Anonymous enumeration
Invoke-EnumerateAzureBlobs -Base company
Invoke-EnumerateAzureSubDomains -base company -verbose

#Authencticated enumeration
Get-AzureDomainInfo -folder MicroBurst -VerboseGet-MSOLDomainInfo
Get-MSOLDomainInfo
