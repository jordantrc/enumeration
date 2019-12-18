# Invoke-AzureRMEnumeration.ps1
# 
# Azure Resource Manager enumeration script
#
# Taken in whole or in-part from the 
# Pentesting Azure Applications book by Matt Burrough
#

# Before running this script:
#  * Run: Import-Module AzureRM
#  * Authenticate to Azure in PowerShell using Connect-AzureRmAccount
#  * Bypass execution signed code policy with set-exectionpolicy

# Show Azure subscription
Write-Output (" Subscription ", "=================")
Write-Output ("Get-AzureRmContext")
$context = Get-AzureRmContext
$context
$context.Account
$context.Tenant
$context.Susbscription

Write-Output ("Get-AzureRmRoleAssignment")
Get-AzureRmRoleAssignment

Write-Output("", " Resources ", "===============")
# show the subscriptions resource groups and a list of its resources
Write-Output("Get-AzureRmResourceGroup")
Get-AzureRmResourceGroup | Format-Table ResourceGroupName,Location,ProvisioningState
Write-Output ("Get-AzureRmResource")
Get-AzureRmResource | Format-Table Name,ResourceType,ResourceGroupName

# Display web apps
Write-Output ("", " Web Apps ", "===============")
Write-Output ("Get-AzureRmWebApp")
Get-AzureRmWebApp

# list virtual machines
Write-Output ("", " Virtual Machines ", "===============")
$vms = Get-AzureRmVM
Write-Output ("Get-AzureRmVM")
$vms
foreach ($vm in $vms) {
    Write-Output ("Get-AzureRmVM -ResourceGroupName " + $vm.ResourceGroupName + "-Name " + $vm.Name)
    Get-AzureRmVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name
    Write-Output ("HardwareProfile:")
    $vm.HardwareProfile
    Write-Output ("OSProfile:")
    $vm.OSProfile
    Write-Output("ImageReference:")
    $vm.StorageProfile.ImageReference
}

# Show Azure storage
Write-Output ("", " Storage ", "===============")
$SAs = Get-AzureRmStorageAccount
Write-Output("Get-AzureRmStorageAccount")
$SAs
foreach ($sa in $SAs) {
    Write-Output ("Get-AzureRmStorageAccountKey -ResourceGroupName " + $sa.ResourceGroupName + " -StorageAccountName" + $sa.StorageAccountName)
    Get-AzureRmStorageAccountKey -ResourceGroupName $sa.ResourceGroupName -StorageAccountName $sa.StorageAccountName
}

# Get networking settings
Write-Output ("", " Networking ", "===============")
Write-Output ("Get-AzureRmNetworkInterface")
Get-AzureRmNetworkInterface
Write-Output ("Get-AzureRmPublicIpAddress")
Get-AzureRmPublicIpAddress

