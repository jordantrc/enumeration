function Test-HTTPHeaders {
<#
.SYNOPSIS
Tests a web server for the use of HTTP Security Header best practices.
.DESCRIPTION
This command utilizes the Invoke-WebRequest command to test for the presence of the best-practice
HTTP Security Headers.
.PARAMETER ComputerName
One or more computer names to test. ComputerName may consist of an IP address or a
DNS-resolvable host name.
.PARAMETER Protocol
HTTP or HTTPS, default is HTTPS.
.PARAMETER Port
The TCP port on which the web service is running.
.PARAMETER TLSVersion
The version of TLS to use for the connection. Ignored if the protocol is HTTP. Default is TLS 1.2. Valid values: 1.0, 1.1, 1.2
.PARAMETER SkipCertificateCheck
Ignores all certificate trust errors - such as expired or self-signed certificates when establishing the TLS connection.
.EXAMPLE
Test-HTTPHeaders -ComputerName www.google.com -Protocol HTTPS -Verbose
This example will test for the presence of the best practice HTTP Security Headers on the
www.google.com website. It will connect using HTTPS and provide verbose output.
.EXAMPLE
Test-HTTPHeaders -ComputerName www.google.com -Protocol HTTPS -TLSVersion 1.1
Performs the same task as the first example but uses TLS 1.1.
#>

    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$True,
                   Mandatory=$True)]
        [Alias('CN','MachineName','Name','Host')]
        [string[]]$ComputerName,
        
        [Parameter(Mandatory=$False)]
        [ValidateSet('HTTPS', 'HTTP', 'https', 'http')]
        [string]$Protocol = "HTTPS",

        [Parameter(Mandatory=$False)]
        [ValidateSet('1.0', '1.1', '1.2')]
        [string]$TLSVersion = "1.2",

        [Parameter(Mandatory=$False)]
        [ValidateRange(1, 65535)]
        [int]$Port = 443,

        [Parameter(Mandatory=$False)]
        [switch]$SkipCertificateCheck
    )

BEGIN {}

PROCESS {
    # the headers that should be provided by the server
    $requiredHeaders = @(
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    )

    # create return object array
    $return = @()

    foreach ($computer in $ComputerName) {
        Write-Host -ForegroundColor "Yellow" -BackgroundColor "Black" "[*] Connecting to ${Protocol}://${computer}:${Port}"

        # set TLSVersion to N/A if using HTTP
        if($Protocol -like "HTTP"){
            $TLSVersion = "N/A"
        }

        # set the version of TLS to use
        switch ( $TLSVersion ) {
            "1.0" {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls
                Write-Verbose "Using TLS 1.0"
            }
            "1.1" {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11
                Write-Verbose "Using TLS 1.1"
            }
            "1.2" {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Write-Verbose "Using TLS 1.2"
            }
            "N/A" {
                Write-Verbose "Not using TLS"
            }
        }

        # connect to each computer using the Invoke-WebRequest method
        Try {
            if($SkipCertificateCheck.IsPresent) {
                Write-Verbose "Skipping certificate checks"
                $response = Invoke-WebRequest -Uri "${Protocol}://${computer}:${Port}" -SkipCertificateCheck -ErrorAction Stop
            }
            else {
                $response = Invoke-WebRequest -Uri "${Protocol}://${computer}:${Port}" -ErrorAction Stop
            }
        }
        Catch {
            Write-Error "Unable to connect to ${Protocol}://${computer}:${Port}"
            return
        }
        $statusCode = $response.StatusCode
        $statusDescription = $response.StatusDescription
        Write-Verbose "Response status: $statusCode - $statusDescription"
        
        # create return object
        $props = @{
            ComputerName = $computer
            Protocol = $Protocol
            Port = $Port
            StatusCode = $statusCode
            StatusDescription = $statusDescription
            TLSVersion = $TLSVersion
        }
        # gather and parse the headers
        Write-Verbose "[*] Checking the response for the HTTP Security Headers"
        Write-Verbose "[*] RESULTS:"
        $headers = $response.Headers

        $headerProps = @{}
        foreach ($header in $requiredHeaders) {
            if($headers.ContainsKey($header)) {
                Write-Verbose "[+] $header header found, value = $headers[$header]"
                $headerProps[$header] = "present, value = [$headers[$header]]"
            }
            else {
                Write-Verbose "[-] $header header missing"
                $headerProps[$header] = "missing"
            }
        }
        $props.Add('HeaderStatus', $headerProps)
        $propsObj = New-Object -TypeName PSObject -Property $props
        $return += $propsObj
    }

    return $return
}

}