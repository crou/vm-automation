$session = (query session $env:USERNAME)
if ($session -match '^>console') {
    Start-Transcript -Path $PSScriptRoot\bootstrap.log -ErrorAction SilentlyContinue
    write-output "$(Get-Date -Format "o")`tRunning in Console"
}
else {
    write-output "$(Get-Date -Format "o")`tRunning in RDP. Exiting."
    #    return
}

# Retrieve info from the azure metadata service
function Get-Metadata {
    param(
        $Path = '/instance?api-version=2019-03-11',
        $UrlPrefix = 'http://169.254.169.254/metadata'
    )

    $response = Invoke-WebRequest -UseBasicParsing -Uri "$($UrlPrefix)$($Path)" -Method GET -Headers @{Metadata = "true" }
    $content = $response.Content | ConvertFrom-Json
    return $content
}

# convert the flat comma delimited format of tags into an Hash table
function Get-Tags {
    param (
        $InputObject
    )
    # Create hashtable
    $dictionary = @{ }
    # Split input string into pairs
    $InputObject.Split(';') | ForEach-Object {
        # Split each pair into key and value
        $key, $value = $_.Split(':')
        # Populate $dictionary
        $dictionary[$key] = $value
    }
    return $dictionary
}

function ConvertTo-Metric {
    param(
        [Parameter(Mandatory)]
        $Name,
        [Parameter(Mandatory)]
        $Namespace,
        [Parameter(ValueFromPipeline)]
        $SingleValue,
        $Min,
        $Max,
        $Sum,
        $Count,
        $Timestamp = [DateTime]::Now.ToUniversalTime().ToString("o")
    )
    if ($SingleValue -ne $null) {
        $Min = $SingleValue
        $Max = $SingleValue
        $Sum = $SingleValue
        $Count = 1
    }
    $metric = @{
        time = $Timestamp
        data = @{
            baseData = @{
                metric    = "$Name"
                namespace = "$Namespace"
                series    = @(
                    @{ 
                        min   = $min 
                        max   = $max 
                        sum   = $sum
                        count = $count
                    } 
                )
            }
        }
    } | convertto-json -depth 10
    return $metric
}
Function Send-Webhook {
    param(
        $uri,
        $message
    )

    $Body = @{
        'text' = $message
    }

    $params = @{
        Headers = @{'accept' = 'application/json' }
        Body    = $Body | convertto-json
        Method  = 'Post'
        URI     = $uri
    }

    try {
        $null = Invoke-RestMethod @params
    }
    catch {
        Write-Warning "Unable to send the webhook"
    }
}
function  Send-AzCustomMetric {
    param (
        [Parameter(ValueFromPipeline)]
        $data
    )

    # Get a monitor Token if not expired
    if ($script:monToken -eq $null -or ([datetime]'1/1/1970').AddSeconds($script:monToken.expires_on) -lt (get-date)) {
        $script:monToken = Get-Metadata -Path '/identity/oauth2/token?api-version=2018-02-01&resource=https://monitoring.azure.com/'
    }   
    
    if ($script:monUrl -eq $Null) {    
        $script:monUrl = "https://$($instance.compute.location).monitoring.azure.com$($instance.compute.resourceId)/metrics"
    }
    #Write-Output $url
    
    $null = Invoke-WebRequest -UseBasicParsing -Uri $script:monUrl -Method Post -Headers @{Authorization = "Bearer $($script:monToken.access_token)" } -Body $data -ContentType 'application/json'    -ErrorAction SilentlyContinue
}

function Get-RdpSession {
    $pattern = '^(?<Interactive>[ >])(?<SessionName>\S*)\s+(?<UserName>\S*)\s+(?<ID>\d+)\s+(?<State>\S*)\s*(?:(?<Type>\S*)\s+(?<Device>\S*))?'
    $Result = qwinsta.exe 2>$null
    $Result | Where-Object { $_ -match $pattern } |
    ForEach-Object {
        $Properties = @{
            ComputerName  = $Computer
            IsInteractive = $matches.Interactive -as [bool]
            SessionName   = $matches.SessionName
            UserName      = $matches.UserName
            ID            = [int]$matches.ID
            State         = $matches.State
            Type          = $matches.Type
            Device        = $matches.Device
        }
        if ($PSVersion -eq 2) {
            New-Object -TypeName PSObject -Property $Properties
        }
        else {
            [PSCustomObject]$Properties
        }
    }
}

Function Invoke-VPNMonitor {
    while ($true) {
        $statusPre = $statusNow    
        $statusNow = Get-NetAdapter -InterfaceDescription "Cisco AnyConnect Secure Mobility*" | Select-Object -ExpandProperty Status
        if ($statusNow -ne 'up') {
            Write-Output "$(Get-Date -Format "o")`tVPN Not Connected. Retry..."
            0 | ConvertTo-Metric -Name "VPN Connected" -Namespace "Custom Metric" | Send-AzCustomMetric
            Invoke-VPNConnect -VpnHost 'CSG.TICKETMASTER.COM' -Username $user -Password $passClear
        }
        elseif ($statusPre -ne 'up' -and $statusNow -eq 'up') {
            Write-Output "$(Get-Date -Format "o")`tVPN is now successfully connected"
            1 | ConvertTo-Metric -Name "VPN Connected" -Namespace "Custom Metric" | Send-AzCustomMetric
            Send-Webhook -message "VPN on $env:computername is now Connected" -uri $webhookUri
        }
        elseif ($statusNow -eq 'up') {
            write-output "$(Get-Date -Format "o")`tPing!"
            1 | ConvertTo-Metric -Name "VPN Connected" -Namespace "Custom Metric" | Send-AzCustomMetric
        }
        Start-Sleep -Seconds 30
    }
}


# Start the vpncli.exe and pass the username and password as input
Function Invoke-VPNConnect {
    param (
        $VpnHost,
        $VpncliPath = "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\vpncli.exe",
        $Username,
        $Password
    )
    # Stop past client
    stop-process -Name "vpnui" -ErrorAction SilentlyContinue -Force
    stop-process -Name "vpncli" -ErrorAction SilentlyContinue -Force

    # kill RDP Session
    try {
        Get-RdpSession | Where-Object { $_.State -eq 'active' -and $_.SessionName -like 'rdp*' -and $_.UserName -ne $env:username } | ForEach-Object { 
            write-output "$(Get-Date -Format "o")`tKilling RDP Session $($_.id)"
            start-process "rwinsta" -ArgumentList "$($_.id)" -Verb runas -ErrorAction SilentlyContinue
        }
    }
    catch { Write-Warning "Unable to kill rdp session: $($Error[0].Exception.Message)" }

    Get-RdpSession | Where-Object { $_.State -eq 'active' -and $_.SessionName -like 'rdp*' -and $_.UserName -eq $env:username } | ForEach-Object { 
        write-output "$(Get-Date -Format "o")`tReconnecting RDP Session $($_.id) To Console"
        start-process "tscon"  -ArgumentList "$($_.id) /dest:console" -Verb runas -ErrorAction SilentlyContinue
    }
  

    write-output "$(Get-Date -Format "o")`tStart VPN Client"
    Start-Process -FilePath $VpncliPath -ArgumentList "connect $VpnHost" #-RedirectStandardOutput $psscriptroot\stdout.txt -RedirectStandardError $psscriptroot\stderr.txt
    $counter = 0; $h = 0;
    while ($counter++ -lt 1000 -and $h -eq 0) {
        Start-Sleep -m 10
        $h = (Get-Process vpncli).MainWindowHandle
    }
    #if it takes more than 10 seconds then display message
    if ($h -eq 0) {
        Write-Output "$(Get-Date -Format "o")`tCould not start the VPN it takes too long."
    }
    else {
        # make sure the vpncli is on foreground for the credential input (sendkey)
        [void] [Win]::SetForegroundWindow($h)

        Write-Output "$(Get-Date -Format "o")`t...and send user and pass"
        #Write login and password
        [System.Windows.Forms.SendKeys]::SendWait("$Username{Enter}")
        [System.Windows.Forms.SendKeys]::SendWait("$Password{Enter}")

    }
}

#Set foreground window function
#This function is called in VPNConnect
Add-Type @'
  using System;
  using System.Runtime.InteropServices;
  public class Win {
     [DllImport("user32.dll")]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool SetForegroundWindow(IntPtr hWnd);
  }
'@ -ErrorAction Stop

Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop

# Read vm instance context / metadata
$instance = Get-Metadata
$tags = Get-Tags $instance.compute.tags
$webhookUri = ''

# Get the Azure Vault token
write-output "$(Get-Date -Format "o")`tRead Key Vault"
$kv = Get-Metadata -Path '/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net'
$kvToken = $kv.access_token
$kvUrl = "$($tags['environment'])-kv-$($tags['namespace']).vault.azure.net"
$kvUser = "$($instance.compute.name)-vpn-user"
$kvPass = "$($instance.compute.name)-vpn-password"
$content = (Invoke-WebRequest -UseBasicParsing -Uri https://$kvUrl/secrets/$($kvUser)?api-version=2016-10-01 -Method GET -Headers @{Authorization = "Bearer $kvToken" }).content | ConvertFrom-Json
$user = $content.value
$content = (Invoke-WebRequest -UseBasicParsing -Uri https://$kvUrl/secrets/$($kvPass)?api-version=2016-10-01 -Method GET -Headers @{Authorization = "Bearer $kvToken" }).content | ConvertFrom-Json
$passClear = $content.value
$pass = $content.value | ConvertTo-SecureString -AsPlainText -Force

Write-Output "$(Get-Date -Format "o")`tVPN User is: $user"

# install the cert if not there
$cert = Get-ChildItem Cert:\CurrentUser\my | Where-Object Subject -like "*$user*"
if ($cert -eq $null) {
    write-output "$(Get-Date -Format "o")`tInstall the certificat for $user"
    $certUrl = "https://$($tags['environment'])stinfraprovision.blob.core.windows.net/certs/$($user).pfx"
    $null = Invoke-WebRequest -UseBasicParsing -Uri $certUrl -OutFile "$env:TEMP\$($user).pfx"
    $null = Import-PfxCertificate -Password $pass -FilePath "$env:TEMP\$($user).pfx" -CertStoreLocation Cert:\CurrentUser\My
}

# Start the VPN
Invoke-VPNMonitor
Stop-Transcript -ErrorAction SilentlyContinue