$session = (query session $env:USERNAME)
if ($session -match '^>console') {
    Start-Transcript -Path $PSScriptRoot\bootstrap.log -Append -ErrorAction SilentlyContinue
    write-output "Running in Console"
}
else {
    write-output "Running in RDP. Exiting."
    return
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

    write-output "`nStart VPN Client"
    Start-Process -FilePath $VpncliPath -ArgumentList "connect $VpnHost" #-RedirectStandardOutput $psscriptroot\stdout.txt -RedirectStandardError $psscriptroot\stderr.txt
    $counter = 0; $h = 0;
    while ($counter++ -lt 1000 -and $h -eq 0) {
        Start-Sleep -m 10
        $h = (Get-Process vpncli).MainWindowHandle
    }
    #if it takes more than 10 seconds then display message
    if ($h -eq 0) {
        Write-Output "Could not start the VPN it takes too long."
    }
    else {
        # make sure the vpncli is on foreground for the credential input (sendkey)
        [void] [Win]::SetForegroundWindow($h)

        Write-Output "`t...and send user and pass"
        #Write login and password
        [System.Windows.Forms.SendKeys]::SendWait("$Username{Enter}")
        [System.Windows.Forms.SendKeys]::SendWait("$Password{Enter}")

    }
    write-output "Done`n"
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


# Get the Azure Vault token
write-output "Read Key Vault"
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

# install the cert if not there
$cert = Get-ChildItem Cert:\CurrentUser\my | Where-Object Subject -like "*$user*"
if ($cert -eq $null) {
    write-output "Install the certificat for $user"
    $certUrl = "https://$($tags['environment'])stinfraprovision.blob.core.windows.net/certs/$($user).pfx"
    $null = Invoke-WebRequest -UseBasicParsing -Uri $certUrl -OutFile "$env:TEMP\$($user).pfx"
    $null = Import-PfxCertificate -Password $pass -FilePath "$env:TEMP\$($user).pfx" -CertStoreLocation Cert:\CurrentUser\My
}

# Start the VPN
Invoke-VPNConnect -VpnHost 'CSG.TICKETMASTER.COM' -Username $user -Password $passClear


Stop-Transcript -ErrorAction SilentlyContinue