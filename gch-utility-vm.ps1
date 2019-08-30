
# this is an initial setup for a vm
Start-Transcript -Path $psscriptroot\transcript.log -Force -ErrorAction SilentlyContinue


function Install-Software {
    param (
        [Parameter(Mandatory)]
        $Name,
        [Parameter(Mandatory)]
        $Download,
        [Parameter(Mandatory)]
        $VerifyPath,
        $InstallArgument = '/silent'
    )
    $binName = split-path -leaf $Download
    if ($binName -notlike '*.exe') {
        $binName = "setup-$($binName).exe"
    }
    # check if the software already installed
    if ((Test-Path -Path $VerifyPath -ErrorAction SilentlyContinue) -eq $true) {
        write-output "$Name is installed"
        return
    }
    # check if already downloaded
    if ((Test-Path -Path "$env:TEMP\$binName") -eq $false) {
        write-output "Download $binName"
        $null = Invoke-WebRequest -UseBasicParsing -Uri $Download -OutFile "$env:TEMP\$binName"
    }

    Write-Host "`nInstall $($Name)..." -ForegroundColor Yellow
    $null = Start-Process -Wait "$env:TEMP\$binName" -ArgumentList $InstallArgument

    # check now installed
    if ((Test-Path -Path $VerifyPath -ErrorAction SilentlyContinue) -eq $true) {
        write-output "Successfully Installed $binName"
    }
    else {
        write-error "[$name]`tInstallation Error - Validation File Not found: $VerifyPath"
    }

}

function Set-SecureAutoLogon {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [string]
        $Username,

        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [System.Security.SecureString]
        $Password,

        [string]
        $Domain,

        [Int]
        $AutoLogonCount,

        [switch]
        $RemoveLegalPrompt,

        [string]
        $BackupFile
    )

    begin {
        [string] $WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        [string] $WinlogonBannerPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        [string] $Enable = 1
        [string] $Disable = 0

        #region C# Code to P-invoke LSA LsaStorePrivateData function.
        Add-Type @"
            using System;
            using System.Collections.Generic;
            using System.Text;
            using System.Runtime.InteropServices;
            namespace ComputerSystem
            {
                public class LSAutil
                {
                    [StructLayout(LayoutKind.Sequential)]
                    private struct LSA_UNICODE_STRING
                    {
                        public UInt16 Length;
                        public UInt16 MaximumLength;
                        public IntPtr Buffer;
                    }
                    [StructLayout(LayoutKind.Sequential)]
                    private struct LSA_OBJECT_ATTRIBUTES
                    {
                        public int Length;
                        public IntPtr RootDirectory;
                        public LSA_UNICODE_STRING ObjectName;
                        public uint Attributes;
                        public IntPtr SecurityDescriptor;
                        public IntPtr SecurityQualityOfService;
                    }
                    private enum LSA_AccessPolicy : long
                    {
                        POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
                        POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
                        POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
                        POLICY_TRUST_ADMIN = 0x00000008L,
                        POLICY_CREATE_ACCOUNT = 0x00000010L,
                        POLICY_CREATE_SECRET = 0x00000020L,
                        POLICY_CREATE_PRIVILEGE = 0x00000040L,
                        POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
                        POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
                        POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
                        POLICY_SERVER_ADMIN = 0x00000400L,
                        POLICY_LOOKUP_NAMES = 0x00000800L,
                        POLICY_NOTIFICATION = 0x00001000L
                    }
                    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                    private static extern uint LsaRetrievePrivateData(
                                IntPtr PolicyHandle,
                                ref LSA_UNICODE_STRING KeyName,
                                out IntPtr PrivateData
                    );
                    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                    private static extern uint LsaStorePrivateData(
                            IntPtr policyHandle,
                            ref LSA_UNICODE_STRING KeyName,
                            ref LSA_UNICODE_STRING PrivateData
                    );
                    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                    private static extern uint LsaOpenPolicy(
                        ref LSA_UNICODE_STRING SystemName,
                        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                        uint DesiredAccess,
                        out IntPtr PolicyHandle
                    );
                    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                    private static extern uint LsaNtStatusToWinError(
                        uint status
                    );
                    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                    private static extern uint LsaClose(
                        IntPtr policyHandle
                    );
                    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                    private static extern uint LsaFreeMemory(
                        IntPtr buffer
                    );
                    private LSA_OBJECT_ATTRIBUTES objectAttributes;
                    private LSA_UNICODE_STRING localsystem;
                    private LSA_UNICODE_STRING secretName;
                    public LSAutil(string key)
                    {
                        if (key.Length == 0)
                        {
                            throw new Exception("Key length zero");
                        }
                        objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                        objectAttributes.Length = 0;
                        objectAttributes.RootDirectory = IntPtr.Zero;
                        objectAttributes.Attributes = 0;
                        objectAttributes.SecurityDescriptor = IntPtr.Zero;
                        objectAttributes.SecurityQualityOfService = IntPtr.Zero;
                        localsystem = new LSA_UNICODE_STRING();
                        localsystem.Buffer = IntPtr.Zero;
                        localsystem.Length = 0;
                        localsystem.MaximumLength = 0;
                        secretName = new LSA_UNICODE_STRING();
                        secretName.Buffer = Marshal.StringToHGlobalUni(key);
                        secretName.Length = (UInt16)(key.Length * UnicodeEncoding.CharSize);
                        secretName.MaximumLength = (UInt16)((key.Length + 1) * UnicodeEncoding.CharSize);
                    }
                    private IntPtr GetLsaPolicy(LSA_AccessPolicy access)
                    {
                        IntPtr LsaPolicyHandle;
                        uint ntsResult = LsaOpenPolicy(ref this.localsystem, ref this.objectAttributes, (uint)access, out LsaPolicyHandle);
                        uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                        if (winErrorCode != 0)
                        {
                            throw new Exception("LsaOpenPolicy failed: " + winErrorCode);
                        }
                        return LsaPolicyHandle;
                    }
                    private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
                    {
                        uint ntsResult = LsaClose(LsaPolicyHandle);
                        uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                        if (winErrorCode != 0)
                        {
                            throw new Exception("LsaClose failed: " + winErrorCode);
                        }
                    }
                    public void SetSecret(string value)
                    {
                        LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING();
                        if (value.Length > 0)
                        {
                            //Create data and key
                            lusSecretData.Buffer = Marshal.StringToHGlobalUni(value);
                            lusSecretData.Length = (UInt16)(value.Length * UnicodeEncoding.CharSize);
                            lusSecretData.MaximumLength = (UInt16)((value.Length + 1) * UnicodeEncoding.CharSize);
                        }
                        else
                        {
                            //Delete data and key
                            lusSecretData.Buffer = IntPtr.Zero;
                            lusSecretData.Length = 0;
                            lusSecretData.MaximumLength = 0;
                        }
                        IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
                        uint result = LsaStorePrivateData(LsaPolicyHandle, ref secretName, ref lusSecretData);
                        ReleaseLsaPolicy(LsaPolicyHandle);
                        uint winErrorCode = LsaNtStatusToWinError(result);
                        if (winErrorCode != 0)
                        {
                            throw new Exception("StorePrivateData failed: " + winErrorCode);
                        }
                    }
                }
            }
"@
        #endregion
    }

    process {

        try {
            $ErrorActionPreference = "Stop"

            $decryptedPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            )

            if ($BackupFile) {
                # Initialize the hash table with a string comparer to allow case sensitive keys.
                # This allows differentiation between the winlogon and system policy logon banner strings.
                $OrigionalSettings = New-Object System.Collections.Hashtable ([system.stringcomparer]::CurrentCulture)

                $OrigionalSettings.AutoAdminLogon = (Get-ItemProperty $WinlogonPath ).AutoAdminLogon
                $OrigionalSettings.ForceAutoLogon = (Get-ItemProperty $WinlogonPath).ForceAutoLogon
                $OrigionalSettings.DefaultUserName = (Get-ItemProperty $WinlogonPath).DefaultUserName
                $OrigionalSettings.DefaultDomainName = (Get-ItemProperty $WinlogonPath).DefaultDomainName
                if ((Get-ItemProperty $WinlogonPath).DefaultPassword) {
                    $OrigionalSettings.DefaultPassword = (Get-ItemProperty $WinlogonPath).DefaultPassword
                    Remove-ItemProperty -Path $WinlogonPath -Name DefaultPassword -Force
                }
                $OrigionalSettings.AutoLogonCount = (Get-ItemProperty $WinlogonPath).AutoLogonCount

                # The winlogon logon banner settings.
                $OrigionalSettings.LegalNoticeCaption = (Get-ItemProperty $WinlogonPath).LegalNoticeCaption
                $OrigionalSettings.LegalNoticeText = (Get-ItemProperty $WinlogonPath).LegalNoticeText

                # The system policy logon banner settings.
                $OrigionalSettings.legalnoticecaption = (Get-ItemProperty $WinlogonBannerPolicyPath).legalnoticecaption
                $OrigionalSettings.legalnoticetext = (Get-ItemProperty $WinlogonBannerPolicyPath).legalnoticetext

                $OrigionalSettings | Export-Clixml -Depth 10 -Path $BackupFile
            }

            # Store the password securely.
            $lsaUtil = New-Object ComputerSystem.LSAutil -ArgumentList "DefaultPassword"
            $lsaUtil.SetSecret($decryptedPass)

            # Store the autologon registry settings.
            Set-ItemProperty -Path $WinlogonPath -Name AutoAdminLogon -Value $Enable -Force

            Set-ItemProperty -Path $WinlogonPath -Name DefaultUserName -Value $Username -Force
            Set-ItemProperty -Path $WinlogonPath -Name DefaultDomainName -Value $Domain -Force

            if ($AutoLogonCount) {
                Set-ItemProperty -Path $WinlogonPath -Name AutoLogonCount -Value $AutoLogonCount -Force
            }
            else {
                try { Remove-ItemProperty -Path $WinlogonPath -Name AutoLogonCount -ErrorAction stop } catch { $global:error.RemoveAt(0) }
            }

            if ($RemoveLegalPrompt) {
                Set-ItemProperty -Path $WinlogonPath -Name LegalNoticeCaption -Value $null -Force
                Set-ItemProperty -Path $WinlogonPath -Name LegalNoticeText -Value $null -Force

                Set-ItemProperty -Path $WinlogonBannerPolicyPath -Name legalnoticecaption -Value $null -Force
                Set-ItemProperty -Path $WinlogonBannerPolicyPath -Name legalnoticetext -Value $null -Force
            }
        }
        catch {
            throw 'Failed to set auto logon. The error was: "{0}".' -f $_
        }

    }
}

function Set-AutoRun {
    param(
        $Path,
        $Name = "AutoRun"
    )
    $runKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $null = New-ItemProperty -Path $runKey -Name $Name -Value $Path -PropertyType ExpandString -Force
}

function Get-Metadata {
    param(
        $Path = '/instance?api-version=2019-03-11',
        $UrlPrefix = 'http://169.254.169.254/metadata'
    )

    $response = Invoke-WebRequest -UseBasicParsing -Uri "$($UrlPrefix)$($Path)" -Method GET -Headers @{Metadata = "true" }
    $content = $response.Content | ConvertFrom-Json
    return $content
}

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
##################################################
$ErrorActionPreference = 'Stop'

# Install software
Install-Software -Name 'VSCode'        -Download "https://vscode-update.azurewebsites.net/latest/win32-x64/stable" -VerifyPath "$env:ProgramFiles\Microsoft VS Code\code.exe" -InstallArgument "/silent /mergetasks=!runcode"
Install-Software -Name 'SQLAnywhere17' -Download 'http://d5d4ifzqzkhwt.cloudfront.net/sqla17client/SQLA17_Windows_Client.exe' -VerifyPath "$env:ProgramFiles\SQL Anywhere 17\Bin64\scjview.exe" -InstallArgument '/s /a /l:1033 /s "/v: /qn /norestart"'
Install-Software -Name 'Dotnet-Core' -Download 'https://download.visualstudio.microsoft.com/download/pr/a9bb6d52-5f3f-4f95-90c2-084c499e4e33/eba3019b555bb9327079a0b1142cc5b2/dotnet-hosting-2.2.6-win.exe' -VerifyPath "$env:ProgramFiles\dotnet\dotnet.exe" -InstallArgument '/install /norestart /quiet'

# Get the context from the Azure Metadata service
$instance = Get-Metadata
$tags = Get-Tags $instance.compute.tags

# Once we have the Azure Context (for tags), Install the Cisco AnyConnect Client...
Install-Software -Name "AnyConnect"    -Download "https://$($tags['environment'])stinfraprovision.blob.core.windows.net/bin/anyconnect-win-3.1.00495-web-deploy-k9.exe" -InstallArgument "/qn /norestart" -VerifyPath "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\vpncli.exe"


# Get the Azure Vault token
write-output "Read Key Vault"
$kv = Get-Metadata -Path '/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net'
$kvToken = $kv.access_token
$kvUrl = "$($tags['environment'])-kv-$($tags['namespace']).vault.azure.net"
$kvSecret = "$($instance.compute.name)-admin-password"
$content = (Invoke-WebRequest -UseBasicParsing -Uri https://$kvUrl/secrets/$($kvSecret)?api-version=2016-10-01 -Method GET -Headers @{Authorization = "Bearer $kvToken" }).content | ConvertFrom-Json

# Create local user for VPN
$vpnuser = 'gchvpn'
$user = Get-LocalUser -Name $vpnuser -ErrorAction SilentlyContinue
if ($user -eq $null) {
    write-output "Create autlogin user: $vpnuser"
    $null = New-LocalUser $vpnuser -Password ($content.value | ConvertTo-SecureString -AsPlainText -Force) -FullName "VPN Operator" -Description "Auto Login user to connect to vpn" -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    $null = Add-LocalGroupMember -Group "Administrators" -Member $vpnuser
}

write-output "Enable AutoLogon for $vpnuser"
Set-SecureAutoLogon -Username $vpnuser -Password ($content.value | ConvertTo-SecureString -AsPlainText -Force)
write-output "Enable the Bootstrap"
Set-AutoRun -Name "Connect-VPN" -Path "powershell.exe -File $psscriptroot\gch-utility-bootstrap.ps1"
$null = New-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Force
$null = New-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -value 0 -force	
Stop-Transcript -ErrorAction SilentlyContinue