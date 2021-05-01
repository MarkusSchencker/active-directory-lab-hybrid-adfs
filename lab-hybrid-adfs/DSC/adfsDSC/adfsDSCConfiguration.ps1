Configuration Main
{
    Param 
    ( 
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )

    # enable TLS1.2 to prevent access failure with PowerShell Gallery
    $RegPath1 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319"
    New-ItemProperty -path $RegPath1 -name SystemDefaultTlsVersions -value 1 -PropertyType DWORD
    New-ItemProperty -path $RegPath1 -name SchUseStrongCrypto -value 1 -PropertyType DWORD

    $RegPath2 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    New-ItemProperty -path $RegPath2 -name SystemDefaultTlsVersions -value 1 -PropertyType DWORD
    New-ItemProperty -path $RegPath2 -name SchUseStrongCrypto -value 1 -PropertyType DWORD

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    # Register-PSRepository -Name "PSGallery" -SourceLocation "https://www.powershellgallery.com/api/v2" -InstallationPolicy Trusted
    # Register-PSRepository -Default -InstallationPolicy Trusted
	set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
	
    $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
    $shortDomain = $wmiDomain.DomainName

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${shortDomain}\$($AdminCreds.UserName)", $AdminCreds.Password)
        
    Node localhost
    {
        LocalConfigurationManager            
        {            
            DebugMode = 'All'
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true
        }

        WindowsFeature installADFS  #install ADFS
        {
            Ensure = "Present"
            Name   = "ADFS-Federation"
        }

        Script SaveCert
        {
            SetScript  = {
				#install the certificate(s) that will be used for ADFS Service
                $cred=$using:DomainCreds
                $wmiDomain = $using:wmiDomain
                $DCName = $wmiDomain.DomainControllerName
                $PathToCert="$DCName\src\*.pfx"
                $CertFile = Get-ChildItem -Path $PathToCert
				for ($file=0; $file -lt $CertFile.Count; $file++)
				{
					$Subject   = $CertFile[$file].BaseName
					$CertPath  = $CertFile[$file].FullName
					$cert      = Import-PfxCertificate -Exportable -Password $cred.Password -CertStoreLocation cert:\localmachine\my -FilePath $CertPath
				}
            }

            GetScript =  { @{} }

            TestScript = { 
                $wmiDomain = $using:wmiDomain
                $DCName = $wmiDomain.DomainControllerName
                $PathToCert="$DCName\src\*.pfx"
                $File = Get-ChildItem -Path $PathToCert
                $Subject=$File.BaseName
                $cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$Subject"} -ErrorAction SilentlyContinue
                return ($cert -ine $null)   #if not null (if we have the cert) return true
            }
        }

        Script InstallAADConnect
        {
            SetScript = {
                $AADConnectDLUrl="https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
                $exe="$env:SystemRoot\system32\msiexec.exe"

                $tempfile = [System.IO.Path]::GetTempFileName()
                $folder = [System.IO.Path]::GetDirectoryName($tempfile)

                $webclient = New-Object System.Net.WebClient
                $webclient.DownloadFile($AADConnectDLUrl, $tempfile)

                Rename-Item -Path $tempfile -NewName "AzureADConnect.msi"
                $MSIPath = $folder + "\AzureADConnect.msi"

                Invoke-Expression "& `"$exe`" /i $MSIPath /qn /passive /forcerestart"
            }

            GetScript =  { @{} }
            TestScript = { 
                return Test-Path "$env:TEMP\AzureADConnect.msi" 
            }
            DependsOn  = '[Script]SaveCert','[WindowsFeature]installADFS'
        }
    }
}
