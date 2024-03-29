Configuration Main
{
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
	Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        LocalConfigurationManager            
        {            
            DebugMode = 'All'
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true
        }

	    WindowsFeature WebAppProxy
        {
            Ensure = "Present"
            Name = "Web-Application-Proxy"
        }

        WindowsFeature Tools 
        {
            Ensure = "Present"
            Name = "RSAT-RemoteAccess"
            IncludeAllSubFeature = $true
        }

        WindowsFeature MoreTools 
        {
            Ensure = "Present"
            Name = "RSAT-AD-PowerShell"
            IncludeAllSubFeature = $true
        }

        WindowsFeature Telnet
        {
            Ensure = "Present"
            Name = "Telnet-Client"
        }
    }
}
