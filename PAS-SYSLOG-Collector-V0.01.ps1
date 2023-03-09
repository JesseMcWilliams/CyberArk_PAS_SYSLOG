<#
    Based on the scripts written by jcreameriii
    https://github.com/jcreameriii/PAS-APM-Dashboard-Package-for-Splunk
#>

[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [ValidateSet(
            "All",
            "LocalHostInfo",
            "LocalHostNetwork",
            "LocalHostDrives",
            "LocalHostFirewall",
            "LocalUsers",
            "LocalGroups",
            "LocalSoftwareAll",
            "LocalSoftwareFilter",
            "Vault",
            "PVWA",
            "CPM",
            "PSM",
            "CCP",
            "CVCS"
            )]
        [string[]]$CollectionProfile = ("All"),

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string]$TextSeparator = "|",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string]$PVWALogonType = "CyberArk",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch]$WriteLog
    )

#region GlobalVariables To be Modified
# Global Variables
#  SYSLOGSERVER: This is the IP address or Hostname.
$SYSLOGSERVER = "192.168.113.33"

#  PORT:  This is the port that the SYSLOG server is listening on.
#    UDP Ports:  514
#    TCP Ports:  5144
$SYSLOGPORT = 5140

#  PROTOCOL:  This is either TCP or UDP
$SYSLOGPROTOCOL = "UDP"

#  PVWA Information
#   PVWAURL:  The fully qualified domain names or IP addresses of the VIPs or hosts (epv.company.com)
$PVWAURL = @(
    "192.168.184.134"
    )

#   PVWAIGNORESSL:  True will not validate that the provided Certificate is valid.  False will validate SSL certificate.
$PVWAIGNORESSL = $true
#endregion

#region Script Variables
#  PVWA endpoints to test.  Should be in the form of PasswordVault/v10/logon
#  These are case sensitive.
#    This is for the Synthetic Transaction Monitoring.  How quickly is the PVWA responding.
$PVWAENDPOINTSTOTEST = @{
    DefaultLogon = "PasswordVault/v10/logon"
    CyberArk     = "PasswordVault/v10/logon/cyberark"
    LDAP         = "PasswordVault/v10/logon/LDAP"
    RADIUS       = "PasswordVault/v10/logon/RADIUS"
    SAML         = "PasswordVault/v10/logon/SAML"
}

#  Collection Monitor Types.  This are the Types/Group of monitors.  They can be used by the SIEM to decode the data being sent.
$COLLECTIONMONITORTYPES = @{
    Application = 'ApplicationMonitor'
    Host        = 'HostMonitor'
    Network     = 'NetworkMonitor'
    Drives      = 'DriveMonitor'
    User        = 'UserMonitor'
    Group       = 'GroupMonitor'
    Software    = 'SoftwareMonitor'
    Firewall    = 'FirewallMonitor'
    Certificate = 'CertificateMonitor'
    OS          = 'OSMonitor'
    Hardware    = 'HardwareMonitor'
    Logon       = 'LogonMonitor'
    Shadow      = 'PSMShadowUserMonitor'
    Transaction = 'SyntheticTransactionMonitor'
}

# Seperators used to separate fields in the output data.
$TEXTSEPARATORORDER = [ordered]@{
    0 = '|' # Pipe
    1 = ';' # Semi Colon
    2 = '~' # Tilde
    3 = '+' # Plus
    4 = '@' # At
    5 = '*' # Star
    6 = '%' # Percent
    7 = '^' # Carrot / Top Hat
    8 = '`' # Back Tick
}

#  CyberArk Abbreviation to Service Names.  
#  This maps the component type to the Service names that are used by that component.
$CYBERARKSERVICENAMES = @{
    Vault   = @('PrivateArk Server', 'PrivateArk Database', 'CyberArk Logic Container', 'PrivateArk Remote Control Agent', 'Cyber-Ark Event Notification Engine', 'CyberArk Vault Disaster Recovery', 'MpsSvc')
    PVWA    = @('W3SVC', 'CyberArk Scheduled Tasks', 'MpsSvc')
    CPM     = @('Cyberark Password Manager', 'Cyberark Central Policy Manager Scanner', 'MpsSvc')
    PSM     = @('Cyber-Ark Privileged Session Manager', 'W3SVC', 'TermService', 'MpsSvc')
    CVCS    = @('CyberArk Vault-Conjur Synchronizer', 'MpsSvc')
    CCP     = @('W3SVC', 'CyberArk Application Password Provider', 'MpsSvc')
}

#  CyberArk Abbreviation to Component Names.
$CYBERARKCOMPONENTNAMES = @{
    Vault = "CyberArk Secure Digital Vault"
    PVWA = "CyberArk Privileged Vault Web Access"
    CPM = "CyberArk Central Policy Manager"
    PSM = "CyberArk Privileged Session Manager"
    PSMP = "CyberArk Privileged Session Manager for SSH"
    PSMC = "CyberArk Privileged Session Manager for Cloud"
    PTA = "CyberArk Privileged Threat Analytics"
    CVCS = "CyberArk Vault Cojur Synchronizer"
    CCP = "CyberArk Central Credential Provider"
}

#  Collect Version Info for software.  
#  This is an array of software we want to return versions of when using the software filter.
$COLLECTSOFTWAREINFOFILTER = @(
    'Google Chrome',
    'Microsoft Visual C++*',
    'Microsoft .NET*',
    'Microsoft ASP*',
    'Microsoft PowerShell*',
    'Mozilla Firefox*',
    'CyberArk*',
    'PrivateArk*'
)

#  Domain Role mapping.  
#  This is used by the HostInfo function to decode the Domain Role.
$DOMAINROLEMAPPING = @{
    0 = "Stand-Alone Workstation"
    1 = "Member Workstation"
    2 = "Stand-Alone Server"
    3 = "Member Server"
    4 = "Domain Controller"
    5 = "PDC Emulator Domain Controller"
}
#endregion

#region Script Definitions
#  Script version.  This can be used by the SIEM for decoding the data format.
$Version = "1.0.0000"

#  Define the SYSLOG message format and version to be specified in the SYSLOG messages
$SYSLOGMESSAGEFORMAT = 'CEF'
$SYSLOGMESSAGEVERSION = 0

#  Specify the SYSLOG application name
$SYSLOGAPPLICATIONNAME = 'CyberArk'

#  Get the current date and time and format it.  We get the date and time here so it is the same for 
#  this group of data.  We get the UTC time to match the Vaults output time zone.
$LocalDate = Get-Date
$UTCDate = $LocalDate.ToUniversalTime()
$DateTime = $UTCDate.ToString("yyyy-MM-ddTHH:mm:ssZ")

#  Combine the SYSLOG Message Format, Version, and Date Time into the header
$SYSLOGMESSAGEHEADER = ("{0} {1}:{2}" -f $DateTime, $SYSLOGMESSAGEFORMAT, $SYSLOGMESSAGEVERSION)

# Get the local computer name.
$TheLocalHostName = (Get-CimInstance -ClassName Win32_ComputerSystem).Name

# Write data sent to the SYSLOG server to a log file.
$SYSLOGDATALOGFILE = ("{0}_{1}_SYSLOG_Data_Sent.log" -f $(Get-Date -Format "yyyy-MM-dd"), $TheLocalHostName)

# Enable writing SYSLOG data to a log file
if ($WriteLog)
{
    $SYSLOGENABLEDATALOGGING = $true
}
else
{
    $SYSLOGENABLEDATALOGGING = $false
}

#$SYSLOGENABLEDATALOGGING = $true

#endregion

#region Get Host Data
function Get-HostInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )

    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Host"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    
    # Get the related CIMInstance details from CIM session
    $TargetHostComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $TargetCIMSession
    $TargetHostProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct -CimSession $TargetCIMSession
    $TargetHostProcessor = Get-CimInstance -ClassName Win32_Processor -CimSession $TargetCIMSession
    $TargetHostOperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $TargetCIMSession
    $TargetHostInstalledUpdates = Get-CimInstance -ClassName Win32_QuickFixEngineering -CimSession $TargetCIMSession
    $IPAddress = ((Get-NetIPAddress -AddressFamily IPv4 -CimSession $TargetCIMSession -PrefixOrigin Manual,Dhcp).IPAddress -join ",")

    # Get the last installed update, if it exists.  If it is a fresh OS install it can be null.
    if (($TargetHostInstalledUpdates.count -gt 0) -and ($TargetHostInstalledUpdates[0].InstalledOn))
    {
        # Sort the list of installed updates
        #  Filter entries that have invalid dates.
        $cleanTargetHostInstalledUpdates = $TargetHostInstalledUpdates | Where-Object InstalledOn

        #  Now sort.
        $sortedUpdates = $cleanTargetHostInstalledUpdates | Sort-Object InstalledOn -Desc

        # Get the most recent entry
        $mostRecentlyInstalledUpdate = $sortedUpdates[0].InstalledOn
    }
    else
    {
        $mostRecentlyInstalledUpdate = $TargetHostOperatingSystem.InstallDate
    }
    
    # Get available host information.
    $HostInformation = [ordered]@{
        Host_Name = $TargetHostComputerSystem.Name
        Host_Domain = $TargetHostComputerSystem.Domain
        Host_DNSName = $TargetHostComputerSystem.DNSHostName
        Host_Manufacturer = $TargetHostComputerSystem.Manufacturer
        Host_Model = $TargetHostComputerSystem.Model
        Host_PhysicalMemory = $TargetHostComputerSystem.TotalPhysicalMemory
        Host_SerialNumber = $TargetHostProduct.IdentifyingNumber
        Host_ProcessorCores = $TargetHostProcessor.NumberOfCores
        Host_ProcessorSockets = $TargetHostComputerSystem.NumberOfProcessors
        Host_ProcessorName = $TargetHostProcessor.Name
        Host_ProcessorCaption = $TargetHostProcessor.Caption
        Host_OSRoot = $TargetHostOperatingSystem.SystemDirectory
        Host_OSVersion = $TargetHostOperatingSystem.version
        Host_OSInstallDate = $TargetHostOperatingSystem.InstallDate
        Host_LocalTime = $TargetHostOperatingSystem.LocalDateTime
        Host_TimeZone = (Get-CimInstance -ClassName Win32_TimeZone -CimSession $TargetCIMSession).Caption
        Host_LastBoot = $TargetHostOperatingSystem.LastBootUpTime
        
        # The DomainRole returns a number.  We have to lookup that number to get the string representation of it.
        Host_DomainRole = ($DOMAINROLEMAPPING[[int]($TargetHostComputerSystem.DomainRole)])
        
        # Build the FQDN from the DNSHostName and the first entry in the SuffixSearchList, which is the primary suffix.
        Host_FQDN = ("{0}.{1}" -f $TargetHostComputerSystem.DNSHostName, (Get-DnsClientGlobalSetting -CimSession $TargetCIMSession).SuffixSearchList[0])
        
        # This class returns all updates.  We have to sort the InstalledOn to get the latest entry which should be at the top.
        Host_LastUpdate = $mostRecentlyInstalledUpdate

        # Add the host's IP addresses
        Host_IPAddresses = $IPAddress
    }
    
    # Build output string
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version
    )
    $syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    # Build data string
    $syslogoutput = ("{0}{1}{2}" -f $syslogIntro, (Get-TextSeparator -SeparatorIndex $SeparatorIndex), (Get-StringFromHashTable -SourceHashTable $HostInformation -SeparatorIndex $SeparatorIndex))

    # Strip Carrige Return and Line Feed from data.
    $syslogoutput = $syslogoutput.Replace("`r","").Replace("`n","")

    # Return the syslogouptut string
    #Write-Host ("{0}:  {1}" -f $TheLocalHostName, $syslogoutput)
    return $syslogoutput

}
function Get-HostNetworkInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )

    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Network"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    
    # Get the related CIMInstance details from CIM session
    $TargetHostComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $TargetCIMSession
    $_LocalNetAdapters = Get-CimInstance -Query "Select * from Win32_NetworkAdapter Where NetEnabled = True" -CimSession $TargetCIMSession

    # Create a list to hold the adapter strings
    $Local_NetworkAdapters = New-Object System.Collections.Generic.List[string]

    # Loop over each network adapter found
    foreach ($_localNetAdapter in $_LocalNetAdapters)
    {
        # 
        # Get the user's details and add it to an ordered dictionary.
        $Local_NetAdapter = [ordered]@{
            DeviceID = $_localNetAdapter.DeviceID
            Index = $_localNetAdapter.Index
            GUID = $_localNetAdapter.GUID
            Caption = $_localNetAdapter.Caption
            Description = $_localNetAdapter.Description
            AdapterType = $_localNetAdapter.AdapterType
            MACAddress = $_localNetAdapter.MACAddress
            TimeOfLastReset = $_localNetAdapter.TimeOfLastReset
            Speed = $_localNetAdapter.Speed
            IPConfiguration = Get-TargetNetworkAdapterDetails -TargetAdapter $_localNetAdapter -SeparatorIndex ($SeparatorIndex + 1)
        }

        $_localNetAdapterString = Get-StringFromHashTable -SourceHashTable $Local_NetAdapter -SeparatorIndex ($SeparatorIndex)
        
        # Add the user details to the list
        $Local_NetworkAdapters.Add($_localNetAdapterString.Replace("`r","").Replace("`n",""))

        # Cleanup the Local Users variable
        $Local_NetAdapter.Clear()
    }

    # Build header string
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version
    )

    # Join the Header array into a string.
    $syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    # Build the output list.
    $OutputList = New-Object System.Collections.Generic.List[string]

    # Build the output list from the active network adapters
    foreach ($ana in $Local_NetworkAdapters)
    {
        # Get available host information.
        $HostInformation = [ordered]@{
            Host_Name = $TargetHostComputerSystem.Name
            Host_Networking = $ana
        }
        
        # Build data string
        $syslogoutput = ("{0}{1}{2}" -f $syslogIntro, (Get-TextSeparator -SeparatorIndex $SeparatorIndex), (Get-StringFromHashTable -SourceHashTable $HostInformation -SeparatorIndex $SeparatorIndex))

        # Strip Carrige Return and Line Feed from data.
        $syslogoutputClean = $syslogoutput.Replace("`r","").Replace("`n","")

        # Add the output string to the output list
        $OutputList.Add($syslogoutputClean)
    }
    
    # Return the syslogouptut string
    return $OutputList
}
function Get-HostDriveInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )

    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Drives"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    # Get the related CIMInstance details from CIM session
    $TargetHostComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $TargetCIMSession
    $_LocalDrives = (Get-CimInstance -ClassName Win32_DiskDrive -CimSession $TargetCIMSession)

    # Create an array to hold the drive data.
    $Local_Drives = New-Object System.Collections.Generic.List[string]

    # Loop over each drive found
    foreach ($_localDrive in $_LocalDrives)
    {
        # 
        # Get the Drive's details and add it to an ordered dictionary.
        $Local_Drive = [ordered]@{
            DID = $_localDrive.DeviceID
            Name = $_localDrive.Name
            Caption = $_localDrive.Caption
            Description = $_localDrive.Description.Replace("`r","").Replace("`n","")
            InterfaceType = $_localDrive.InterfaceType
            Size = $_localDrive.Size
            PartitionCount = $_localDrive.Partitions
            Partitions = (Get-TargetDrivePartitons -TargetDrive $_localDrive -SeparatorIndex ($SeparatorIndex + 1))
        }

        $_localDriveString = Get-StringFromHashTable -SourceHashTable $Local_Drive -SeparatorIndex ($SeparatorIndex)
        #Write-Host ("{0} : Drive :  {1}" -f $TheLocalHostName, $_localDriveString)
        
        # Add the user details to the list
        $Local_Drives.Add($_localDriveString.Replace("`r","").Replace("`n",""))

        # Cleanup the Local Users variable
        $Local_Drive.Clear()
    }
    
    # Build output list
    $outputList = New-Object System.Collections.Generic.List[string]

    # Loop over each drive and add it to the output list
    foreach ($_drive in $Local_Drives)
    {
        # Get available host information.
        $HostInformation = [ordered]@{
            Host_Name = $TargetHostComputerSystem.Name

            # Collect local drives and network drives.
            Host_Drives = $_drive
        }

        # Build output string
        $localHeader = @(
            $SYSLOGMESSAGEHEADER,
            $SYSLOGAPPLICATIONNAME,
            $MonitorType,
            $Version
        )
        $syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

        # Build data string
        $syslogoutput = ("{0}{1}{2}" -f $syslogIntro, (Get-TextSeparator -SeparatorIndex $SeparatorIndex), (Get-StringFromHashTable -SourceHashTable $HostInformation -SeparatorIndex $SeparatorIndex))

        # Strip Carrige Return and Line Feed from data.
        $syslogoutputClean = $syslogoutput.Replace("`r","").Replace("`n","")

        # Add to output list.
        $outputList.Add($syslogoutputClean)
    }

    # Return Reults
    return $outputList
}
function Get-HostFirewallInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )

    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Firewall"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    # Specify an output array/list to hold each entry.
    $outputStrings = New-Object System.Collections.Generic.List[string]

    # Use a try catch block
    try
    {
        # Get the firewall rules from the related CIM Session
        $FirewallRules = Get-NetFirewallRule -CimSession $TargetCIMSession -Direction $Direction -Enabled True -ErrorAction Stop

        # Loop over each rule found
        foreach ($_FirewallRule in $FirewallRules)
        {
            # 
            # Get the user's details and add it to an ordered dictionary.
            $_RuleDetails = [ordered]@{
                ID                  = $_FirewallRule.ID
                DisplayName         = $_FirewallRule.DisplayName
                Group               = $_FirewallRule.Group
                Enabled             = $_FirewallRule.Enabled
                Profile             = $_FirewallRule.Profile
                Direction           = $_FirewallRule.Direction
                Action              = $_FirewallRule.Action
                Caption             = $_FirewallRule.Caption
                Description         = $_FirewallRule.Description
                DisplayGroup        = $_FirewallRule.DisplayGroup
                RuleGroup           = $_FirewallRule.RuleGroup

            }

            $_firewallRuleString = Get-StringFromHashTable -SourceHashTable $_RuleDetails -SeparatorIndex $SeparatorIndex
            
            # Add the user details to the list
            $outputStrings.Add($_firewallRuleString.Replace("`r","").Replace("`n",""))

            # Cleanup the Local Users variable
            $_RuleDetails.Clear()

        }
        
    }
    catch
    {
        # Get the error details
        $baseError = $_.Exception

        # Build the error information
        $_RuleDetails = [ordered]@{
            ID                  = 0
            DisplayName         = "Error"
            Group               = $baseError.HResult
            Enabled             = $baseError.ErrorSource
            Profile             = $baseError.Source
            Direction           = $baseError.ErrorData
            Action              = $baseError.NativeErrorCode
            Caption             = $baseError.MessageId
            Description         = $baseError.Message
            DisplayGroup        = "Firewall Service Is Stopped!"
            RuleGroup           = ""

        }
        $_firewallRuleString = Get-StringFromHashTable -SourceHashTable $_RuleDetails -SeparatorIndex $SeparatorIndex
            
        # Add the user details to the list
        $outputStrings.Add($_firewallRuleString.Replace("`r","").Replace("`n",""))

        # Cleanup the Local Users variable
        $_RuleDetails.Clear()

    }
    finally
    {
        # Build the output list
        $outputList = New-Object System.Collections.Generic.List[string]

        # Build output string
        $localHeader = @(
            $SYSLOGMESSAGEHEADER,
            $SYSLOGAPPLICATIONNAME,
            $MonitorType,
            $Version,
            $TargetHostName
        )
        
        # Join the local header array to a string.
        $syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

        # Loop over each rule
        foreach ($_rule in $outputStrings)
        {
            # Build data string
            $syslogoutput = ("{0}{1}{2}" -f $syslogIntro, (Get-TextSeparator -SeparatorIndex $SeparatorIndex), $_rule)

            # Strip Carrige Return and Line Feed from data.
            $syslogoutputClean = $syslogoutput.Replace("`r","").Replace("`n","")

            # Add to the output list.
            $outputList.Add($syslogoutputClean)
        }
    }

    # Return the syslogouptut string
    return $outputList
}
function Get-TargetNetworkAdapterDetails
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ciminstance]$TargetAdapter,
        
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int]$SeparatorIndex
    )
    # Create an array to hold the user data.
    $Local_NetworkAdapterDetails = New-Object System.Collections.Generic.List[string]

    # Get all details
    $_LocalAdapterDetails = Get-CimAssociatedInstance -InputObject $TargetAdapter -ResultClass Win32_NetworkAdapterConfiguration
    #(Get-CimInstance Win32_NetworkAdapter)

    # Loop over each drive found
    foreach ($_localAdapterDetail in $_LocalAdapterDetails)
    {
        # 
        # Get the Adapter's details and add it to an ordered dictionary.
        $Local_AdapterDetail = [ordered]@{
            Index = $_localAdapterDetail.Index
            DHCPEnabled = $_localAdapterDetail.DHCPEnabled
            DNSDomainSuffixSearchOrder = (($_localAdapterDetail.DNSDomainSuffixSearchOrder) -Join $TEXTSEPARATORORDER[$SeparatorIndex + 2])
            DNSHostName = $_localAdapterDetail.DNSHostName
            DNSServerSearchOrder = (($_localAdapterDetail.DNSServerSearchOrder) -Join $TEXTSEPARATORORDER[$SeparatorIndex + 2])
            IPAddresses = (($_localAdapterDetail.IPAddress) -Join $TEXTSEPARATORORDER[$SeparatorIndex + 2])
            IPSubnet = (($_localAdapterDetail.IPSubnet) -Join $TEXTSEPARATORORDER[$SeparatorIndex + 2])
            DefaultIPGateway = (($_localAdapterDetail.DefaultIPGateway) -Join $TEXTSEPARATORORDER[$SeparatorIndex + 2])
            InterfaceIndex = $_localAdapterDetail.InterfaceIndex
            MACAddress = $_localAdapterDetail.MACAddress
            IPFilterSecurityEnabled = $_localAdapterDetail.IPFilterSecurityEnabled
        }

        $_localAdapterDetailsString = Get-StringFromHashTable -SourceHashTable $Local_AdapterDetail -SeparatorIndex ($SeparatorIndex + 1)
        
        # Add the user details to the list
        $Local_NetworkAdapterDetails.Add($_localAdapterDetailsString.Replace("`r","").Replace("`n",""))

        # Cleanup the Local Users variable
        $Local_AdapterDetail.Clear()
    }

    # Create output string using the requested seperator
    $_outputStringAdapterDetails = ($Local_NetworkAdapterDetails -Join $TEXTSEPARATORORDER[$SeparatorIndex])

    # Return Reults
    #Write-Host ("{0} : Drives : {1}" -f $TheLocalHostName, $_outputStringDrives)
    return $_outputStringAdapterDetails
}
function Get-TargetDrivePartitons
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ciminstance]$TargetDrive,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int]$SeparatorIndex
    )
    # Create an array to hold the user data.
    $Local_Drive_Partitions = New-Object System.Collections.Generic.List[string]

    # Get all drives
    $_LocalDrivePartitions = Get-CimAssociatedInstance -InputObject $TargetDrive -ResultClass Win32_DiskPartition
    #(Get-CimInstance Win32_DiskDriveToDiskPartition -Filter "DeviceID = '$($TargetDrive)'")

    # Loop over each partition found
    foreach ($_localDrivePartiton in $_LocalDrivePartitions)
    {
        # Get the partition details and add it to an ordered dictionary.
        $Local_Drive = [ordered]@{
            Index = $_localDrivePartiton.Index
            Name = $_localDrivePartiton.Name
            Caption = $_localDrivePartiton.Caption
            Description = $_localDrivePartiton.Description
            Type = $_localDrivePartiton.Type
            Size = $_localDrivePartiton.Size
            LogicalDisk = (Get-TargetPartitionLogicalDisk -TargetPartiton $_localDrivePartiton -SeparatorIndex ($SeparatorIndex + 2))
        }

        $_localPartitonString = Get-StringFromHashTable -SourceHashTable $Local_Drive -SeparatorIndex ($SeparatorIndex + 1)
        #Write-Host ("{0} : Part :  {1}" -f $TheLocalHostName, $_localPartitonString)
        
        # Add the user details to the list
        $Local_Drive_Partitions.Add($_localPartitonString.Replace("`r","").Replace("`n",""))

        # Cleanup the Local Users variable
        $Local_Drive.Clear()
    }

    # Create output string using the requested seperator
    $_outputStringPartitions = ($Local_Drive_Partitions -Join $TEXTSEPARATORORDER[$SeparatorIndex])
    
    # Return the data
    return $_outputStringPartitions
}
function Get-TargetPartitionLogicalDisk
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ciminstance]$TargetPartiton,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int]$SeparatorIndex
    )
    
    # Create an array to hold the user data.
    $Logical_Drives = New-Object System.Collections.Generic.List[string]

    # Get all drives
    $_LogicalDrives = Get-CimAssociatedInstance -InputObject $TargetPartiton -ResultClass Win32_LogicalDisk
    #(Get-CimInstance Win32_DiskDriveToDiskPartition -Filter "DeviceID = '$($TargetDrive)'")

    # Loop over each partition found
    foreach ($_logicalDrive in $_LogicalDrives)
    {
        # Get the Logical Drive details and add it to an ordered dictionary.
        $Logical_Drive = [ordered]@{
            DeviceID = $_logicalDrive.DeviceID
            VolumeSerialNumber = $_logicalDrive.VolumeSerialNumber
            Name = $_logicalDrive.Name
            Caption = $_logicalDrive.Caption
            Description = $_logicalDrive.Description
            DriveType = $_logicalDrive.DriveType
            FileSystem = $_logicalDrive.FileSystem
            MediaType = $_logicalDrive.MediaType
            Size = $_logicalDrive.Size
            FreeSpace = $_logicalDrive.FreeSpace
        }

        $_logicalDriveString = Get-StringFromHashTable -SourceHashTable $Logical_Drive -SeparatorIndex ($SeparatorIndex + 1)
        #Write-Host ("{0} : Logical :  {1}" -f $TheLocalHostName, $_logicalDriveString)
        
        # Add the user details to the list
        $Logical_Drives.Add($_logicalDriveString.Replace("`r","").Replace("`n",""))

        # Cleanup the Local Users variable
        $Logical_Drive.Clear()
    }

    # Create output string using the requested seperator
    $_outputStringLogical = ($Logical_Drives -Join $TEXTSEPARATORORDER[$SeparatorIndex])
    
    # Return the data
    return $_outputStringLogical
}
function Get-HostUsers
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    # Separator order: |, ;, ~, +, @, %, *
    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["User"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    # Create an array to hold the user data.
    $Local_Users = New-Object System.Collections.Generic.List[string]

    # Get the local users.
    $_Users = Get-CimInstance -ClassName Win32_UserAccount -CimSession $TargetCIMSession -Filter "Domain='$($TargetHostName)'"

    # Get the user details.  Loop over the users retrieved in the first step.
    foreach ($_user in $_Users)
    {
        # The Locked attribute returns Null if it isn't set.  Need to return false.
        if ($_user.Locked)
        {
            $_isLocked = $_user.Locked
        }
        else
        {
            $_isLocked = $false
        }
        # Get the user's details and add it to an ordered dictionary.
        $Local_User = [ordered]@{
            SID = $_user.SID
            Name = $_user.Name
            Caption = $_user.Caption
            Domain = $_user.Domain
            Description = $_user.Description.Replace("`r","").Replace("`n","")
            Disabled = $_user.Disabled
            Locked = $_isLocked
            PasswordLastSet = (Get-LocalUser -Name $_user.Name).PasswordLastSet
        }

        $_localUserString = Get-StringFromHashTable -SourceHashTable $Local_User -SeparatorIndex ($SeparatorIndex)
        #-TextSeparator "~"

        # Add the user details to the list
        $Local_Users.Add($_localUserString)

        # Cleanup the Local Users variable
        $Local_User.Clear()
    }
    
    # Create the output string list
    $outputList = New-Object System.Collections.Generic.List[string]

    # Build output string
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostName
    )
    
    # Join the local header into a string.
    $syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    # Loop over each user and build the output string.
    foreach ($_user in $Local_Users)
    {
        # Build data string
        $syslogoutput = ("{0}{1}{2}" -f $syslogIntro, (Get-TextSeparator -SeparatorIndex $SeparatorIndex), $_user)
        #($Local_Users -join (Get-TextSeparator -SeparatorIndex ($SeparatorIndex + 1)))

        # Strip Carrige Return and Line Feed from data.
        $syslogoutputClean = $syslogoutput.Replace("`r","").Replace("`n","")

        # Add the string to the output list
        $outputList.Add($syslogoutputClean)
    }
    
    
    # Return the syslogouptut string
    return $outputList
}

function Get-HostGroups
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    # Separator order: |, ;, ~, +, @, %, *
    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Group"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    # Create an array to hold the user data.
    $Local_Groups = New-Object System.Collections.Generic.List[string]

    # Get the local users.
    $_Groups = Get-CimInstance -ClassName Win32_Group -Filter 'LocalAccount = True' -CimSession $TargetCIMSession

    # Get the user details.  Loop over the users retrieved in the first step.
    foreach ($_Group in $_Groups)
    {
        # Get the user's details and add it to an ordered dictionary.
        $Local_Group = [ordered]@{
            SID = $_Group.SID
            Name = $_Group.Name
            Caption = $_Group.Caption
            Domain = $_Group.Domain
            Description = $_Group.Description.Replace("`r","").Replace("`n","")
            Members = (Get-TargetGroupMembers -GroupName $_Group.Name -GroupDomain $_Group.Domain -SeparatorIndex ($SeparatorIndex + 1))
        }

        $_localGroupString = Get-StringFromHashTable -SourceHashTable $Local_Group -SeparatorIndex ($SeparatorIndex)
        #-TextSeparator "~"
        #Write-Host ("{0}:  {1}" -f $TheLocalHostName, $_localGroupString)
        
        # Add the user details to the list
        $Local_Groups.Add($_localGroupString)

        # Cleanup the Local Users variable
        $Local_Group.Clear()
    }

    # Build the output list
    $outputList = New-Object System.Collections.Generic.List[string]

    # Loop over each group and add it to the output list.
    foreach ($_group in $Local_Groups)
    {
        # Build output string
        $localHeader = @(
            $SYSLOGMESSAGEHEADER,
            $SYSLOGAPPLICATIONNAME,
            $MonitorType,
            $Version,
            $TargetHostName
        )
        $syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

        # Build data string
        $syslogoutput = ("{0}{1}{2}" -f $syslogIntro, (Get-TextSeparator -SeparatorIndex $SeparatorIndex), $_Group)
        #($Local_Groups -Join (Get-TextSeparator -SeparatorIndex $SeparatorIndex))

        # Strip Carrige Return and Line Feed from data.
        $syslogoutputClean = $syslogoutput.Replace("`r","").Replace("`n","")

        # Add the string to the output list
        $outputList.Add($syslogoutputClean)
    }
    
    # Return the syslogouptut string
    return $outputList
    

}

function Get-TargetGroupMembers
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$GroupName,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$GroupDomain,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch] $Bare
    )

    # Get all members of the group.
    $_LocalGroupMembers = (Get-CimInstance -ClassName Win32_GroupUser -Filter "GroupComponent = `"Win32_Group.Domain='$($GroupDomain)',Name='$($GroupName)'`"").PartComponent

    # Create output string
    $OutputStringGroupMembers = ""

    # Get the text separator
    $TextSeparator = Get-TextSeparator -SeparatorIndex $SeparatorIndex
    
    # Return the base results if requested with the Bare switch
    if ($Bare)
    {
        return $_LocalGroupMembers
    }

    # Loop the members to get the username and domain.
    foreach ($_member in $_LocalGroupMembers)
    {
        #Write-Host ("{0}:{1}\{2} ({3})" -f $GroupName, $_member.Domain, $_member.Name, $_member.SID)
        # Add to the string for members
        $OutputStringGroupMembers += ("{0}\{1} ({2})" -f $_member.Domain, $_member.Name, $_member.SID)

        # Add Separator to the string
        $OutputStringGroupMembers += $TextSeparator
    }

    # Strip the trailing Separator and return the string
    if ($OutputStringGroupMembers.Length -gt 0)
    {
        # Strip Carrige Return and Line Feed from data.
        $OutputStringGroupMembers = ($OutputStringGroupMembers.Substring(0, $OutputStringGroupMembers.Length -($TextSeparator.Length))).Replace("`r","").Replace("`n","")

        # Return the data
        Write-Debug ("{0}\{1}:  {2}" -f $GroupDomain, $GroupName, $OutputStringGroupMembers)
        return $OutputStringGroupMembers
    }
    else
    {
        Write-Debug ("{0}\{1}:  {2}" -f $GroupDomain, $GroupName, $OutputStringGroupMembers)
        return ""
    }
    

}

function Get-TargetServiceInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$ServiceName,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$ComponentName,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    Write-Host ("Getting Service  :  {0}" -f $ServiceName)
    
    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Application"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    try
    {
        # Get information about the service.
        $ServiceInfo = Get-Service -Name $ServiceName -ErrorAction Stop
        $ServiceStatus = $ServiceInfo | Format-Table -HideTableHeaders Status | Out-String
        If ($ServiceStatus -like "*Running*") 
        { 
            $ServiceStatusNumeric = 1 
        } 
        else 
        { 
            $ServiceStatusNumeric = 0 
        }
        # Get the Host's IP Address
        $IPAddress = ((Get-NetIPAddress -AddressFamily IPv4 -CimSession $TargetCIMSession -PrefixOrigin Manual,Dhcp).IPAddress -join ",")

        # Get information about the software
        $SoftwareDetails = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -like "*$($ServiceName)*"

        # Check to see if any results were found.
        if (-not $SoftwareDetails)
        {
            $SoftwareDetails = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object DisplayName -like "*$($CYBERARKCOMPONENTNAMES[$ComponentName])*"
        }
        
        $SoftwareName    = $SoftwareDetails | Select-Object DisplayName | Select-Object -first 1 | Format-Table -HideTableHeaders | Out-String
        $SoftwareVersion = $SoftwareDetails | Select-Object DisplayVersion | Select-Object -first 1 | Format-Table -HideTableHeaders | Out-String
    }
    catch
    {
        Write-Host ("Service NOT Found:  {0}" -f $ServiceName)
        $ServiceStatus = "Not Found"
        $ServiceStatusNumeric = 0
        $SoftwareName = "Not Found"
        $SoftwareVersion = 0
    }
    
    # Build output string
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostName,
        $ServiceName,
        $ServiceStatus,
        $ServiceStatusNumeric,
        $SoftwareName,
        $SoftwareVersion,
        $IPAddress
    )

    $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)
    
    # Strip Carrige Return and Line Feed from data.
    $syslogoutput = $syslogoutput.Replace("`r","").Replace("`n","")

    # Return the syslogouptut string
    return $syslogoutput
}

function Get-HostInstalledSoftware
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [Parameter(Mandatory = $false,
				   Position = 0)]
		[bool] $UseFilter,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    # Separator order: |, ;, ~, +, @, %, *
    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Software"]

    # We don't want to use Win32_Product due to the issues discussed here:  
    #    https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations?view=powershell-7.3
    #    https://learn.microsoft.com/en-US/troubleshoot/windows-server/admin-development/windows-installer-reconfigured-all-applications
    #    https://devblogs.microsoft.com/scripting/use-powershell-to-find-installed-software/

    Write-Host ("Target Host:  {0}" -f $TargetHostName)

    # Create an array to hold the user data.
    $Local_SoftwareList = New-Object System.Collections.Generic.List[string]

    # Get all installed software from the registry.  This can be run using Invoke-Command.
    $LocallyInstalledSoftware = Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object Publisher, DisplayName, DisplayVersion, InstallDate, InstallLocation

    # Check to see if we need to filter the results
    if ($UseFilter)
    {
        # Create an array to hold the user data.
        $filteredSoftwareList = New-Object System.Collections.Generic.List[pscustomobject]

        # Filter the results.  To support the use of wild card characters we have to loop over the filter array.
        foreach ($targetFilter in $COLLECTSOFTWAREINFOFILTER)
        {
            $foundSoftware = ($LocallyInstalledSoftware | Where-Object -Property DisplayName -Like $targetFilter)
            # Check to see if multiple items matched.
            if ($foundSoftware -is [array])
            {
                # Multiple results returned.  Loop over them
                foreach ($foundPackage in $foundSoftware)
                {
                    $filteredSoftwareList.Add($foundPackage)
                }
            }
            else
            {
                $filteredSoftwareList.Add($foundSoftware)
            }
            
        }
        # Output the list to the original.
        $LocallyInstalledSoftware.Clear()
        $LocallyInstalledSoftware = $filteredSoftwareList
    }
    
    # Loop over each entry in the results
    foreach ($_Install in $LocallyInstalledSoftware)
    {
        # Get the user's details and add it to an ordered dictionary.
        $Local_Software = [ordered]@{
            Publisher = $_Install.Publisher
            DisplayName = $_Install.DisplayName
            DisplayVersion = $_Install.DisplayVersion
            InstallDate = $_Install.InstallDate
            InstallLocation = $_Install.InstallLocation
        }

        # Check for empty records.
        if (($null -eq $Local_Software.Publisher) -and ($null -eq $Local_Software.DisplayName) -and ($null -eq $Local_Software.DisplayVersion))
        {
            # Skip to the next entry
            #Write-Host "*** Null ***"
            continue
        }
        $_localSoftwareString = Get-StringFromHashTable -SourceHashTable $Local_Software -SeparatorIndex ($SeparatorIndex)
        #-TextSeparator "~"

        # Add the user details to the list
        #Write-Debug ("{0} : Adding Software : {1}" -f $TargetHostName, $_localSoftwareString)
        $Local_SoftwareList.Add($_localSoftwareString)
        
        # Cleanup the Local Users variable
        $Local_Software.Clear()
    }
    
    # Build output string
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostName
    )
    $syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    # Build output list.
    $outputList = New-Object System.Collections.Generic.List[string]

    # Loop over each installed software and add it to the output list.
    foreach ($_package in $Local_SoftwareList)
    {
        # Build data string
        $syslogoutput = ("{0}{1}{2}" -f $syslogIntro, (Get-TextSeparator -SeparatorIndex $SeparatorIndex), $_package)
        #($Local_SoftwareList -Join (Get-TextSeparator -SeparatorIndex $SeparatorIndex))

        # Strip Carrige Return and Line Feed from data.
        $syslogoutputClean = $syslogoutput.Replace("`r","").Replace("`n","")

        # add the package to the output list.
        $outputList.Add($syslogoutputClean)
    }
    
    
    # Return the syslogouptut string
    return $outputList

}

function Get-CertificateInformationIIS
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )

    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Certificate"]
    
    # Check if WebAdministration module is installed.
    if (Get-Module -ListAvailable -Name WebAdministration)
    {
        # The web administration moduel is available.
        #  Import the module.
        Import-Module WebAdministration

        # Check if IISAdministration module is installed.
        if (Get-Module -ListAvailable -Name IISAdministration)
        {
            # The web administration moduel is available.
            #  Import the module.
            Import-Module IISAdministration

            #  Get the IIS Server Manager Properties.
            $IISServer = Get-IISServerManger 

            # Get the Web Sites configured on the IIS server.
            $IISSites = $IISServer.Sites

            # Loop over each site.
            foreach ($_site in $IISSites)
            {
                # Get the Certificate Hash.
                $certHash = $_site.CertificateHash
                $certStore = $_site.CertificateStoreName

                Write-Host ("Certificate Hash :  {0}" -f $certHash)
                Write-Host ("Certificate Store:  {0}" -f $certStore)
            }
        }
        
    }
    

    # Get certificate details
    
    # Build output string
    # $localHeader = @(
    #     $SYSLOGMESSAGEHEADER,
    #     $SYSLOGAPPLICATIONNAME,
    #     $MonitorType,
    #     $Version,
    #     $TargetHostName
    # )
    #$syslogIntro = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    # Build data string
    #$syslogoutput += ("|{0}" -f (Get-StringFromHashTable -SourceHashTable $HostInformation -SeparatorIndex $SeparatorIndex))

    # Return the syslogouptut string
    return $syslogoutput
}
#endregion

#region CyberArk Data
function Get-PSMSessionCount
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    #PSM Session Count
    $MonitorType = "ApplicationMonitor"

    # Create an array to hold the user data.
    $localHeader = New-Object System.Collections.Generic.List[string]
    $localHeader.Add($SYSLOGMESSAGEHEADER)
    $localHeader.Add($SYSLOGAPPLICATIONNAME)
    $localHeader.Add($MonitorType)
    $localHeader.Add($Version)
    $localHeader.Add($TargetHostName)
    
    # Test if the command exists.
    if ((Test-CommandExists -Command Get-RDUserSession) -and (Test-RoleInstalled -RoleName "Remote-Desktop-Services" -TargetHostName $TargetHostName))
    {
        # The Get-RDUserSession command exists and the Role of Rmeote Desktop Services is installed.
        # Check if the Deployment exists.
        if (Test-RDDeploymentExists -TargetHostName $TargetHostName)
        {
            $PSMSessionInformation = Get-RDUserSession
            $PSMSessionCount = $PSMSessionInformation | Measure-Object | Format-Table -HideTableHeaders Count | Out-String

            $localHeader.Add("Remote Desktop User Sessions")
            $localHeader.Add($PSMSessionCount)
            $localHeader.Add("")
        }
        else
        {
            # Remote Desktop Services is installed but no deployment exists.
            $localHeader.Add("Remote Desktop User Sessions")
            $localHeader.Add(0)
            $localHeader.Add("Remote Desktop Services Deployment or Collection Missing!")
        }
        
    }
    else
    {
        # Remote Desktop Services is not installed
        $localHeader.Add("Remote Desktop User Sessions")
        $localHeader.Add(0)
        $localHeader.Add("Remote Desktop Services Role Not Installed!")
    }
    
    # Build the output string
    $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    #cleanup command to remove new lines and carriage returns
    $syslogoutputclean = $syslogoutput -replace "`n|`r"

    return $syslogoutputclean
}

function Get-HostPerformance
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    Write-Host "Getting OS Monitor information for host."

    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Hardware"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    
    # Get the related CIMInstance details from CIM session
    $TargetHostComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $TargetCIMSession
    $TargetHostMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -CimSession $TargetCIMSession
    $TargetHostProcessor = Get-CimInstance -ClassName Win32_Processor -CimSession $TargetCIMSession
    $TargetHostOperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $TargetCIMSession
    $TargetHostDrives = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $TargetCIMSession

    #Hardware Performance Checks
    $CPU = ($TargetHostProcessor | Measure-Object -property LoadPercentage -Average | Select-Object Average).Average
    $FreePhysicalMemoryMB = $TargetHostOperatingSystem.FreePhysicalMemory
    $TotalPhysicalMemory = ($TargetHostMemory.Capacity | Measure-Object -Sum).Sum
    $TotalPhysicalMemoryMB = $TotalPhysicalMemory / 1024
    $PercentageUsedPhysicalMemory = (1 - ($FreePhysicalMemoryMB/$TotalPhysicalMemoryMB)) * 100
    $MemoryDecimal = $PercentageUsedPhysicalMemory
    $Memory = [math]::Round($MemoryDecimal,1)
    $TotalSpace = $TargetHostDrives | Where-Object{$_.DeviceID -like "*C*"} | Format-Table -HideTableHeaders Size | Out-String
    $FreeSpace = $TargetHostDrives | Where-Object{$_.DeviceID -like "*C*"} | Format-Table -HideTableHeaders FreeSpace | Out-String
    $TotalSpaceGBDecimal = $TotalSpace / 1073741824
    $FreeSpaceGBDecimal = $FreeSpace / 1073741824
    $TotalSpaceGB = [math]::Round($TotalSpaceGBDecimal,1)
    $FreeSpaceGB = [math]::Round($FreeSpaceGBDecimal,1)
    $IPAddress = ((Get-NetIPAddress -AddressFamily IPv4 -CimSession $TargetCIMSession -PrefixOrigin Manual,Dhcp).IPAddress -join ",")

    # Build output string attributes.
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostComputerSystem.Name,
        $CPU,
        $Memory,
        $TotalSpaceGB,
        $FreeSpaceGB,
        "",
        "",
        $IPAddress
    )
    
    # Build output string
    $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    #cleanup command to remove new lines and carriage returns
    $syslogoutputclean = $syslogoutput -replace "`n|`r"

    return $syslogoutputclean
}

function Get-OSMonitor
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    Write-Host "Getting OS Monitor information for host."

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
    
    
    # Get the related CIMInstance details from CIM session
    $TargetHostComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $TargetCIMSession
    $TargetHostOperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $TargetCIMSession

    #OS System Information
    $MonitorType = "OSMonitor"
    $OSName = $TargetHostOperatingSystem.Caption | Out-String
    $OSVersion = $TargetHostOperatingSystem.Version | Out-String
    $OSServPack = $TargetHostOperatingSystem.ServicePackMajorVersion | Out-String
    $OSArchitecture = $TargetHostOperatingSystem.OSArchitecture | Out-String
    $IPAddress = ((Get-NetIPAddress -AddressFamily IPv4 -CimSession $TargetCIMSession -PrefixOrigin Manual,Dhcp).IPAddress -join ",")

    # Build output string attributes.
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostName,
        $OSName,
        $OSVersion,
        $OSServPack,
        $OSArchitecture,
        "",
        $IPAddress
    )
    
    # Build output string
    $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    #cleanup command to remove new lines and carriage returns
    $syslogoutputclean = $syslogoutput -replace "`n|`r"

    return $syslogoutputclean
}

function Get-LocalAdministratorLogon
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    # Get the last logon time stamp for local admin users
    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Logon"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
        
    # Get the related CIMInstance details from CIM session
    $TargetHostUserAccounts = Get-CimInstance -ClassName Win32_UserAccount -CimSession $TargetCIMSession -Filter "Domain='$($TargetHostName)'"
    
    $LocalAdministrator = $TargetHostUserAccounts | Select-Object * | Where-Object SID -Like "*500"
    $LastLogon = (Get-LocalUser -SID $LocalAdministrator.SID).LastLogon

    # Build output string attributes.
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostName,
        $LocalAdministrator.Name,
        $LocalAdministrator.SID,
        $LastLogon
    )
    
    # Build output string
    $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    #cleanup command to remove new lines and carriage returns
    $syslogoutputclean = $syslogoutput -replace "`n|`r"

    # Return the data
    return $syslogoutputclean
}
function Get-AdministratorLogons
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    # Get the last logon time stamp for local admin users
    # Set the monitor type for this section.
    $MonitorType = $COLLECTIONMONITORTYPES["Logon"]

    # Get the CIM session for host.  Check if the passed in host name is the local host.
    if ($TargetHostName -ieq ((Get-CimInstance -ClassName Win32_ComputerSystem).Name))
    {
        $TargetCIMSession = New-CimSession
    }
    else
    {
        $TargetCIMSession = New-CimSession -ComputerName $TargetHostName
    }
        
    # Get the related CIMInstance details from CIM session
    $TargetHostUserAccounts = Get-CimInstance -ClassName Win32_UserAccount -CimSession $TargetCIMSession -Filter "Domain='$($TargetHostName)'"
    $TargetHostAdminGroup = Get-CimInstance -ClassName Win32_Group -CimSession $TargetCIMSession -Filter "SID = 'S-1-5-32-544'"
    $TargetGroupMembers = Get-TargetGroupMembers -GroupName $TargetHostAdminGroup.Name -GroupDomain $TargetHostName -Bare
    
    # Loop over the group members.
    foreach ($_member in $TargetGroupMembers)
    {
        # Get user details
        Write-Host ("WinNT://{0}/{1}" -f $_member.Domain, $_member.Name)
        $LastLogon = (Get-LocalUser -Name $_member.Name).LastLogon
        $userTarget = ("WinNT://{0}/{1},User" -f $_member.Domain, $_member.Name)
        #$userObject = [ADSI]$userTarget
        #$userObject.GetType()
        #$userObject | Select-Object *
        $userDetails = ""
        Write-Host ("")
    }

    $LocalAdministrator = $TargetHostUserAccounts | Select-Object * | Where-Object SID -Like "*500"
    $LastLogon = (Get-LocalUser -SID $LocalAdministrator.SID).LastLogon

    # Build output string attributes.
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostName,
        $LocalAdministrator.Name,
        $LocalAdministrator.SID,
        $LastLogon
    )
    
    # Build output string
    $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)

    #cleanup command to remove new lines and carriage returns
    $syslogoutputclean = $syslogoutput -replace "`n|`r"

    # Return the data
    return $syslogoutputclean
}
function Get-SyntheticTransactionMonitor
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetURL,
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [bool]$IgnoreSSL = $false,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    Write-Host ("Testing response time for:  ({0})" -f $TargetURL)

    $MonitorType = "SyntheticTransactionMonitor"
    
    # Disable SSL checking if needed
    if ($IgnoreSSL)
    {
        # Call skip certificate check
        Skip-CertificateCheck

    }

    # Make the web call to load the page.
    try
    {
        # Setup headers needed to make the request.
        $_headers = @{
            'user-agent' = "Chrome/109.0.0.0"
        }
        # Create a stop watch to time the page loading.
        $stopwatch = New-Object System.Diagnostics.Stopwatch

        # Start the stop watch.
        $stopwatch.Start()
        
        #$httpcheck = invoke-webrequest $TargetURL -DisableKeepAlive -UseBasicParsing -ErrorAction SilentlyContinue | Format-Table -HideTableHeaders StatusCode | Out-String
        $httpResult = invoke-webrequest $TargetURL -ErrorAction Stop -Headers $_headers

        # 
        $httpstatusCode = [int]$httpResult.StatusCode
        $httpServerInfo = $httpResult.BaseResponse.Server
        $httpMessage = $httpResult.StatusDescription
    }
    catch
    {
        $httpResult = $_.Exception.Response
        $httpServerInfo = $httpResult.Server
        Write-Warning ("HTTP Failed to load:  {0}" -f $httpResult.ResponseURI)
        $httpstatusCode = [int]$httpResult.StatusCode
        $httpMessage = $_.Exception.Message
        Write-Warning ("HTTP Response Code :  {0}" -f $httpstatusCode)
        Write-Warning ("HTTP Response Desc :  {0}" -f $httpResult.StatusDescription)
        Write-Warning ("HTTP Error Message :  {0}" -f $httpMessage)
        Write-Warning ("HTTP Server Info   :  {0}" -f $httpServerInfo)
        
    }
    finally
    {
        # Stop the stop watch
        $stopwatch.Stop()
        
        # Calculate the elapsed time
        $stopwatchms = ($stopwatch.ElapsedMilliseconds / 1000)
    }
    

    # Build output string attributes.
    $localHeader = @(
        $SYSLOGMESSAGEHEADER,
        $SYSLOGAPPLICATIONNAME,
        $MonitorType,
        $Version,
        $TargetHostName,
        $TargetURL,
        $httpstatusCode,
        $stopwatchms,
        $httpServerInfo,
        $httpMessage
    )
    
    # Build output string
    $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)
    
    #cleanup command to remove new lines and carriage returns
    $syslogoutputclean = $syslogoutput -replace "`n|`r"

    return $syslogoutputclean
}

function Get-PSMShadowUsers
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int] $SeparatorIndex = 0
    )
    #PSM Shadow User Monitor
    $MonitorType = "PSMShadowUserMonitor"

    # Create an array to hold the results.
    $PSMShadowUserDetails = New-Object System.Collections.Generic.List[string]
    $PSMShadowUsers = Get-LocalUser -Name *PSM-* | Select-Object Name,FullName
    ForEach ($name in $PSMShadowUsers) {
        $PSMShadowUserName = $name.Name
        $PSMShadowUserFullName = $name.FullName

        # Build output string attributes.
        $localHeader = @(
            $SYSLOGMESSAGEHEADER,
            $SYSLOGAPPLICATIONNAME,
            $MonitorType,
            $Version,
            $TargetHostName,
            $PSMShadowUserName,
            $PSMShadowUserFullName
        )
        
        # Build output string
        $syslogoutput = $localHeader -join (Get-TextSeparator -SeparatorIndex $SeparatorIndex)
        
        $PSMShadowUserDetails.Add($syslogoutput)
        
    }

    return $PSMShadowUserDetails
}
#endregion

#region SendData
function Send-Data
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetAddress,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int]$TargetPort,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ValidateSet("TCP","UDP")]
        [string]$TargetProtocol,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$DataToSend,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [bool]$WriteLogFile = $SYSLOGENABLEDATALOGGING,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string]$LogFileToWriteTo = $SYSLOGDATALOGFILE
    )
    # Send the data to the SYSLOG server
    if (($WriteLogFile) -and ($LogFileToWriteTo -ne ""))
    {
        Write-Information ("Writing SYSLOG data to:  {0}" -f $LogFileToWriteTo)
        # Write to the specified Log File.
        Add-Content -Path $LogFileToWriteTo -Value ($DataToSend) -ErrorAction Ignore
    }
    if ($true)
    {
        try
        {
            Write-Information ("`r`nSending SYSLOG data to ({0}:\\{1}:{2})" -f $TargetProtocol, $TargetAddress, $TargetPort)
            Write-Verbose ("Data:  {0}" -f $DataToSend)
            # Clean output
            $syslogoutputclean = $DataToSend -replace "`n|`r"

            # Convert data to JSON.  This doesn't seem to be needed.  It was wrapping the data in quotes.
            #$syslogoutputjson = ConvertTo-Json -InputObject $syslogoutputclean
            $syslogoutputjson = $syslogoutputclean

            # Convert the message from a string to a byte array.
            $Encoding = [System.Text.Encoding]::ASCII

            # Get the byte array using the specified encoding.
            $ByteSyslogMessage = $Encoding.GetBytes($syslogoutputjson)

            # Choose the protocol
            if ($TargetProtocol -ieq "UDP")
            {
                Write-Verbose ("`tStart Sending UDP")

                # Create a new UDP client
                $UDPCLient = New-Object System.Net.Sockets.UdpClient

                # Connect to the destination
                $UDPCLient.Connect($TargetAddress, $TargetPort)

                # Start sending the data.
                $null = $UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length)
                Write-Verbose ("`tFinished Sending UDP`r`n")
            }
            elseif ($TargetProtocol -ieq "TCP")
            {
                Write-Verbose ("`tStart Sending TCP")
                # Create the TCP connection using the TCP sockets client.
                $tcpSocket = New-Object System.Net.Sockets.TcpClient($TargetAddress, $TargetPort)

                # Get the TCP stream object
                $tcpStream = $tcpSocket.GetStream()

                # Create a stream writer for sending data
                $streamWriter = New-Object System.IO.StreamWriter($tcpStream)

                # Set Autoflush.
                $streamWriter.AutoFlush = $true

                # Create a stream reader for getting data
                $streamReader = New-Object System.IO.StreamReader($tcpStream)

                # Create a buffer for the stream writting.
                $streamBuffer = New-Object System.Byte[] 1024

                #Start writing the stream
                while ($tcpSocket.Connected)
                {
                    # Read data sent by the remote party.
                    while ($tcpStream.DataAvailable)
                    {
                        # Read the data from the stream using the buffer.
                        $rawResponse = $tcpStream.Read($streamBuffer, 0, 1024)

                        # Convert the raw response to a string.
                        $response = $Encoding.GetString($streamBuffer, 0, $rawResponse)

                    }
                    #
                    Write-Information ("Reading data stream:  {0}" -f $response)

                    # Write stream
                    Write-Debug ("Writing data stream:  {0}" -f ($syslogoutputjson))
                    $streamWriter.Write($ByteSyslogMessage, 0, $ByteSyslogMessage.Length)

                    # Wait for the stream to fully establish
                    Start-Sleep -m 500

                    # Break
                    break
                }
                Write-Verbose ("`tFinished Sending TCP`r`n")
            }
            
        }
        catch
        {
            Write-Warning ("Failed to send data to: ({0}:\\{1}:{2})" -f $TargetProtocol, $TargetAddress, $TargetPort)
            Write-Warning ("Data Length  :  {0:n0} Bytes" -f $ByteSyslogMessage.Length)
            Write-Warning ("Error Type   :  {0}" -f $_.GetType())
            Write-Warning ("Error Code   :  {0}" -f $_.Exception.InnerException.ErrorCode)
            Write-Warning ("`r`nError Message:  `r`n{0}" -f $_.Exception.InnerException.Message)
            Write-Warning ("`r`nError Details:  `r`n{0}" -f $_.Exception.Message)
            Write-Error ("Error:  {0}" -f $_.ErrorDetails.Message)
        }
        finally
        {
            if ($streamWriter){$streamWriter.Close()}
            if ($streamReader){$streamReader.Close()}
            if ($tcpStream){$tcpStream.Close()}
        }        
    }
    
    Write-Host ("****  Finished Sending Data  ****")
}
#endregion

#region HelperFunctions
function Get-TextSeparator
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int]$SeparatorIndex
    )
    
    # This function retrieves the charactor specified by the Separator Index number.

    $retSeparatorCharacter = $TEXTSEPARATORORDER[$SeparatorIndex]

    # Debug Information
    Write-Verbose ("Index ({0}) : Character ({1})" -f $SeparatorIndex, $retSeparatorCharacter)

    # Return the data
    return $retSeparatorCharacter
}
function Get-StringFromHashTable
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.Collections.Specialized.OrderedDictionary]$SourceHashTable,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [int]$SeparatorIndex
    )

    # Create a variable to hold the output string
    $outputString = ""
    
    # Get the text separator
    $TextSeperator = Get-TextSeparator -SeparatorIndex $SeparatorIndex

    # Loop over the Ordered HashTable and build a string
    foreach ($key in $SourceHashTable.Keys)
    {
        # Debug output
        Write-Debug ("{0}:  {1}" -f $key, $SourceHashTable[$key])

        # Append to the output string
        $outputString += $SourceHashTable[$key]
        $outputString += $TextSeperator
    }

    # Strip the trailing Separator and return the string
    return $outputString.Substring(0, $outputString.Length -($TextSeperator.Length))
}
function Test-CommandExists
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$Command
    )
    # Check to see if the command exists.  Returns True or False
    $retValue = $false

    # Get the current Error Action Preference
    $oldPreference = $ErrorActionPreference

    # Test the command
    try
    {
        # Set the desired Error Action Preference
        $ErrorActionPreference = 'stop'
        if (Get-Command $Command)
        {
            # Set the return value to true.  The command does exist.
            $retValue = $true
        }
    }
    catch
    {
        # Set the return value to false.  The command does not exist.
        $retValue = $false
    }
    finally
    {
        # Set the previous Error Action Preference
        $ErrorActionPreference = $oldPreference
    }

    # Return the result
    return $retValue
}
function Test-RoleInstalled
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$RoleName,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    # Check to see if the command exists.  Returns True or False
    $retValue = $false

    # If this runs on the vault an exception will be thrown because the Windows Installer service is stopped.
    try
    {
        # Get the information about the role
        $RoleState = (Get-WindowsFeature -Name $RoleName -ComputerName $TargetHostName).InstallState

        # Check if the role state is Installed or Available.
        if ($RoleState -ieq "Installed")
        {
            #The role is installed.
            $retValue = $true
        }
    }
    catch
    {
        Write-Warning ('Is the "Windows Modules Installer" service stopped?')
    }

    # Return the result
    return $retValue
}
function Test-RDDeploymentExists
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    # Check to see if the command exists.  Returns True or False
    $retValue = $false

    # Get the current Error Action Preference
    $oldPreference = $ErrorActionPreference

    # Test the command
    try
    {
        # Set the desired Error Action Preference
        $ErrorActionPreference = 'stop'
        if (Get-RSDessionCollection)
        {
            # Set the return value to true.  The command does exist.
            $retValue = $true
        }
    }
    catch
    {
        # Set the return value to false.  The command does not exist.
        $retValue = $false
    }
    finally
    {
        # Set the previous Error Action Preference
        $ErrorActionPreference = $oldPreference
    }

    # Return the result
    return $retValue
}
Function Skip-CertificateCheck 
{
	<#
	.SYNOPSIS
	Bypass SSL Validation

	.DESCRIPTION
	Enables skipping of ssl certificate validation for current PowerShell session.

	.EXAMPLE
	Skip-CertificateCheck

	#>

	$CompilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
	$CompilerParameters.GenerateExecutable = $false
	$CompilerParameters.GenerateInMemory = $true
	$CompilerParameters.IncludeDebugInformation = $false
	$CompilerParameters.ReferencedAssemblies.Add("System.DLL") | Out-Null
	$CertificatePolicy = @'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@

    $CSharpCodeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $PolicyResult = $CSharpCodeProvider.CompileAssemblyFromSource($CompilerParameters, $CertificatePolicy)
    $CompiledAssembly = $PolicyResult.CompiledAssembly
    ## Create an instance of TrustAll and attach it to the ServicePointManager
    $TrustAll = $CompiledAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll

}

#endregion


function Find-AllInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )

    #  This will collect the data related to
    #    All CyberArk Components
    #    Information about the local Host, Users, and Groups.
    #    Information about the installed software.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "All"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
    
    # Call Each Section.
     Find-HostInfo -TargetHostName $TargetHostName
     Find-HostNetworking -TargetHostName $TargetHostName
    # Find-HostDrives -TargetHostName $TargetHostName
    # Find-HostFirewall -TargetHostName $TargetHostName
    # Find-HostUsers -TargetHostName $TargetHostName
    # Find-HostGroups -TargetHostName $TargetHostName
    # Find-HostSoftware -TargetHostName $TargetHostName -UseFilter $false
    # Find-VaultInfo -TargetHostName $TargetHostName
    # Find-PVWAInfo -TargetHostName $TargetHostName
    # Find-CPMInfo -TargetHostName $TargetHostName
    # Find-PSMInfo -TargetHostName $TargetHostName
    # Find-CCPInfo -TargetHostName $TargetHostName
    # Find-CVCSInfo -TargetHostName $TargetHostName

    # Need to fix the other data collections.
    # Need to fix the sending of the SYSLOG data.

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}
#region ComponentCollectionFlow
function Find-HostInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    #  This will collect information about the local Host, Users, and Groups.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Local Host Information"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
    $_DataToSend = Get-HostInfo -TargetHostName $TargetHostName

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }
    
    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}

function Find-HostUsers
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    #  This will collect information about the local Host, Users, and Groups.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Local Host Users"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)

    # Get the host user information.
    $_DataToSend = Get-HostUsers -TargetHostName $TargetHostName

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}

function Find-HostGroups
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    #  This will collect information about the local Host, Users, and Groups.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Local Host Groups"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
    $_DataToSend = Get-HostGroups -TargetHostName $TargetHostName

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}

function Find-HostSoftware
{
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false,
				   Position = 0)]
		[bool] $UseFilter,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
	)
    #  This will collect information about the locally installed software.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Locally Installed Software"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
    # Collect Installed Software Names, Version, Install Date, and Who Installed it.
    $_DataToSend = Get-HostInstalledSoftware -TargetHostName $TargetHostName -UseFilter $UseFilter

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}

function Find-HostNetworking
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    #  This will collect information about the local Host, Users, and Groups.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Local Host Networking"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
    $_DataToSend = Get-HostNetworkInfo -TargetHostName $TargetHostName

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }
    
    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}
function Find-HostDrives
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    #  This will collect information about the local Host, Users, and Groups.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Local Host Drives"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
    $_DataToSend = Get-HostDriveInfo -TargetHostName $TargetHostName

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}

function Find-HostFirewall
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    #  This will collect information about the local Host, Users, and Groups.
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Local Host Firewall"

    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)

    $_DataToSend = Get-HostFirewallInfo -TargetHostName $TargetHostName -Direction Inbound

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }

    $_DataToSend = Get-HostFirewallInfo -TargetHostName $TargetHostName -Direction Outbound

    # Loop over the array to send.
    foreach ($message in $_DataToSend)
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $message
    }
    
    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}
function Find-HostCommonInfo
{
    [CmdletBinding()]
	Param (
		[parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
	)
    # The data in this section is collected for every component type.
    $ThisComponentAbbreviation = "Common"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)

    # Collect HardwareMonitor
    $_PerfResult = Get-HostPerformance -TargetHostName $TargetHostName

    # Send the data to the SYSLOG server
    if (($null -ne $_PerfResult) -and ($_PerfResult -ne ""))
    {
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_PerfResult
    }

    # Collect OSMonitor
    $_OSResult = Get-OSMonitor -TargetHostName $TargetHostName

    # Send the data to the SYSLOG server
    if (($null -ne $_OSResult) -and ($_OSResult -ne ""))
    {
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_OSResult
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $ThisComponentAbbreviation)
}

function Find-VaultInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )
    #  This will collect the data related to the
    #  CyberArk Component:  Vault
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "Vault"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
    # Collect Service Information & Send.
    foreach ($_Service in $CYBERARKSERVICENAMES[$ThisComponentAbbreviation])
    {
        # Get the service details.
        $_ServiceResult = Get-TargetServiceInfo -ServiceName $_Service -ComponentName $ThisComponentAbbreviation -TargetHostName $TargetHostName
        
        # Send the data to the SYSLOG server
        if (($null -ne $_ServiceResult) -and ($_ServiceResult -ne ""))
        {
            #
            Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_ServiceResult
        }
    }

    # Collect LogMonitor
    $_LogonResults = Get-LocalAdministratorLogon -TargetHostName $TargetHostName

    # Send the data to the SYSLOG server
    if (($null -ne $_LogonResults) -and ($_LogonResults -ne ""))
    {
        #
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_LogonResults
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
}

function Find-PVWAInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )

    #  This will collect the data related to the
    #  CyberArk Component:  PVWA
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "PVWA"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
    
    # Collect Service Information & Send.
    #  Get the array of services related to this component.
    $_Services = $CYBERARKSERVICENAMES[$ThisComponentAbbreviation]

    #  Loop over the array of services to get information about each service.
    foreach ($_Service in $_Services)
    {
        
        # Get the service details.
        $_ServiceResult = Get-TargetServiceInfo -ServiceName $_Service -ComponentName $ThisComponentAbbreviation -TargetHostName $TargetHostName
        
        # Send the data to the SYSLOG server
        if (($null -ne $_ServiceResult) -and ($_ServiceResult -ne ""))
        {
            #
            Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_ServiceResult
        }
        
    }
    
    # Collect PVWA SyntheticTransactionMonitor
    if ($true)
    {
        # Loop over the entries in the variable.
        foreach ($targetSite in $PVWAURL)
        {
            #  Only one end point needs to be tested.  We are just getting the time it takes to load.
            $_DataToSend = Get-SyntheticTransactionMonitor -TargetHostName $TargetHostName -TargetURL ("https://{0}/{1}" -f $PVWAURL, $PVWAENDPOINTSTOTEST[$PVWALogonType]) -IgnoreSSL $PVWAIGNORESSL

            # Send the data to the SYSLOG server
            if (($null -ne $_DataToSend) -and ($_DataToSend -ne ""))
            {
                #
                Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_DataToSend
            }
        }
        
    }
    

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
}

function Find-CPMInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )

    #  This will collect the data related to the
    #  CyberArk Component:  CPM
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "CPM"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
    # Collect Service Information & Send.
    foreach ($_Service in $CYBERARKSERVICENAMES[$ThisComponentAbbreviation])
    {
        # Get the service details.
        $_ServiceResult = Get-TargetServiceInfo -ServiceName $_Service -ComponentName $ThisComponentAbbreviation -TargetHostName $TargetHostName
        
        # Send the data to the SYSLOG server
        if (($null -ne $_ServiceResult) -and ($_ServiceResult -ne ""))
        {
            #
            Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_ServiceResult
        }
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
}

function Find-PSMInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )

    #  This will collect the data related to the
    #  CyberArk Component:  PSM
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "PSM"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
    # Collect Service Information & Send.
    foreach ($_Service in $CYBERARKSERVICENAMES[$ThisComponentAbbreviation])
    {
        # Get the service details.
        $_ServiceResult = Get-TargetServiceInfo -ServiceName $_Service -ComponentName $ThisComponentAbbreviation -TargetHostName $TargetHostName
        
        # Send the data to the SYSLOG server
        if (($null -ne $_ServiceResult) -and ($_ServiceResult -ne ""))
        {
            #
            Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_ServiceResult
        }
    }
    
    # Collect RDS/PSM Session Count
    $_PSMSessionCount = Get-PSMSessionCount -TargetHostName $TargetHostName

    # Check to see if any data was returned.
    if (($_PSMSessionCount))
    {
        # Send the data to the SYSLOG server
        Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_PSMSessionCount
    }

    # Collect PSM Shadow Users.  This returns an array that we need to loop over.
    $_PSMShadowUsers = Get-PSMShadowUsers

    # Check to see if any data was returned.
    if (($_PSMShadowUsers) -and ($_PSMShadowUsers.count -gt 0))
    {
        foreach ($_shadowUser in $_PSMShadowUsers)
        {
            # Cast the returned data to a string.
            $_shadowUser = [string]$_shadowUser

            # Send the data to the SYSLOG server
            Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_shadowUser
        }
    }
    
    
    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
}

function Find-CCPInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )

    #  This will collect the data related to the
    #  CyberArk Component:  CCP
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "CCP"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
    # Collect Service Information & Send.
    foreach ($_Service in $CYBERARKSERVICENAMES[$ThisComponentAbbreviation])
    {
        # Get the service details.
        $_ServiceResult = Get-TargetServiceInfo -ServiceName $_Service -ComponentName $ThisComponentAbbreviation -TargetHostName $TargetHostName
        
        # Send the data to the SYSLOG server
        if (($null -ne $_ServiceResult) -and ($_ServiceResult -ne ""))
        {
            #
            Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_ServiceResult
        }
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
}

function Find-CVCSInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]$TargetHostName
    )

    #  This will collect the data related to the
    #  CyberArk Component:  CVCS
    #  This data will be sent to the SIEM specified.
    $ThisComponentAbbreviation = "CVCS"
    Write-Host ("{0} Starting Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
    # Collect Service Information & Send.
    foreach ($_Service in $CYBERARKSERVICENAMES[$ThisComponentAbbreviation])
    {
        # Get the service details.
        $_ServiceResult = Get-TargetServiceInfo -ServiceName $_Service -ComponentName $ThisComponentAbbreviation -TargetHostName $TargetHostName
        
        # Send the data to the SYSLOG server
        if (($null -ne $_ServiceResult) -and ($_ServiceResult -ne ""))
        {
            #
            Send-Data -TargetAddress $SYSLOGSERVER -TargetPort $SYSLOGPORT -TargetProtocol $SYSLOGPROTOCOL -DataToSend $_ServiceResult
        }
    }

    Write-Host ("{0} Finished Data Collection For {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $CYBERARKCOMPONENTNAMES[$ThisComponentAbbreviation])
}


#endregion
#region FlowControl
Write-Debug "****  Starting  ****"
Write-Host ("{0} Selected Component(s):  {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), ($CollectionProfile -join ","))

# Get the common information.  Information that is collected for every component type.
Find-HostCommonInfo -TargetHostName $TheLocalHostName
#Get-CertificateInformationIIS -TargetHostName $TheLocalHostName
#exit

# Loop over the Selected Component(s) "CollectionProfile".
foreach ($tc in $CollectionProfile)
{
    Write-Host ("{0} Processing Component:  {1}" -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $tc)
    #  Choose what to run.  There should be a seperate entry for each CollectionProfile type.
    #    This is the Validation set options
    #    [ValidateSet("All", "LocalHostInfo", "LocalUsers", "LocalGroups", "LocalSoftwareAll", "LocalSoftwareFilter", "Vault", "PVWA", "CPM", "PSM", "CCP", "CVCS")]
    
    if      ($tc -ieq "All")             {Find-AllInfo -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalHostInfo")   {Find-HostInfo -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalHostNetwork"){Find-HostNetworking -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalHostDrives") {Find-HostDrives -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalHostFirewall"){Find-HostFirewall -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalUsers")      {Find-HostUsers -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalGroups")     {Find-HostGroups -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalSoftwareAll"){Find-HostSoftware -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "LocalSoftwareFilter"){Find-HostSoftware  -TargetHostName $TheLocalHostName -UseFilter $true}
    elseif  ($tc -ieq "Vault")           {Find-VaultInfo -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "PVWA")            {Find-PVWAInfo -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "CPM")             {Find-CPMInfo -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "PSM")             {Find-PSMInfo -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "CCP")             {Find-CCPInfo -TargetHostName $TheLocalHostName}
    elseif  ($tc -ieq "CVCS")            {Find-CVCSInfo -TargetHostName $TheLocalHostName}
    else{Write-Error ("Invalid Component Specified!  {0}" -f $tc)}
}

Write-Host ("{0} SYSLOG data collection & data send has completed." -f $(Get-Date -Format "yyyy-MM-dd hh:mm:ss"))
Write-Debug "****  Finished  ****"
#endregion


