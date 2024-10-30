<#
.SYNOPSIS
	Checks if a VMware virtual machine (VM) exists in inventory and prompts the user for action if it does.

.DESCRIPTION
	This function verifies whether a specified VM is already present in the VMware inventory. 
	If the VM exists, it prompts the user with options to re-import the VM, delete it, or retain it.
	The function optionally takes a pre-set answer parameter to automate user input, allowing for
	batch or non-interactive operations.

.PARAMETER Vm
	Specifies the virtual machine object to check in the VMware inventory.
	This parameter is mandatory.

.PARAMETER Answer
	(Optional) A predefined answer to bypass user interaction. Valid values are:
	- 'y': Yes, remove and re-import the VM.
	- 'a': Yes to all, apply to all remaining VMs in batch mode.
	- 'n': No, skip the VM.
	- 'l': No to all, skip all remaining VMs in batch mode.
	Defaults to $null, which prompts for interactive input.

.EXAMPLE
	# Prompts the user if the VM is already in inventory
	Test-VMForReImport -Vm $vmObject

	# Uses a predefined answer to avoid prompts
	Test-VMForReImport -Vm $vmObject -Answer 'y'

.NOTES
	This function returns a boolean and the answer string, indicating whether the VM was removed
	and whether to apply the action to subsequent VMs in batch mode.
#>

function Test-VMForReImport {
    param (
        [Parameter(Mandatory = $true)] 
        [AllowNull()]
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VirtualMachineImpl]
        $Vm,

        [Parameter()] 
        [AllowNull()]
        [string]
        $Answer = $null
    )

    # Return true if no VM object is provided (prevents errors when VM is null)
    if ($null -eq $Vm) {
        return $true, $Answer
    }

    # Prompt the user if no answer is provided
    if ([string]::IsNullOrEmpty($Answer)) {
        Write-Host -ForegroundColor Magenta "`nA VM named '$($vm.Name)' already in the inventory.`nDo you want re-import '$($vm.Name)'"
        do {
            $readAnswer = Read-Host -Prompt "[Y] Yes  [A] Yes to All  [N] No  [L] No to All"
        } until ('y', 'a', 'n', 'l' -contains $readAnswer)
    }
    else {
        # Use provided answer if available
        $readAnswer = $Answer
    }

    # Process the response based on user input or provided answer
    switch ($readAnswer) {
        'a' {
            # 'Yes to all' - Power off and delete VM permanently
            if ($vm.PowerState -eq 'PoweredOn') {
                Write-Logger "Powering Off $($vm.name) ..."
                Stop-VM $vm -Confirm:$false | Out-Null
            }
            Write-Logger "Removing $($vm.name) ..."
            Remove-VM -VM $vm -DeletePermanently -Confirm:$false | Out-Null
            return $true, 'y'
        }
        'y' {
            # 'Yes' - Power off and delete VM permanently
            if ($vm.PowerState -eq 'PoweredOn') {
                Write-Logger "Powering Off $($vm.name) ..."
                Stop-VM $vm -Confirm:$false | Out-Null
            }
            Write-Logger "Removing $($vm.name) ..."
            Remove-VM -VM $vm -DeletePermanently -Confirm:$false | Out-Null
            return $true, $Answer
        }
        'l' {
            # 'No to all' - Skip VM without deleting
            return $false, 'n'
        }
        'n' {
            # 'No' - Skip VM without deleting
            return $false, $Answer
        }
    }    
}


Function Write-Logger {
    param(
        [Parameter(Mandatory = $true)][String]$message,
        [Parameter(Mandatory = $false)][String]$color = "green"
    )

    $timeStamp = Get-Date -Format "MM-dd-yyyy_hh:mm:ss"

    Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
    Write-Host -ForegroundColor $color " $message"
    $logMessage = "[$timeStamp] $message"
    $logMessage | Out-File -Append -LiteralPath $verboseLogFile
}


<#
.SYNOPSIS
	Returns a list of transport zones based on the specified type and site code.

.DESCRIPTION
	This function provides transport zone configurations for NSX based on the specified type (e.g., 'Overlay', 'VLAN', or 'Overlay/VLAN'). 
	It optionally allows specifying a site code to generate transport zone names customized for a specific site.

.PARAMETER Type
	Specifies the type of transport zone(s) to retrieve. Valid values are:
	- 'Overlay': Returns only the Overlay transport zone.
	- 'VLAN': Returns only the VLAN transport zone.
	- 'Overlay/VLAN': Returns both Overlay and VLAN transport zones.
	This parameter is mandatory.

.PARAMETER SiteCode
	(Optional) Specifies the site code used to customize the transport zone name.
	Defaults to "sfo-m01".

.EXAMPLE
	# Returns both Overlay and VLAN transport zones for the default site code.
	Get-TransportZone -Type "Overlay/VLAN"

	# Returns only the Overlay transport zone for the site code "nyc-m01".
	Get-TransportZone -Type "Overlay" -SiteCode "nyc-m01"

.NOTES
	This function returns an array of ordered dictionaries, each representing a transport zone with a name and transport type.
#>

function Get-TransportZone {
    param(
        [Parameter(Mandatory = $true)]
        $Type,

        [Parameter(Mandatory = $false)]
        $SiteCode = "sfo-m01"
    )

    # Determine the transport zone(s) to return based on the specified Type
    switch ($Type) {
        'Overlay/VLAN' {
            # Return both Overlay and VLAN transport zones
            return @(
                [ordered]@{
                    name          = "$SiteCode-tz-overlay01"
                    transportType = "OVERLAY"
                }
                [ordered]@{
                    name          = "$SiteCode-tz-vlan01"
                    transportType = "VLAN"
                }
            )
        }  
        'Overlay' {
            # Return only the Overlay transport zone
            return  @(
                [ordered]@{
                    name          = "$SiteCode-tz-overlay01"
                    transportType = "OVERLAY"
                }
            )
        }  
        'VLAN' {
            # Return only the VLAN transport zone
            return   @(
                [ordered]@{
                    name          = "$SiteCode-tz-vlan01"
                    transportType = "VLAN"
                }
            )
        }
        default {
            # Return an empty array for unsupported transport types
            return  @()
        }  
    }
}

<#
.SYNOPSIS
	Converts a CIDR notation network address into a dotted decimal netmask.

.DESCRIPTION
	This function takes a network address in CIDR notation (e.g., "192.168.1.0/24") and converts the CIDR prefix length into a standard dotted decimal netmask format (e.g., "255.255.255.0").

.PARAMETER NetworkCIDR
	Specifies the network address in CIDR notation (e.g., "192.168.1.0/24"). The input should include both the network portion and the CIDR prefix length.

.RETURNS
	Returns a string representation of the netmask in dotted decimal format.

.EXAMPLE
	# Convert a CIDR notation address to a dotted decimal netmask
	ConvertTo-Netmask -NetworkCIDR "192.168.1.0/24"

.NOTES
	This function is useful for networking scenarios where the CIDR prefix length needs to be converted into a dotted decimal format.
#>

function ConvertTo-Netmask {
    param (
        [string]$NetworkCIDR
    )

    # Split the network address and CIDR value
    $network, $cidr = $NetworkCIDR -split '/'
    $cidr = [int]$cidr

    # Create the binary representation of the netmask by creating $cidr number of 1's followed by 0's to make a 32-bit binary string
    $binaryMask = "1" * $cidr + "0" * (32 - $cidr)

    # Convert each 8-bit segment of the binary mask into a decimal octet and format it as an IP address
    $netmask = [System.Net.IPAddress]::Parse(
        [string]([convert]::ToInt32($binaryMask.Substring(0, 8), 2)) + "." +
        [string]([convert]::ToInt32($binaryMask.Substring(8, 8), 2)) + "." +
        [string]([convert]::ToInt32($binaryMask.Substring(16, 8), 2)) + "." +
        [string]([convert]::ToInt32($binaryMask.Substring(24, 8), 2))
    )
    
    # Return the netmask in dotted decimal format
    return $netmask.IPAddressToString
}

<#
.SYNOPSIS
	Converts a hashtable to a .psd1-compatible string format.

.DESCRIPTION
	This function takes a hashtable and converts it into a properly formatted string representation 
	that can be saved as a .psd1 file, preserving data types and hierarchical structure. 
	Supports nested hashtables, arrays, and common PowerShell data types.

.PARAMETER Hashtable
	The hashtable to convert into a .psd1-compatible string. This parameter is mandatory.

.PARAMETER IndentLevel
	Specifies the current indentation level for formatting nested structures. Defaults to 0. 
	This parameter is primarily used internally for recursive formatting.

.RETURNS
	Returns a formatted string representation of the hashtable, suitable for saving as a .psd1 file.

.EXAMPLE
	# Converts a nested hashtable to a .psd1-compatible format
	$myHashtable = @{
		Name = 'Example'
		Settings = @{
			Enabled = $true
			Values = @('One', 'Two', 'Three')
		}
	}
	Convert-HashtableToPsd1String -Hashtable $myHashtable

.NOTES
	This function supports common data types like strings, integers, booleans, arrays, and nested hashtables.
	Customizes formatting based on type for readability and .psd1 compatibility.
#>

function Convert-HashtableToPsd1String {
    param (
        [Parameter(Mandatory)]
        [hashtable]$Hashtable,

        [int]$IndentLevel = 0  # Parameter to track the current indentation level
    )

    # Generate indentation for the current level
    $indentation = ("`t" * $IndentLevel)
    $output = $indentation + "[ordered]@{" + [Environment]::NewLine

    # Process each key-value pair in the hashtable
    $Hashtable.GetEnumerator() | ForEach-Object {
        $key = $_.Key
        $value = $_.Value
        $currentIndentation = ("`t" * ($IndentLevel + 1)) # Next level indentation

        # Check for nested hashtables and convert recursively
        if ($value -is [System.Collections.Hashtable] -or $value -is [System.Collections.IDictionary]) {
            $output += "$currentIndentation`"$key`" = " + (Convert-HashtableToPsd1String -Hashtable $value -IndentLevel ($IndentLevel + 1)) + [Environment]::NewLine
        }
        # Format string values with quotes
        elseif ($value -is [string]) {
            $output += "$currentIndentation`"$key`" = '$value'" + [Environment]::NewLine
        }
        # Format numeric values without quotes
        elseif ($value -is [int] -or $value -is [double]) {
            $output += "$currentIndentation`"$key`" = $value" + [Environment]::NewLine
        }
        # Format boolean values without quotes, prefixed by '$'
        elseif ($value -is [boolean]) {
            $output += "$currentIndentation`"$key`" = `$$value" + [Environment]::NewLine
        }
        # Handle null values explicitly
        elseif ($null -eq $value) {
            $output += "$currentIndentation`"$key`" = `$null" + [Environment]::NewLine
        }
        # Handle array values, iterating over each item
        elseif ($value -is [array]) {
            $arrayOutput = "$currentIndentation`"$key`" = @(" + [Environment]::NewLine
            foreach ($item in $value) {
                # Handle nested hashtables within arrays
                if ($item -is [hashtable] -or $item -is [System.Collections.IDictionary]) {
                    $arrayOutput += (Convert-HashtableToPsd1String -Hashtable $item -IndentLevel ($IndentLevel + 2)).Replace("[ordered]@{", "$currentIndentation`t[ordered]@{") + [Environment]::NewLine
                }
                # Format strings within arrays
                elseif ($item -is [string]) {
                    $arrayOutput += "$currentIndentation`t'$item'" + [Environment]::NewLine
                }
                # Format numeric values within arrays
                elseif ($item -is [int] -or $item -is [double]) {
                    $arrayOutput += "$currentIndentation`t$item" + [Environment]::NewLine
                }
                else {
                    # Handle any other types within arrays
                    $arrayOutput += "$currentIndentation`t$item" + [Environment]::NewLine
                }
            }
            $arrayOutput += "$currentIndentation)" + [Environment]::NewLine
            $output += $arrayOutput
        } 
        else {
            throw "Unsupported type '$($value.GetType())' for key '$key'. Only common types, hashtables, and arrays are supported."
        }
    }

    # Close the ordered hashtable structure
    $output += "$indentation}" + [Environment]::NewLine
    return $output
}

<#
.SYNOPSIS
	Generates a JSON-compliant ordered hashtable representing a workload configuration.

.DESCRIPTION
	This function constructs an ordered hashtable based on the input data, adhering to a specific structure needed for workload deployments. 
	The function organizes various parameters such as management settings, network specifications, vSAN configurations, and NSX-T settings, 
	making it suitable for converting to JSON for API usage or configuration files.

.PARAMETER InputData
	An ordered hashtable containing all necessary input data for generating the workload configuration, including SDDC, NSX, and vSAN details.

.RETURNS
	Returns an ordered hashtable representing the workload configuration.

.EXAMPLE
	# Create a workload configuration hashtable
	$workloadConfig = Get-JsonWorkload -InputData $inputData

.NOTES
	This function is designed to work with ordered hashtables, ensuring the order of keys is maintained in the output.
	Useful for generating JSON configurations for infrastructure deployments.
#>

function Get-JsonWorkload {
    param (
        [System.Management.Automation.OrderedHashtable]
        $InputData
    ) 

    # Construct the ordered hashtable with nested structures for workload configuration
    return [ordered]@{
        # Top-level settings for deployment
        deployWithoutLicenseKeys    = $InputData.DeployWithoutLicenseKeys
        skipEsxThumbprintValidation = $InputData.SkipEsxThumbprintValidation
        managementPoolName          = $InputData.Management.PoolName

        # SDDC Manager specifications
        sddcManagerSpec             = [ordered]@{
            secondUserCredentials = [ordered]@{
                username = "vcf"
                password = $InputData.SddcManager.Hostname.VcfPassword
            }        
            ipAddress             = $InputData.SddcManager.Hostname.Ip
            hostname              = $InputData.SddcManager.Hostname.Hostname
            rootUserCredentials   = [ordered]@{
                username = 'root'
                password = $InputData.SddcManager.Hostname.RootPassword
            }
            localUserPassword     = $InputData.SddcManager.Hostname.LocalPassword        
        }
        sddcId                      = $InputData.SddcId
        esxLicense                  = $InputData.EsxLicense 
        workflowType                = "VCF"
        ceipEnabled                 = $InputData.CeipEnabled
        fipsEnabled                 = $InputData.FipsEnabled

        # Network and DNS configuration
        ntpServers                  = $InputData.NetworkSpecs.NtpServers
        dnsSpec                     = [ordered]@{
            subdomain  = $InputData.NetworkSpecs.DnsSpec.Subdomain
            domain     = $InputData.NetworkSpecs.DnsSpec.Domain
            nameserver = $InputData.NetworkSpecs.DnsSpec.NameServers
        }
        networkSpecs                = @(
            # Management network configuration
            [ordered]@{
                networkType  = "MANAGEMENT"
                subnet       = $InputData.NetworkSpecs.ManagementNetwork.subnet
                gateway      = $InputData.NetworkSpecs.ManagementNetwork.gateway
                vlanId       = $InputData.NetworkSpecs.ManagementNetwork.vLanId
                mtu          = $InputData.NetworkSpecs.ManagementNetwork.Mtu
                portGroupKey = $InputData.NetworkSpecs.ManagementNetwork.portGroupKey    
            },
            # vMotion network configuration
            [ordered]@{
                networkType            = "VMOTION"
                subnet                 = $InputData.NetworkSpecs.vMotionNetwork.subnet
                gateway                = $InputData.NetworkSpecs.vMotionNetwork.gateway
                vlanId                 = $InputData.NetworkSpecs.vMotionNetwork.vLanId
                mtu                    = $InputData.NetworkSpecs.vMotionNetwork.Mtu
                portGroupKey           = $InputData.NetworkSpecs.vMotionNetwork.portGroupKey
                includeIpAddressRanges = @(
                    [ordered]@{
                        endIpAddress   = $InputData.NetworkSpecs.vMotionNetwork.Range.End
                        startIpAddress = $InputData.NetworkSpecs.vMotionNetwork.Range.Start
                    }
                )
            },
            # VSAN network configuration
            [ordered]@{
                networkType            = "VSAN"
                subnet                 = $InputData.NetworkSpecs.vSan.subnet
                gateway                = $InputData.NetworkSpecs.vSan.gateway
                vlanId                 = $InputData.NetworkSpecs.vSan.vLanId
                mtu                    = $InputData.NetworkSpecs.vSan.Mtu
                portGroupKey           = $InputData.NetworkSpecs.vSan.portGroupKey
                includeIpAddressRanges = @(
                    [ordered]@{
                        endIpAddress   = $InputData.NetworkSpecs.vSan.Range.Start
                        startIpAddress = $InputData.NetworkSpecs.vSan.Range.End
                    }
                )
            },
            # VM management network configuration
            [ordered]@{
                networkType  = "VM_MANAGEMENT"
                subnet       = $InputData.NetworkSpecs.VmManamegent.subnet
                gateway      = $InputData.NetworkSpecs.VmManamegent.gateway
                vlanId       = $InputData.NetworkSpecs.VmManamegent.vlanId
                mtu          = $InputData.NetworkSpecs.VmManamegent.mtu
                portGroupKey = $InputData.NetworkSpecs.VmManamegent.portGroupKey 
            }
        )

        # NSX-T specifications
        nsxtSpec                    = [ordered]@{
            nsxtManagerSize         = $InputData.Nsxt.ManagerSize
            nsxtManagers            = $InputData.Nsxt.Managers
            rootNsxtManagerPassword = $InputData.Nsxt.Password.Root
            nsxtAdminPassword       = $InputData.Nsxt.Password.Admin
            nsxtAuditPassword       = $InputData.Nsxt.Password.Audit
            vip                     = $InputData.Nsxt.vip
            vipFqdn                 = $InputData.Nsxt.vipFqdn
            nsxtLicense             = $InputData.Nsxt.License
            transportVlanId         = $InputData.Nsxt.TransportVlanId
            ipAddressPoolSpec       = [ordered]@{ 
                name        = $InputData.Nsxt.ipAddressPoolSpec.name
                description = $InputData.Nsxt.ipAddressPoolSpec.description
                subnets     = @(
                    [ordered]@{
                        ipAddressPoolRanges = @(
                            [ordered]@{
                                start = $InputData.Nsxt.ipAddressPoolSpec.subnets.ipAddressPoolRanges.start
                                end   = $InputData.Nsxt.ipAddressPoolSpec.subnets.ipAddressPoolRanges.end
                            }
                        )
                        cidr                = $InputData.Nsxt.ipAddressPoolSpec.subnets.cidr
                        gateway             = $InputData.Nsxt.ipAddressPoolSpec.subnets.gateway
                    }
                )
            }
        }

        # vSAN specifications
        vsanSpec                    = [ordered]@{
            licenseFile   = $InputData.vSan.LicenseFile
            vsanDedup     = (($InputData.vSan.ESA) ? $false : ($InputData.vSan.Dedup))
            esaConfig     = [ordered]@{ enabled = $InputData.vSan.ESA }
            hclFile       = $InputData.vSan.HclFile 
            datastoreName = $InputData.vSan.DatastoreName
        }

        # DVS specifications with network type and traffic type settings
        dvsSpecs                    = @(
            [ordered]@{
                dvsName          = $InputData.Nsxt.DvsName 
                vmnics           = $InputData.Nsxt.Vmnics 
                mtu              = $InputData.Nsxt.Mtu 
                networks         = @("MANAGEMENT", "VMOTION", "VSAN", "VM_MANAGEMENT")
                niocSpecs        = @(
                    [ordered]@{ trafficType = "VSAN"; value = "HIGH" },
                    [ordered]@{ trafficType = "VMOTION"; value = "LOW" },
                    [ordered]@{ trafficType = "VDP"; value = "LOW" },
                    [ordered]@{ trafficType = "VIRTUALMACHINE"; value = "HIGH" },
                    [ordered]@{ trafficType = "MANAGEMENT"; value = "NORMAL" },
                    [ordered]@{ trafficType = "NFS"; value = "LOW" },
                    [ordered]@{ trafficType = "HBR"; value = "LOW" },
                    [ordered]@{ trafficType = "FAULTTOLERANCE"; value = "LOW" },
                    [ordered]@{ trafficType = "ISCSI"; value = "LOW" }
                )
                nsxtSwitchConfig = [ordered]@{
                    transportZones = get-TransportZone -Type $InputData.Nsxt.TransportType -SiteCode $InputData.SddcId
                }
            }
        )

        # Cluster specifications
        clusterSpec                 = [ordered]@{
            clusterName         = $InputData.Cluster.Name
            clusterEvcMode      = $InputData.Cluster.EvcMode
            clusterImageEnabled = $InputData.Cluster.ImageEnabled
            vmFolders           = [ordered]@{
                MANAGEMENT = "$($InputData.SddcId)-fd-mgmt"
                NETWORKING = "$($InputData.SddcId)-fd-nsx"
                EDGENODES  = "$($InputData.SddcId)-fd-edge"
            } 
        }

        # PSC specifications
        pscSpecs                    = @(
            [ordered]@{
                adminUserSsoPassword = $InputData.VCenter.Password.Admin
                pscSsoSpec           = [ordered]@{
                    ssoDomain = $InputData.VCenter.SsoDomain
                }
            }
        )

        # vCenter specifications
        vcenterSpec                 = [ordered]@{
            vcenterIp           = $InputData.VCenter.Ip 
            vcenterHostname     = $InputData.VCenter.Hostname 
            licenseFile         = $InputData.VCenter.License     
            vmSize              = $InputData.VCenter.Size.Vm  
            storageSize         = $InputData.VCenter.Size.Storage  
            rootVcenterPassword = $InputData.VCenter.Password.Root
        }

        # Host specifications (external function call)
        hostSpecs                   = Get-HostSpec -InputData $InputData
    }
}




<#
.SYNOPSIS
	Generates a list of host specifications based on input data.

.DESCRIPTION
	This function creates an ordered array of host specifications derived from input data. 
	Each host specification includes properties like IP address, credentials, vSwitch settings, 
	and optionally, SSH and SSL thumbprints for validation.

.PARAMETER InputData
	An ordered hashtable containing necessary data for generating host specifications. 
	This includes network settings, credentials, and thumbprint details for ESXi hosts.

.RETURNS
	Returns an array of ordered hashtables, where each hashtable represents a host specification.

.EXAMPLE
	# Generate host specifications for a virtual deployment
	$hostSpecs = Get-HostSpec -InputData $inputData

.NOTES
	This function is used to generate host configuration details for each ESXi host, 
	applicable to virtualized infrastructure deployment scenarios.
#>

function Get-HostSpec {
    param (
        [System.Management.Automation.OrderedHashtable]
        $InputData
    ) 

    # Initialize the array to hold each host's specification
    $hostSpecs = @()
    $i = 1  # Counter for generating unique server IDs

    # Iterate over each host key in the deployment input data
    foreach ($key in $InputData.VirtualDeployment.Esx.Hosts.Keys) {
        # Construct a host specification as an ordered hashtable
        $h = [ordered]@{
            association      = $InputData.Management.Datacenter
            ipAddressPrivate = [ordered]@{
                ipAddress = $InputData.VirtualDeployment.Esx.Hosts[$key].Ip
                cidr      = $InputData.NetworkSpecs.ManagementNetwork.subnet
                gateway   = $InputData.NetworkSpecs.ManagementNetwork.gateway
            }
            hostname         = $key
            credentials      = [ordered]@{
                username = "root"
                password = $InputData.VirtualDeployment.Esx.Password
            } 
            vSwitch          = "vSwitch0"
            serverId         = "host-$($i)"
        }

        # Add thumbprints for SSH and SSL if validation is not skipped
        if (!$InputData.SkipEsxThumbprintValidation) {
            $h['sshThumbprint'] = $InputData.VirtualDeployment.Esx.Hosts[$key].SshThumbprint
            $h['sslThumbprint'] = $InputData.VirtualDeployment.Esx.Hosts[$key].SslThumbprint
        }

        # Append the host specification to the list
        $hostSpecs += $h
        $i++  # Increment counter for the next host
    }

    # Return the list of host specifications
    return $hostSpecs
}



<#
.SYNOPSIS
	Imports VCF deployment data from an Excel file and organizes it into an ordered hashtable.

.DESCRIPTION
	This function reads VCF deployment parameters from an Excel file, extracting data from various worksheets, 
	and organizes it into an ordered hashtable suitable for further processing or configuration.
	The function uses specific rows and columns to retrieve data related to ESXi hosts, network specifications, 
	credentials, vSAN configurations, among others.

.PARAMETER Path
	The path to the Excel file containing VCF deployment data. The file must contain specific worksheets such as 'Deploy Parameters', 
	'credentials', 'Hosts and Networks', and 'Virtual Deployment'.

.RETURNS
	Returns an ordered hashtable structured with keys relevant to VCF deployment configurations.

.EXAMPLE
	# Import VCF deployment data from an Excel file
	$vcfData = Import-ExcelVCFData -Path "C:\path\to\vcf_data.xlsx"

.NOTES
	This function relies on the `Import-Excel` cmdlet to read data from the Excel file. Ensure that the ImportExcel PowerShell module is installed.
#>

function Import-ExcelVCFData {
    param(
        [string]
        $Path
    )

    # Check if the specified path exists
    if (Test-Path $Path) {
        # Import data from various sheets and specific row/column ranges
        $vcfInfra = Import-Excel -Path $Path -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 5 -EndColumn 7 -DataOnly
        $licenseImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 5 -EndColumn 7 -DataOnly -StartRow 11 -EndRow 15
        $vcfVarious = Import-Excel -Path $Path -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 9 -EndColumn 11 -DataOnly
        $credentialsImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'credentials' -DataOnly
        $mgmtNetworkImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 2 -EndColumn 7 -DataOnly -Raw -StartRow 7 -EndRow 10
        $esxImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 12 -DataOnly -Raw -StartRow 6 -EndRow 7
        $rangeImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 12 -DataOnly -Raw -StartRow 8 -EndRow 10
        $dsImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 2 -EndColumn 7 -DataOnly -Raw -StartRow 12 -EndRow 21
        $overlayImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 13 -DataOnly -Raw -StartRow 22 -EndRow 28
        $thumbprintImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 13 -DataOnly -Raw -StartRow 12 -EndRow 18
        $Virtual = Import-Excel -Path $Path -NoHeader -WorksheetName 'Virtual Deployment' -StartColumn 5 -EndColumn 12 -DataOnly -Raw -StartRow 3 -EndRow 36
    }
    else {
        Write-Host -ForegroundColor Red "`n$Path doesn't exist ...`n"
        return $null
    } 

    # Process and structure the imported data
    $deployWithoutLicenseKeys = $licenseImport[0].P2 -eq 'No'

    # If Virtual[23] is specified, build $wldHosts object
    if ($Virtual[23].P1 -ne 'n/a') {
        $wldHosts = [ordered]@{
            Ova           = (($EsxOVA)? $EsxOVA : $Virtual[1].P5) 
            vCPU          = $Virtual[13].P3
            vMemory       = $Virtual[14].P3
            BootDisk      = $Virtual[15].P3
            CachingvDisk  = $Virtual[16].P3
            CapacityvDisk = $Virtual[17].P3
            ESADisk1      = $Virtual[16].P3
            ESADisk2      = $Virtual[17].P3 
            VMNetwork1    = $Virtual[18].P3 
            VMNetwork2    = $Virtual[19].P3 
            Syslog        = $Virtual[20].P3
            Password      = $credentialsImport[5].P2
            Hosts         = [ordered]@{}
        }

        # Add individual host configurations
        for ($i = 24; $i -lt 32; $i++) {
            if ($Virtual[$i].P1 -ne 'n/a') {
                $wldHosts.Hosts[$($Virtual[$i].P1)] = [ordered]@{
                    Ip            = $Virtual[$i].P2
                    SshThumbprint = ($null -eq $Virtual[$i].P4) ? "SHA256:DUMMY_VALUE" : $Virtual[$i].P4
                    SslThumbprint = ($null -eq $thumbprintImport[$i].P6) ? "SHA25_DUMMY_VALUE" : $thumbprintImport[$i].P6
                }
            }
        }
    }
    else {
        $wldHosts = $null
    }

    # Construct the final ordered hashtable with all configuration settings
    return [ordered]@{
        VirtualDeployment           = [ordered]@{
            # General VM deployment settings
            VMDatacenter = $Virtual[1].P2
            VMCluster    = $Virtual[2].P2
            VMDatastore  = $Virtual[3].P2
            VMFolder     = $Virtual[4].P2
            Esx          = [ordered]@{
                # ESX configurations
                Ova           = (($EsxOVA)? $EsxOVA : $Virtual[1].P5) 
                vCPU          = $Virtual[13].P2
                vMemory       = $Virtual[14].P2
                BootDisk      = $Virtual[15].P2
                CachingvDisk  = $Virtual[16].P2
                CapacityvDisk = $Virtual[17].P2
                ESADisk1      = $Virtual[16].P2
                ESADisk2      = $Virtual[17].P2 
                VMNetwork1    = $Virtual[18].P2 
                VMNetwork2    = $Virtual[19].P2 
                Syslog        = $Virtual[20].P2
                Password      = $credentialsImport[5].P2
                Hosts         = [ordered]@{
                    # Populate host data with IPs and thumbprints
                    $esxImport[0].P1 = [ordered]@{Ip = $esxImport[1].P1; SshThumbprint = ($null -eq $thumbprintImport[3].P2) ? "SHA256:DUMMY_VALUE" : $thumbprintImport[3].P2; SslThumbprint = ($null -eq $thumbprintImport[3].P4) ? "SHA25_DUMMY_VALUE" : $thumbprintImport[3].P4 }
                    $esxImport[0].P2 = [ordered]@{Ip = $esxImport[1].P2; SshThumbprint = ($null -eq $thumbprintImport[4].P2) ? "SHA256:DUMMY_VALUE" : $thumbprintImport[4].P2; SslThumbprint = ($null -eq $thumbprintImport[4].P4) ? "SHA25_DUMMY_VALUE" : $thumbprintImport[4].P4 }
                    $esxImport[0].P3 = [ordered]@{Ip = $esxImport[1].P3; SshThumbprint = ($null -eq $thumbprintImport[5].P2) ? "SHA256:DUMMY_VALUE" : $thumbprintImport[5].P2; SslThumbprint = ($null -eq $thumbprintImport[5].P4) ? "SHA25_DUMMY_VALUE" : $thumbprintImport[5].P4 }
                    $esxImport[0].P4 = [ordered]@{Ip = $esxImport[1].P4; SshThumbprint = ($null -eq $thumbprintImport[6].P2) ? "SHA256:DUMMY_VALUE" : $thumbprintImport[6].P2; SslThumbprint = ($null -eq $thumbprintImport[6].P4) ? "SHA25_DUMMY_VALUE" : $thumbprintImport[6].P4 }
                }
            
            }
            WldEsx       = $wldHosts
            Cloudbuilder = [ordered]@{
                # Cloud Builder specific configuration
                Ova           = (($CloudBuilderOVA)? $CloudBuilderOVA : $Virtual[2].P5)
                VMName        = $Virtual[6].P2
                Hostname      = $Virtual[7].P2
                Ip            = $Virtual[8].P2 
                AdminPassword = $Virtual[10].P2
                RootPassword  = $Virtual[11].P2
                PortGroup     = $Virtual[9].P2
            }
        }

        # Additional main configurations
        DeployWithoutLicenseKeys    = $deployWithoutLicenseKeys
        SddcId                      = $vcfInfra[38].P2
        EsxLicense                  = ($deployWithoutLicenseKeys) ? "" : $licenseImport[1].P2
        workflowType                = "VCF"
        CeipEnabled                 = ($vcfVarious[5].P3 -ieq 'yes')
        FipsEnabled                 = ($vcfVarious[6].P3 -ieq 'yes')
        SkipEsxThumbprintValidation = $thumbprintImport[0].P3 -eq 'No'
    
        # Management configuration
        Management                  = [ordered]@{
            Datacenter = $vcfInfra[18].P2 # Datacenter Name
            PoolName   = $vcfInfra[37].P2 # Network Pool Name
        }

        # SDDC Manager Configuration
        SddcManager                 = [ordered]@{ 
            Hostname = [ordered]@{ 
                VcfPassword   = $credentialsImport[15].P2 # SDDC Manager Super User
                RootPassword  = $credentialsImport[14].P2 # SDDC Manager Appliance Root Account
                LocalPassword = $credentialsImport[16].P2 # SDDC Manager Local Account
                Ip            = $vcfInfra[36].P2
                Hostname      = $vcfInfra[35].P2
            }
        }

        # vCenter configuration
        VCenter                     = [ordered]@{
            Ip        = $vcfInfra[13].P3
            Hostname  = $vcfInfra[13].P2   
            License   = ($deployWithoutLicenseKeys) ? "" : $licenseImport[3].P2      
            Size      = [ordered]@{
                Vm      = $vcfInfra[14].P2
                Storage = ($vcfInfra[15].P2 -eq 'large') ? "lstorage" : (($vcfInfra[15].P2 -eq 'xlarge') ? "xlstorage" : $null)
            } 
            Password  = [ordered]@{
                Admin = $credentialsImport[7].P2 
                Root  = $credentialsImport[8].P2
            }
            SsoDomain = "vsphere.local"
        }

        # Cluster configuration
        Cluster                     = [ordered]@{
            Name         = $vcfInfra[19].P2        
            EvcMode      = $vcfInfra[21].P2
            ImageEnabled = $vcfInfra[20].P2 -eq 'yes'
        }

        # Network specifications
        NetworkSpecs                = [ordered]@{
            DnsSpec           = [ordered]@{
                Subdomain   = $vcfVarious[3].P2
                Domain      = $vcfVarious[3].P2
                NameServers = $(
                    $ns = @()
                    for ($i = 3; $i -le 4; $i++) {
                        if ($vcfInfra[$i].P2 -ne 'n/a') {
                            $ns += $vcfInfra[$i].P2
                        }
                    }
                    $ns -join ','  # Join the array elements with a comma and return as the value
                )
            }
    
            NtpServers        = @(
                $nt = @()
                for ($i = 5; $i -le 6; $i++) {
                    if ($vcfInfra[$i].P2 -ne 'n/a') {
                        $nt += $vcfInfra[$i].P2
                    }  
                }
                $nt
            )

            # Management network settings
            ManagementNetwork = [ordered]@{
                subnet       = $mgmtNetworkImport[1].P4
                vLanId       = [int]"$($mgmtNetworkImport[1].P2)"
                Mtu          = [int]"$($mgmtNetworkImport[1].P6)"
                portGroupKey = $mgmtNetworkImport[1].P3
                gateway      = $mgmtNetworkImport[1].P5
            }

            # vMotion network settings
            vMotionNetwork    = [ordered]@{
                subnet       = $mgmtNetworkImport[2].P4
                vLanId       = [int]"$($mgmtNetworkImport[2].P2)"
                Mtu          = [int]"$($mgmtNetworkImport[2].P6)"
                portGroupKey = $mgmtNetworkImport[2].P3
                gateway      = $mgmtNetworkImport[2].P5
                Range        = [ordered]@{ 
                    Start = $rangeImport[0].p2
                    End   = $rangeImport[0].p4
                }
            }

            # vSAN network settings
            vSan              = [ordered]@{
                subnet       = $mgmtNetworkImport[3].P4
                vLanId       = [int]"$($mgmtNetworkImport[3].P2)"
                Mtu          = [int]"$($mgmtNetworkImport[3].P6)"
                portGroupKey = $mgmtNetworkImport[3].P3
                gateway      = $mgmtNetworkImport[3].P5
                Range        = [ordered]@{
                    Start = $rangeImport[1].p4
                    End   = $rangeImport[1].p2
                }
            }

            # VM management network settings
            VmManamegent      = [ordered]@{
                subnet       = $mgmtNetworkImport[0].P4
                gateway      = $mgmtNetworkImport[0].P5
                vlanId       = [int]"$($mgmtNetworkImport[0].P2)"
                mtu          = [int]"$($mgmtNetworkImport[0].P6)"
                portGroupKey = $mgmtNetworkImport[0].P3
            }
        }

        # NSX-T settings
        Nsxt                        = [ordered]@{
            Managers          = @(
                for ($i = 30; $i -le 32; $i++) {
                    if ($vcfInfra[$i].P2 -eq 'n/a') { continue }
                    [ordered]@{
                        hostname = $vcfInfra[$i].P2
                        ip       = $vcfInfra[$i].P3
                    }
                }
            )

            Password          = [ordered]@{
                Root  = $credentialsImport[10].P2
                Admin = $credentialsImport[11].P2
                Audit = $credentialsImport[12].P2
            }
            ManagerSize       = $vcfInfra[33].P2
            vip               = $vcfInfra[29].P3
            vipFqdn           = $vcfInfra[29].P2 
            License           = ($deployWithoutLicenseKeys) ? "" : $licenseImport[4].P2
            DvsName           = $dsImport[1].P2
            Vmnics            = @($dsImport[2].p2 -split ',')
            Mtu               = [int]"$($dsImport[3].P2)"
            TransportVlanId   = [int]"$($overlayImport[0].P2)"
            TransportType     = $dsImport[4].p2 
            ipAddressPoolSpec = [ordered]@{
                name        = $overlayImport[4].P2
                description = $overlayImport[3].P2
                subnets     = @(
                    [ordered]@{
                        ipAddressPoolRanges = @(
                            [ordered]@{
                                start = $overlayImport[6].P2
                                end   = $overlayImport[6].P4
                            }
                        )
                        cidr                = $overlayImport[5].P2
                        gateway             = $overlayImport[5].P4
                    }
                )
            }
        }

        # vSAN settings
        vSan                        = [ordered]@{
            ESA           = ($vcfVarious[16].P2 -ieq 'yes')
            LicenseFile   = ($deployWithoutLicenseKeys) ? "" : $licenseImport[2].P2  
            HclFile       = ($vcfVarious[17].P2) ? $vcfVarious[17].P2 : ""
            DatastoreName = $vcfVarious[14].P2
            Dedup         = ($vcfVarious[15].P2 -ieq 'yes')
        }
    }
}
 
<#
.SYNOPSIS
	Submits a VCF bringup request and manages HCL file transfers to a VMware Cloud Builder.

.DESCRIPTION
	This function handles the bringup process for VMware Cloud Foundation (VCF) by submitting a JSON payload 
	to a specified Cloud Builder's API endpoint. If an HCL file is provided, the function transfers it 
	to the Cloud Builder via SCP or VM guest file copy, depending on the deployment environment.

.PARAMETER HclFile
	Optional. Specifies the path to the HCL file. If provided, the file will be transferred to the Cloud Builder 
	either via SCP or using Copy-VMGuestFile.

.PARAMETER CloudbuilderFqdn
	The FQDN of the VMware Cloud Builder server where the bringup process will be initiated.

.PARAMETER AdminPassword
	The administrator password as a SecureString. Used to create a PSCredential for authentication with Cloud Builder.

.PARAMETER Json
	The JSON payload to be submitted in the bringup request, which defines the configuration for VCF bringup.

.EXAMPLE
	# Invoke bringup with HCL file and JSON payload
	Invoke-BringUp -HclFile "C:\path\to\hcl.json" -CloudbuilderFqdn "cloudbuilder.example.com" -AdminPassword (ConvertTo-SecureString "password" -AsPlainText -Force) -Json $jsonPayload

.NOTES
	This function uses both SCP (for SSH-based environments) and VM guest file copy based on availability.
	Ensure the ImportExcel module and any necessary modules (e.g., Posh-SSH) are installed for proper functionality.
#>
function Invoke-BringUp {
    param(
        [string]
        $HclFile,

        [string]
        $CloudbuilderFqdn,

        [securestring]
        $AdminPassword,

        [string]
        $Json
    )

    # Create a PSCredential for use with SCP or API requests
    $cred = [Management.Automation.PSCredential]::new('admin', $AdminPassword)

    # Check if an HCL file is provided for transfer
    if ($HclFile) {
        # Transfer HCL file via SCP if SSH is available
        if ($UseSSH.isPresent) {
            $hclFiledest = Split-Path -Path $HclFile
            Write-Logger "SCP HCL $($HCLJsonFile) file to $($HclFile) ..."
            Set-SCPItem -ComputerName $CloudbuilderFqdn -Credential $cred -Path $HCLJsonFile -Destination $hclFiledest -AcceptKey
        }

        # If no VM object is defined, find the Cloud Builder VM by its IP address
        if (!$CloudbuilderVM) {
            $CloudbuilderVM = Get-VM | Where-Object {
                   (Get-VMGuest -VM $_).IPAddress -contains $CloudbuilderFqdn 
            }
        }

        # Transfer HCL file using Copy-VMGuestFile if VM object is found
        Write-Logger "Copy-VMGuestFile HCL $($HCLJsonFile) file to $($HclFile) ..."
        Copy-VMGuestFile -Source $HCLJsonFile -Destination $HclFile -GuestCredential $cred -VM $CloudbuilderVM -LocalToGuest -Force
    }

    # Log message indicating that the bringup request is being submitted
    Write-Logger "Submitting VCF Bringup request ..."

    # Define parameters for the bringup API request
    $bringupAPIParms = @{
        Uri         = "https://$CloudbuilderFqdn/v1/sddcs"
        Method      = 'POST'
        Body        = $Json
        ContentType = 'application/json'
        Credential  = $cred
    }

    # Submit the bringup request to the Cloud Builder's API and capture the response
    $null = Invoke-RestMethod @bringupAPIParms -SkipCertificateCheck

    # Log message for user to check progress in the Cloud Builder UI
    Write-Logger "Open browser to the VMware Cloud Builder UI (https://${CloudbuilderFqdn}) to monitor deployment progress ..."
}



<#
.SYNOPSIS
	Deploys and configures nested ESXi VMs in a specified vApp location.

.DESCRIPTION
	This function deploys ESXi VMs from an OVA template within a specified vApp in VMware vSphere.
	It configures network settings, adjusts VM resources, and prepares the storage layout, including handling vSAN ESA configurations if specified.

.PARAMETER ImportLocation
	The target vApp where the ESXi VMs will be deployed.

.PARAMETER NetworkSpecs
	A hashtable containing network configuration details, including DNS, gateway, and VLAN information.

.PARAMETER Esx
	A hashtable that provides ESXi VM details, such as hostname, IP address, password, and VM networks.

.PARAMETER VsanEsa
	A switch parameter that indicates if the deployment is for vSAN ESA (Express Storage Architecture).
	If specified, the function configures the VMs with NVMe controllers for vSAN ESA.

.EXAMPLE
	# Add a virtual ESXi host in a vApp
	Add-VirtualEsx -ImportLocation $vApp -NetworkSpecs $networkSpecs -Esx $esxDetails -VsanEsa

.NOTES
	This function supports configuring both traditional vSAN and vSAN ESA disk layouts.
	Ensure proper permissions are in place to deploy and configure VMs within the specified vApp location.
#>

function Add-VirtualEsx { 
    param( 
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VAppImpl]
        $ImportLocation,

        [hashtable]
        $NetworkSpecs,

        [hashtable]
        $Esx,

        [switch]
        $VsanEsa
    )

    # Initialize answer for re-import prompts
    $answer = $null

    # Iterate over each host in the ESXi configuration
    foreach ($VMName in $Esx.Hosts.Keys) {
     
        # Retrieve the IP address of the current VM
        $VMIPAddress = $Esx.Hosts[$VMName].Ip

        # Attempt to find an existing VM with the same name in the target vApp
        $vm = Get-VM -Name $VMName -Location $ImportLocation -ErrorAction SilentlyContinue

        # Test if the VM should be redeployed and get the user’s answer if needed
        $redeploy, $answer = Test-VMForReImport -Vm $vm -Answer $answer
        if (! $redeploy) {
            continue
        }

        # Retrieve the datacenter from the parent folder of the import location
        $datacenter = $importLocation.ParentFolder | Get-Datacenter

        # Get OVF configuration for the ESXi OVA and apply network settings
        $ovfconfig = Get-OvfConfiguration $Esx.Ova
        $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
        $ovfconfig.NetworkMapping.$networkMapLabel.value = $Esx.VMNetwork1
        $ovfconfig.common.guestinfo.hostname.value = "$VMName.$($NetworkSpecs.DnsSpec.Domain)"
        $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
        $ovfconfig.common.guestinfo.netmask.value = (ConvertTo-Netmask -NetworkCIDR $NetworkSpecs.ManagementNetwork.subnet)
        $ovfconfig.common.guestinfo.gateway.value = $NetworkSpecs.ManagementNetwork.gateway
        $ovfconfig.common.guestinfo.dns.value = $NetworkSpecs.DnsSpec.NameServers
        $ovfconfig.common.guestinfo.domain.value = $NetworkSpecs.DnsSpec.Domain
        $ovfconfig.common.guestinfo.ntp.value = $NetworkSpecs.NtpServers -join ","
        $ovfconfig.common.guestinfo.syslog.value = $Esx.Syslog
        $ovfconfig.common.guestinfo.password.value = $Esx.Password
        $ovfconfig.common.guestinfo.vlan.value = $NetworkSpecs.ManagementNetwork.vLanId
        $ovfconfig.common.guestinfo.ssh.value = $true

        # Deploy the ESXi VM using the configured OVF template
        Write-Logger "Deploying Nested ESXi VM $VMName ..."
        $vm = Import-VApp -Source $Esx.Ova -OvfConfiguration $ovfconfig -Name $VMName -Location $ImportLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin 
    
        # Check if VM deployment failed
        if (-not $vm) {
            Write-Logger -Color red -Message "Deploy of $( $ovfconfig.common.guestinfo.hostname.value) failed."
            @{date = (Get-Date); failure = $true; vapp = $ImportLocation; component = 'ESX' } | ConvertTo-Json | Out-File state.json
            exit
        }

        # Add additional network adapters to the VM if needed
        Write-Logger "Adding vmnic2/vmnic3 to Nested ESXi VMs ..."
        $vmPortGroup = Get-VirtualNetwork -Name $Esx.VMNetwork2 -Location $datacenter
        if ($vmPortGroup.NetworkType -eq "Distributed") {
            $vmPortGroup = Get-VDPortgroup -Name $Esx.VMNetwork2
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $vmPortGroup -StartConnected -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $vmPortGroup -StartConnected -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
        else {
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $vmPortGroup -StartConnected -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $vmPortGroup -StartConnected -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }

        # Apply advanced network adapter settings for dvfilter-maclearn
        $vm | New-AdvancedSetting -Name "ethernet2.filter4.name" -Value "dvfilter-maclearn" -Confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet2.filter4.onFailure" -Value "failOpen" -Confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet3.filter4.name" -Value "dvfilter-maclearn" -Confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet3.filter4.onFailure" -Value "failOpen" -Confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

        # Set VM CPU and memory configurations
        Write-Logger "Updating vCPU Count to $($Esx.vCPU) & vMEM to $($Esx.vMemory) GB ..."
        Set-VM -VM $vm -NumCpu $Esx.vCPU -CoresPerSocket $Esx.vCPU -MemoryGB $Esx.vMemory -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

        # Configure boot and vSAN disks
        Write-Logger "Updating vSAN Boot Disk size to $($Esx.BootDisk) GB ..."
        Get-HardDisk -VM $vm -Name "Hard disk 1" | Set-HardDisk -CapacityGB $Esx.BootDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        
        # Configure NVMe controller for vSAN ESA if VsanEsa switch is present
        if ($VsanEsa) {
            Write-Logger "Updating vSAN Disk Capacity VMDK size to $($esx.ESADisk1) GB  and $($esx.ESADisk2) GB .."
            Get-HardDisk -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $esx.ESADisk1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            Get-HardDisk -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $esx.ESADisk2 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            Write-Logger "Updating storage controller to NVMe for vSAN ESA ..."
            $devices = $vm.ExtensionData.Config.Hardware.Device
            $newControllerKey = -102
        
            # Initialize device changes and VM configuration spec for adding NVMe controller
            $deviceChanges = @()
            $spec = [VMware.Vim.VirtualMachineConfigSpec]::new()
        
            # Find the existing PVSCSI controller and its attached disks
            $scsiController = $devices | Where-Object { $_.getType().Name -eq "ParaVirtualSCSIController" }
            $scsiControllerDisks = $scsiController.Device
        
            # Create and configure a new NVMe controller with a unique key
            $nvmeControllerAddSpec = [VMware.Vim.VirtualDeviceConfigSpec]::new()
            $nvmeControllerAddSpec.Device = [VMware.Vim.VirtualNVMEController]::new()
            $nvmeControllerAddSpec.Device.Key = $newControllerKey
            $nvmeControllerAddSpec.Device.BusNumber = 0
            $nvmeControllerAddSpec.Operation = 'add'
            $deviceChanges += $nvmeControllerAddSpec
        
            # Reassign each disk on the PVSCSI controller to the new NVMe controller
            foreach ($scsiControllerDisk in $scsiControllerDisks) {
                $device = $devices | Where-Object { $_.Key -eq $scsiControllerDisk }
        
                # Create a device spec to change the controller for each disk
                $changeControllerSpec = [VMware.Vim.VirtualDeviceConfigSpec]::new()
                $changeControllerSpec.Operation = 'edit'
                $changeControllerSpec.Device = $device
                $changeControllerSpec.Device.Key = $device.Key
                $changeControllerSpec.Device.UnitNumber = $device.UnitNumber
                $changeControllerSpec.Device.ControllerKey = $newControllerKey
                $deviceChanges += $changeControllerSpec
            }
        
            # Apply the device changes to add the NVMe controller and reassign disks
            $spec.DeviceChange = $deviceChanges
            $task = $vm.ExtensionData.ReconfigVM_Task($spec)
            $task1 = Get-Task -Id ("Task-$($task.Value)")
            $task1 | Wait-Task | Out-Null
        
            # Remove the original PVSCSI controller after disk reassignment
            Write-Logger "Removing PVSCSI Controller after NVMe configuration ..."
            $spec = [VMware.Vim.VirtualMachineConfigSpec]::new()
            $scsiControllerRemoveSpec = [VMware.Vim.VirtualDeviceConfigSpec]::new()
            $scsiControllerRemoveSpec.Operation = 'remove'
            $scsiControllerRemoveSpec.Device = $scsiController
            $spec.DeviceChange = $scsiControllerRemoveSpec
        
            # Execute the task to remove the PVSCSI controller
            $task = $vm.ExtensionData.ReconfigVM_Task($spec)
            $task1 = Get-Task -Id ("Task-$($task.Value)")
            $task1 | Wait-Task | Out-Null
        
        }
        else {
            Write-Logger "Updating vSAN Cache VMDK size to $($Esx.CachingvDisk) GB & Capacity VMDK size to $($Esx.CapacityvDisk) GB ..."
            Get-HardDisk -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $Esx.CachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            Get-HardDisk -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $Esx.CapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }

        # Power on the VM after configuration
        Write-Logger "Powering On $VMName ..."
        $vm | Start-VM -RunAsync | Out-Null
    }
}


<#
.SYNOPSIS
	Generates a custom vSAN ESA HCL JSON file for a standalone ESXi host.

.DESCRIPTION
	This function connects to a specified ESXi host, collects information about storage devices and controllers, 
	and generates a JSON file compatible with vSAN ESA (Express Storage Architecture). The output JSON includes details 
	on supported devices, firmware, queue depth, and vSAN support modes. The function retrieves the latest 
	vSAN HCL timestamp from VMware’s API for inclusion in the JSON.

.PARAMETER Server
	The FQDN or IP address of the ESXi host.

.PARAMETER Credential
	A PSCredential object used to authenticate to the ESXi host.

.EXAMPLE
	# Generate a custom vSAN ESA HCL JSON for an ESXi host
	$esxiCredential = Get-Credential
	Get-vSANHcl -Server "esxi.example.com" -Credential $esxiCredential

.NOTES
	Original Author: William Lam
	Ensure you have an active internet connection for retrieving the latest vSAN HCL timestamp.
	This function requires PowerCLI and VMware modules.
#>

function Get-vSANHcl {
    param (
        [string]$Server,
        [pscredential]$Credential
    )

    # Connect to the ESXi host using provided credentials
    Connect-VIServer -Server $Server -Credential $Credential
    $vmhost = Get-VMHost  
    $supportedESXiReleases = @("ESXi 8.0 U2", "ESXi 8.0 U3")

    Write-Host -ForegroundColor Green "`nCollecting SSD information from ESXi host ${vmhost} ... "

    # Retrieve VIBs and storage device information from ESXi
    $imageManager = Get-View ($Vmhost.ExtensionData.ConfigManager.ImageConfigManager)
    $vibs = $imageManager.fetchSoftwarePackages()
    $storageDevices = $vmhost.ExtensionData.Config.StorageDevice.scsiTopology.Adapter
    $storageAdapters = $vmhost.ExtensionData.Config.StorageDevice.hostBusAdapter
    $devices = $vmhost.ExtensionData.Config.StorageDevice.scsiLun
    $pciDevices = $vmhost.ExtensionData.Hardware.PciDevice

    # Initialize results arrays and a hash table to track processed devices
    $ctrResults = @()
    $ssdResults = @()
    $seen = @{}

    # Loop through storage devices to gather information on each SSD and controller
    foreach ($storageDevice in $storageDevices) {
        $targets = $storageDevice.target
        if ($null -ne $targets ) {
            foreach ($target in $targets) {
                foreach ($ScsiLun in $target.Lun.ScsiLun) {
                    $device = $devices | Where-Object { $_.Key -eq $ScsiLun }
                    $storageAdapter = $storageAdapters | Where-Object { $_.Key -eq $storageDevice.Adapter }
                    $pciDevice = $pciDevices | Where-Object { $_.Id -eq $storageAdapter.Pci }

                    # Convert PCI device IDs from decimal to hexadecimal
                    $vid = ('{0:x}' -f $pciDevice.VendorId).ToLower()
                    $did = ('{0:x}' -f $pciDevice.DeviceId).ToLower()
                    $svid = ('{0:x}' -f $pciDevice.SubVendorId).ToLower()
                    $ssid = ('{0:x}' -f $pciDevice.SubDeviceId).ToLower()
                    $combined = "${vid}:${did}:${svid}:${ssid}"

                    # Identify and store driver and controller information based on adapter type
                    if ($storageAdapter.Driver -in @("nvme_pcie", "pvscsi")) {
                        switch ($storageAdapter.Driver) {
                            "nvme_pcie" {
                                $controllerType = $storageAdapter.Driver
                                $controllerDriver = ($vibs | Where-Object { $_.Name -eq "nvme-pcie" }).Version
                            }
                            "pvscsi" {
                                $controllerType = $storageAdapter.Driver
                                $controllerDriver = ($vibs | Where-Object { $_.Name -eq "pvscsi" }).Version
                            }
                        }

                        # Generate support information for each supported ESXi release
                        $ssdReleases = @{}
                        foreach ($supportedESXiRelease in $supportedESXiReleases) {
                            $tmpObj = [ordered] @{

                                vsanSupport     = @("All Flash:", "vSANESA-SingleTier")
                                $controllerType = [ordered] @{
                                    $controllerDriver = [ordered] @{
                                        firmwares = @(
                                            [ordered] @{
                                                firmware    = $device.Revision
                                                vsanSupport = [ordered] @{
                                                    tier = @("AF-Cache", "vSANESA-Singletier")
                                                    mode = @("vSAN", "vSAN ESA")
                                                }
                                            }
                                        )
                                        type      = "inbox"
                                    }
                                }
                            }
                            # Add the release if not already present
                            if (!$ssdReleases[$supportedESXiRelease]) {
                                $ssdReleases.Add($supportedESXiRelease, $tmpObj)
                            }
                        }

                        # Store SSD information if it's a unique entry
                        if ($device.DeviceType -eq "disk" -and !$seen[$combined]) {
                            $ssdTmp = [ordered] @{
                                id          = [int]$(Get-Random -Minimum 1000 -Maximum 50000).ToString()
                                did         = $did
                                vid         = $vid
                                ssid        = $ssid
                                svid        = $svid
                                vendor      = $device.Vendor
                                model       = ($device.Model).Trim()
                                devicetype  = $device.ApplicationProtocol
                                partnername = $device.Vendor
                                productid   = ($device.Model).Trim()
                                partnumber  = $device.SerialNumber
                                capacity    = [Int]((($device.Capacity.BlockSize * $device.Capacity.Block) / 1048576))
                                vcglink     = "https://williamlam.com/homelab"
                                releases    = $ssdReleases
                                vsanSupport = [ordered] @{
                                    mode = @("vSAN", "vSAN ESA")
                                    tier = @("vSANESA-Singletier", "AF-Cache")
                                }
                            }

                            # Generate controller details and support information for each ESXi release
                            $controllerReleases = @{}
                            foreach ($supportedESXiRelease in $supportedESXiReleases) {
                                $tmpObj = [ordered] @{
                                    $controllerType = [ordered] @{
                                        $controllerDriver = [ordered] @{
                                            type       = "inbox"
                                            queueDepth = $device.QueueDepth
                                            firmwares  = @(
                                                [ordered] @{
                                                    firmware    = $device.Revision
                                                    vsanSupport = @("Hybrid:Pass-Through", "All Flash:Pass-Through", "vSAN ESA")
                                                }
                                            )
                                        }
                                    }
                                    vsanSupport     = @("Hybrid:Pass-Through", "All Flash:Pass-Through")
                                }
                                # Add controller release information if not already present
                                if (!$controllerReleases[$supportedESXiRelease]) {
                                    $controllerReleases.Add($supportedESXiRelease, $tmpObj)
                                }
                            }

                            # Construct final controller object
                            $controllerTmp = [ordered] @{
                                id       = [int]$(Get-Random -Minimum 1000 -Maximum 50000).ToString()
                                releases = $controllerReleases
                            }

                            # Append controller and SSD information to result arrays
                            $ctrResults += $controllerTmp
                            $ssdResults += $ssdTmp
                            $seen[$combined] = "yes"
                        }
                    }
                }
            }
        }
    }

    # Retrieve the latest vSAN HCL jsonUpdatedTime from VMware's API
    $results = Invoke-WebRequest -Uri 'https://partnerweb.vmware.com/service/vsan/all.json?lastupdatedtime' -Headers @{'x-vmw-esp-clientid' = 'vsan-hcl-vcf-2024' }
    $pattern = '\{(.+?)\}'
    $matched = ([regex]::Matches($results, $pattern)).Value

    if ($null -ne $matched) {
        $vsanHclTime = $matched | ConvertFrom-Json
    }
    else {
        Write-Error "Unable to retrieve vSAN HCL jsonUpdatedTime, ensure you have internet connectivity when running this script"
        return $null
    }

    # Construct final HCL object for output
    $hclObject = [ordered] @{
        timestamp         = $vsanHclTime.timestamp
        jsonUpdatedTime   = $vsanHclTime.jsonUpdatedTime
        totalCount        = $($ssdResults.count + $ctrResults.count)
        supportedReleases = $supportedESXiReleases
        eula              = @{}
        data              = [ordered] @{
            controller = @($ctrResults)
            ssd        = @($ssdResults)
            hdd        = @()
        }
    }

    # Generate the output filename with timestamp
    $dateTimeGenerated = Get-Date -UFormat "%m_%d_%Y_%H_%M_%S"
    $outputFileName = "custom_vsan_esa_hcl_${dateTimeGenerated}.json"

    Write-Host -ForegroundColor Green "Saving Custom vSAN ESA HCL to ${outputFileName}`n"
    $hclObject | ConvertTo-Json -Depth 12 | Out-File -FilePath $outputFileName

    # Return the generated filename
    return $outputFileName 
}

# Export the specified functions from this module to make them available for use when the module is imported
Export-ModuleMember -Function Test-VMForReImport, Write-Logger, Get-TransportZone, ConvertTo-Netmask, Convert-HashtableToPsd1String, Get-JsonWorkload
Export-ModuleMember -Function Import-ExcelVCFData, Invoke-BringUp, Add-VirtualEsx, Get-VSANHcl