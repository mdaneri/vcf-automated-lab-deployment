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
    if ($null -eq $Vm) {
        return $true, $Answer
    }
    if ([string]::IsNullOrEmpty($Answer)) {
        Write-Host -ForegroundColor Magenta "`nA VM named '$($vm.Name)' already in the inventory.`nDo you want re-import '$($vm.Name)'"
        do {
            $readAnswer = Read-Host -Prompt "[Y] Yes  [A] Yes to All  [N] No  [L] No to All"
        }until ( 'y', 'a', 'n', 'l' -contains $readAnswer )

    }
    else {
        $readAnswer = $Answer
    }
    switch ($readAnswer) {
        'a' {
            if ($vm.PowerState -eq 'PoweredOn') {
                Write-Logger "Powering Off $vmname ..."
                Stop-VM $vm -Confirm:$false | Out-Null
            }
            Write-Logger "Removing $vmname ..."
            Remove-VM -VM $vm -DeletePermanently -Confirm:$false | Out-Null
            return $true, 'y'
        }
        'y' {
            if ($vm.PowerState -eq 'PoweredOn') {
                Write-Logger "Powering Off $vmname ..."
                Stop-VM $vm -Confirm:$false | Out-Null
            }
            Write-Logger "Removing $vmname ..."
            Remove-VM -VM $vm -DeletePermanently -Confirm:$false | Out-Null
            return $true, $Answer
        }
        'l' {
            return $false, 'n'
        }
        'n' {
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



function Get-TransportZone {
    param(
        [Parameter(Mandatory = $true)]
        $Type,
        [Parameter(Mandatory = $false)]
        $SiteCode = "sfo-m01"
    )

    switch ($Type) {
        'Overlay/VLAN' {
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
            return  @(
                [ordered]@{
                    name          = "$SiteCode-tz-overlay01"
                    transportType = "OVERLAY"
                }
            )
        }  
        'VLAN' {
            return   @(
                [ordered]@{
                    name          = "$SiteCode-tz-vlan01"
                    transportType = "VLAN"
                }
            )
        }
        default {
            return  @()
        }  
    }
}


function ConvertTo-Netmask {
    param (
        [string]$NetworkCIDR
    )

    # Split the network address and the CIDR value
    $network, $cidr = $NetworkCIDR -split '/'
    $cidr = [int]$cidr

    # Create the binary representation of the netmask
    $binaryMask = "1" * $cidr + "0" * (32 - $cidr)
    $netmask = [System.Net.IPAddress]::Parse(
        [string]([convert]::ToInt32($binaryMask.Substring(0, 8), 2)) + "." +
        [string]([convert]::ToInt32($binaryMask.Substring(8, 8), 2)) + "." +
        [string]([convert]::ToInt32($binaryMask.Substring(16, 8), 2)) + "." +
        [string]([convert]::ToInt32($binaryMask.Substring(24, 8), 2))
    )
    
    return $netmask.IPAddressToString
}



# Function to format hashtable content for .psd1
function Convert-HashtableToPsd1String {
    param (
        [Parameter(Mandatory)]
        [hashtable]$Hashtable,

        [int]$IndentLevel = 0  # Parameter to track the current indentation level
    )

    $indentation = ("`t" * $IndentLevel) # Create the current indentation string
    $output = "$indentation@{" + [Environment]::NewLine

    $Hashtable.GetEnumerator() | Sort-Object -Property Key | ForEach-Object {
        $key = $_.Key
        $value = $_.Value
        $currentIndentation = ("`t" * ($IndentLevel + 1)) # Create the next level indentation string

        if ($value -is [System.Collections.Hashtable] -or $value -is [System.Collections.IDictionary]) {
            # If the value is another hashtable, recursively convert it with increased indentation
            $output += "$currentIndentation`"$key`" = " + (Convert-HashtableToPsd1String -Hashtable $value -IndentLevel ($IndentLevel + 1)) + [Environment]::NewLine
        }
        elseif ($value -is [string]) {
            # If the value is a string, add it with quotes and proper indentation
            $output += "$currentIndentation`"$key`" = '$value'" + [Environment]::NewLine
        }
        elseif ($value -is [boolean]) {
            # If the value is a boolean, add it without quotes and proper indentation
            $output += "$currentIndentation`"$key`" = $value" + [Environment]::NewLine
        }
        elseif ($value -is [array]) {
            # If the value is an array, format each element properly with indentation
            $arrayOutput = "$currentIndentation`"$key`" = @(" + [Environment]::NewLine
            foreach ($item in $value) {
                if ($item -is [string]) {
                    $arrayOutput += "$currentIndentation`t'$item'" + [Environment]::NewLine
                }
                elseif ($item -is [hashtable] -or $item -is [System.Collections.IDictionary]) {
                    $arrayOutput += (Convert-HashtableToPsd1String -Hashtable $item -IndentLevel ($IndentLevel + 2)).Replace("@{", "$currentIndentation`t@{") + [Environment]::NewLine
                }
                elseif ($item -is [int] -or $item -is [float]) {
                    $arrayOutput += "$currentIndentation`t$item" + [Environment]::NewLine
                }
                else {
                    $arrayOutput += "$currentIndentation`t$item" + [Environment]::NewLine
                }
            }
            $arrayOutput += "$currentIndentation)" + [Environment]::NewLine
            $output += $arrayOutput
        }
        elseif ($value -is [int] -or $value -is [float]) {
            # If the value is a number, add it without quotes and with proper indentation
            $output += "$currentIndentation`"$key`" = $value" + [Environment]::NewLine
        }
        else {
            # If the value is of another type, add it as an empty hashtable (for demonstration) with proper indentation
            $output += "$currentIndentation`"$key`" = @{}" + [Environment]::NewLine
        }
    }

    $output += "$indentation}" + [Environment]::NewLine
    return $output
}


function Get-JsonWorkload {
    param (
        [System.Management.Automation.OrderedHashtable]
        $InputData
    ) 
    return [ordered]@{
        deployWithoutLicenseKeys    = $InputData.deployWithoutLicenseKeys
        skipEsxThumbprintValidation = $InputData.SkipEsxThumbprintValidation
        managementPoolName          = $InputData.Management.PoolName
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


        ntpServers                  = $InputData.NetworkSpecs.NtpServers
        dnsSpec                     = [ordered]@{
            subdomain  = $InputData.NetworkSpecs.dnsSpec.Subdomain
            domain     = $InputData.NetworkSpecs.dnsSpec.Domain
            nameserver = $InputData.NetworkSpecs.dnsSpec.NameServers
        }
        networkSpecs                = @(
            [ordered]@{
                networkType  = "MANAGEMENT"
                subnet       = $InputData.NetworkSpecs.ManagementNetwork.subnet
                gateway      = $InputData.NetworkSpecs.ManagementNetwork.gateway
                vlanId       = $InputData.NetworkSpecs.ManagementNetwork.vLanId
                mtu          = $InputData.NetworkSpecs.ManagementNetwork.Mtu
                portGroupKey = $InputData.NetworkSpecs.ManagementNetwork.portGroupKey    
            }
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
            }
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
            }
            [ordered]@{
                networkType  = "VM_MANAGEMENT"
                subnet       = $InputData.NetworkSpecs.VmManamegent.subnet
                gateway      = $InputData.NetworkSpecs.VmManamegent.gateway
                vlanId       = $InputData.NetworkSpecs.VmManamegent.vlanId
                mtu          = $InputData.NetworkSpecs.VmManamegent.mtu
                portGroupKey = $InputData.NetworkSpecs.VmManamegent.portGroupKey 
            }
        )
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
            ipAddressPoolSpec       = $InputData.Nsxt.ipAddressPoolSpec
        }
        vsanSpec                    = [ordered]@{
            licenseFile   = $InputData.vSan.LicenseFile
            vsanDedup     = (($InputData.vSan.ESA)? $false : ($InputData.vSan.Dedup))
            esaConfig     = [ordered]@{
                enabled = $InputData.vSan.ESA
            }
            hclFile       = $InputData.vSan.HclFile 
            datastoreName = $InputData.vSan.DatastoreName
        }

        <#    resourcePoolSpecs           = @( 
        @{
            name                        = 'vcf-m01-cl01-rp-sddc-mgmt'
            type                        = "management"
            cpuReservationPercentage    = 0
            cpuLimit                    = -1
            cpuReservationExpandable    = $true
            cpuSharesLevel              = "normal"
            cpuSharesValue              = 0
            memoryReservationMb         = 0
            memoryLimit                 = -1
            memoryReservationExpandable = $true
            memorySharesLevel           = "normal"
            memorySharesValue           = 0
        }
        @{
            name                        = 'vcf-m01-cl01-rp-sddc-edge'
            type                        = "network"
            cpuReservationPercentage    = 0
            cpuLimit                    = -1
            cpuReservationExpandable    = $true
            cpuSharesLevel              = "normal"
            cpuSharesValue              = 0
            memoryReservationPercentage = 0
            memoryLimit                 = -1
            memoryReservationExpandable = $true
            memorySharesLevel           = "normal"
            memorySharesValue           = 0
        }
        @{
            name                        = 'vcf-m01-cl01-rp-user-edge'
            type                        = 'compute'
            cpuReservationPercentage    = 0
            cpuLimit                    = -1
            cpuReservationExpandable    = $true
            cpuSharesLevel              = "normal"
            cpuSharesValue              = 0
            memoryReservationPercentage = 0
            memoryLimit                 = -1
            memoryReservationExpandable = $true
            memorySharesLevel           = "normal"
            memorySharesValue           = 0
        }
        @{
            name                        = 'vcf-m01-cl01-rp-user-vm'
            type                        = 'compute'
            cpuReservationPercentage    = 0
            cpuLimit                    = -1
            cpuReservationExpandable    = $true
            cpuSharesLevel              = "normal"
            cpuSharesValue              = 0
            memoryReservationPercentage = 0
            memoryLimit                 = -1
            memoryReservationExpandable = $true
            memorySharesLevel           = "normal"
            memorySharesValue           = 0
        }
    )#>
        dvsSpecs                    = @(
            [ordered]@{
                dvsName          = $InputData.Nsxt.DvsName 
                vmnics           = $InputData.Nsxt.Vmnics 
                mtu              = $InputData.Nsxt.Mtu 
                networks         = @("MANAGEMENT", "VMOTION", "VSAN", "VM_MANAGEMENT")
                niocSpecs        = @(
                    [ordered]@{
                        trafficType = "VSAN"
                        value       = "HIGH"
                    }
                    [ordered]@{
                        trafficType = "VMOTION"
                        value       = "LOW"
                    }
                    [ordered]@{
                        trafficType = "VDP"
                        value       = "LOW"
                    }
                    [ordered]@{
                        trafficType = "VIRTUALMACHINE"
                        value       = "HIGH"
                    }
                    [ordered]@{
                        trafficType = "MANAGEMENT"
                        value       = "NORMAL"
                    }
                    [ordered]@{
                        trafficType = "NFS"
                        value       = "LOW"
                    }
                    [ordered]@{
                        trafficType = "HBR"
                        value       = "LOW"
                    }
                    [ordered]@{
                        trafficType = "FAULTTOLERANCE"
                        value       = "LOW"
                    }
                    [ordered]@{
                        trafficType = "ISCSI"
                        value       = "LOW"
                    }
                )
                nsxtSwitchConfig = [ordered]@{
                    transportZones = get-TransportZone -Type $InputData.Nsxt.TransportType -SiteCode $InputData.SiteCode
                }
            }
        ) 
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
        pscSpecs                    = @(
            [ordered]@{
                adminUserSsoPassword = $InputData.VCenter.Password.Admin
                pscSsoSpec           = [ordered]@{
                    ssoDomain = $InputData.VCenter.SsoDomain 
                }
            }
        )
        vcenterSpec                 = [ordered]@{
            vcenterIp           = $InputData.VCenter.Ip 
            vcenterHostname     = $InputData.VCenter.Hostname 
            licenseFile         = $InputData.VCenter.License     
            vmSize              = $InputData.VCenter.Size.Vm  
            storageSize         = $InputData.VCenter.Size.Storage  
            rootVcenterPassword = $InputData.VCenter.Password.Root
        }
        hostSpecs                   = Get-HostSpec
    }


}



function Get-HostSpec {
    param (
        [System.Management.Automation.OrderedHashtable]
        $InputData
    ) 
    $hostSpecs = @()
    $i = 3
    foreach ($key in $InputData.NestedESXi.HostnameToIPsForManagementDomain.Keys ) {
        $h = [ordered]@{
            association      = $InputData.Management.Datacenter
            ipAddressPrivate = [ordered]@{
                ipAddress = $InputData.NestedESXi.HostnameToIPsForManagementDomain[$key]
                cidr      = $InputData.NetworkSpecs.ManagementNetwork.subnet
                gateway   = $InputData.NetworkSpecs.ManagementNetwork.gateway
            }
            hostname         = $key
            credentials      = [ordered]@{
                username = "root"
                password = $InputData.NestedESXi.Password
            } 

            vSwitch          = "vSwitch0"
            serverId         = "host-$($i-2)"
        }
        if (!$InputData.SkipEsxThumbprintValidation) {
            $h['sshThumbprint'] = ($null -eq $thumbprintImport[3].P2 )?"SHA256:DUMMY_VALUE":$thumbprintImport[$i].P2  
            $h['sslThumbprint'] = ($null -eq $thumbprintImport[3].P4)?"SHA25_DUMMY_VALUE": $thumbprintImport[$i].P4
        }

        $hostSpecs += $h
        $i++
    }
    return $hostSpecs
}

Export-ModuleMember -Function Test-VMForReImport
Export-ModuleMember -Function Write-Logger
Export-ModuleMember -Function Get-TransportZone
Export-ModuleMember -Function ConvertTo-Netmask
Export-ModuleMember -Function Convert-HashtableToPsd1String
Export-ModuleMember -Function Get-JsonWorkload