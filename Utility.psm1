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
                Write-Logger "Powering Off $($vm.name) ..."
                Stop-VM $vm -Confirm:$false | Out-Null
            }
            Write-Logger "Removing $($vm.name) ..."
            Remove-VM -VM $vm -DeletePermanently -Confirm:$false | Out-Null
            return $true, 'y'
        }
        'y' {
            if ($vm.PowerState -eq 'PoweredOn') {
                Write-Logger "Powering Off $($vm.name) ..."
                Stop-VM $vm -Confirm:$false | Out-Null
            }
            Write-Logger "Removing $($vm.name) ..."
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
        elseif ($value -is [int] -or $value -is [double]) {
            # If the value is a string, add it with quotes and proper indentation
            $output += "$currentIndentation`"$key`" = $value" + [Environment]::NewLine
        }
        elseif ($value -is [boolean]) {
            # If the value is a boolean, add it without quotes and proper indentation
            $output += "$currentIndentation`"$key`" = `$$value" + [Environment]::NewLine
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
                elseif ($item -is [int] -or $item -is [double]) {
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
        elseif ($null -eq $value  ) {
            $output += "$currentIndentation`"$key`" = null" + [Environment]::NewLine
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
        deployWithoutLicenseKeys    = $InputData.DeployWithoutLicenseKeys
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
            subdomain  = $InputData.NetworkSpecs.DnsSpec.Subdomain
            domain     = $InputData.NetworkSpecs.DnsSpec.Domain
            nameserver = $InputData.NetworkSpecs.DnsSpec.NameServers
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
                    transportZones = get-TransportZone -Type $InputData.Nsxt.TransportType -SiteCode $InputData.SddcId
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
        hostSpecs                   = Get-HostSpec -InputData $InputData
    }


}



function Get-HostSpec {
    param (
        [System.Management.Automation.OrderedHashtable]
        $InputData
    ) 
    $hostSpecs = @()
    $i = 3
    foreach ($key in $InputData.VirtualDeployment.Esx.Hosts.Keys ) {
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
            serverId         = "host-$($i-2)"
        }
        if (!$InputData.SkipEsxThumbprintValidation) {
            $h['sshThumbprint'] = $InputData.VirtualDeployment.Esx.Hosts[$key].SshThumbprint
            $h['sslThumbprint'] = $InputData.VirtualDeployment.Esx.Hosts[$key].SslThumbprint
        }

        $hostSpecs += $h
        $i++
    }
    return $hostSpecs
}



function Import-ExcelVCFData {
    param(
        [string]
        $Path
    )
    if (Test-Path $Path) {
        $r = Import-Excel -Path $Path -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 5 -EndColumn 7 -DataOnly
        $licenseImport = Import-Excel -Path $Path -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 5 -EndColumn 7 -DataOnly -StartRow 11 -EndRow 15
        $r2 = Import-Excel -Path $Path -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 9 -EndColumn 11 -DataOnly
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
    $deployWithoutLicenseKeys = $licenseImport[0].P2 -eq 'No' #License Now
    if ( $Virtual[23].P1 -ne 'n/a') {
        $wldHosts = [ordered]@{
            Ova           = (($EsxOVA)? $EsxOVA : $Virtual[1].P5) 
            vCPU          = $Virtual[13].P3
            vMemory       = $Virtual[14].P3
            BootDisk      = $Virtual[15].P3
            # Vsan disks
            CachingvDisk  = $Virtual[16].P3
            CapacityvDisk = $Virtual[17].P3
            # ESA disks
            ESADisk1      = $Virtual[16].P3
            ESADisk2      = $Virtual[17].P3 
            VMNetwork1    = $Virtual[18].P3 
            VMNetwork2    = $Virtual[19].P3 
            Syslog        = $Virtual[20].P3
   
            Password      = $credentialsImport[5].P2
            Hosts         = [ordered]@{}
        }
        for ($i = 24 ; $i -lt 32; $i++) {
            if ( $Virtual[$i].P1 -ne 'n/a') {
                $wldHosts.Hosts[$($Virtual[$i].P1)] = [ordered]@{ Ip = $Virtual[$i].P2; SshThumbprint = ($null -eq $Virtual[$i].P4 )?"SHA256:DUMMY_VALUE":$Virtual[$i].P4; SslThumbprint = ($null -eq $thumbprintImport[$i].P6 )?"SHA25_DUMMY_VALUE":$thumbprintImport[$i].P6 }            
            }
        }
    }
    else {
        $wldHosts = $null
    }

    return [ordered]@{
        VirtualDeployment           = [ordered]@{ 

            # General Deployment Configuration for Nested ESXi & Cloud Builder VM
            VMDatacenter = $Virtual[1].P2
            VMCluster    = $Virtual[2].P2
            VMDatastore  = $Virtual[3].P2
            VMFolder     = $Virtual[4].P2

            Esx          = [ordered]@{
                Ova           = (($EsxOVA)? $EsxOVA : $Virtual[1].P5) 
                vCPU          = $Virtual[13].P2
                vMemory       = $Virtual[14].P2
                BootDisk      = $Virtual[15].P2
                # Vsan disks
                CachingvDisk  = $Virtual[16].P2
                CapacityvDisk = $Virtual[17].P2
                # ESA disks
                ESADisk1      = $Virtual[16].P2
                ESADisk2      = $Virtual[17].P2 
                VMNetwork1    = $Virtual[18].P2 
                VMNetwork2    = $Virtual[19].P2 
                Syslog        = $Virtual[20].P2
           
                Password      = $credentialsImport[5].P2
                Hosts         = [ordered]@{
                    $esxImport[0].P1 = [ordered]@{Ip = $esxImport[1].P1; SshThumbprint = ($null -eq $thumbprintImport[3].P2 )?"SHA256:DUMMY_VALUE":$thumbprintImport[3].P2; SslThumbprint = ($null -eq $thumbprintImport[3].P4 )?"SHA25_DUMMY_VALUE":$thumbprintImport[3].P4 }
                    $esxImport[0].P2 = [ordered]@{Ip = $esxImport[1].P2; SshThumbprint = ($null -eq $thumbprintImport[4].P2 )?"SHA256:DUMMY_VALUE":$thumbprintImport[4].P2; SslThumbprint = ($null -eq $thumbprintImport[4].P4 )?"SHA25_DUMMY_VALUE":$thumbprintImport[4].P4 }
                    $esxImport[0].P3 = [ordered]@{Ip = $esxImport[1].P3; SshThumbprint = ($null -eq $thumbprintImport[5].P2 )?"SHA256:DUMMY_VALUE":$thumbprintImport[5].P2; SslThumbprint = ($null -eq $thumbprintImport[5].P4 )?"SHA25_DUMMY_VALUE":$thumbprintImport[5].P4 }
                    $esxImport[0].P4 = [ordered]@{Ip = $esxImport[1].P4; SshThumbprint = ($null -eq $thumbprintImport[6].P2 )?"SHA256:DUMMY_VALUE":$thumbprintImport[6].P2; SslThumbprint = ($null -eq $thumbprintImport[6].P4 )?"SHA25_DUMMY_VALUE":$thumbprintImport[6].P4 }
                }
            }
            WldEsx       = $wldHosts
            Cloudbuilder = [ordered]@{
                Ova           = (($CloudBuilderOVA)? $CloudBuilderOVA :$Virtual[2].P5)
                # Cloud Builder Configurations
                VMName        = $Virtual[6].P2
                Hostname      = $Virtual[7].P2
                Ip            = $Virtual[8].P2 
                AdminPassword = $Virtual[10].P2
                RootPassword  = $Virtual[11].P2
                PortGroup     = $Virtual[9].P2
            }

        }

        DeployWithoutLicenseKeys    = $deployWithoutLicenseKeys
        SddcId                      = $r[38].P2
        EsxLicense                  = ($deployWithoutLicenseKeys)?"":$licenseImport[1].P2
        workflowType                = "VCF"
        CeipEnabled                 = ($r2[5].P3 -ieq 'yes')
        FipsEnabled                 = ($r2[6].P3 -ieq 'yes')
        SkipEsxThumbprintValidation = $thumbprintImport[0].P3 -eq 'No'
        
        Management                  = [ordered]@{
            Datacenter = $r[18].P2 #Datacenter Name
            PoolName   = $r[37].P2 #Network Pool Name
        }
        # SDDC Manager Configuration
        SddcManager                 = [ordered]@{ 
            Hostname = [ordered]@{ 
                VcfPassword   = $credentialsImport[15].P2 #SDDC Manager Super User *
                RootPassword  = $credentialsImport[14].P2 #SDDC Manager Appliance Root Account *
                LocalPassword = $credentialsImport[16].P2 #SDDC Manager Local Account
                Ip            = $r[36].P2
                Hostname      = $r[35].P2
            }
        }
 
        VCenter                     = [ordered]@{
            Ip        = $r[13].P3
            Hostname  = $r[13].P2   
            License   = ($deployWithoutLicenseKeys)?"":$licenseImport[3].P2      
            Size      = [ordered]@{
                Vm      = $r[14].P2
                Storage = ($r[15].P2 -eq 'large')?"lstorage":(($r[15].P2 -eq 'xlarge')?"xlstorage":$null)
            } 
            Password  = [ordered]@{
                Admin = $credentialsImport[7].P2 
                Root  = $credentialsImport[8].P2
            }
            SsoDomain = "vsphere.local"
        }

        Cluster                     = [ordered]@{
            Name         = $r[19].P2        
            EvcMode      = $r[21].P2
            ImageEnabled = $r[20].P2 -eq 'yes'
        }

         
        NetworkSpecs                = [ordered]@{
            DnsSpec           = [ordered]@{
                Subdomain   = $r2[3].P2
                Domain      = $r2[3].P2
                NameServers = $( 
                    $ns = @()
                    for ($i = 3; $i -le 4; $i++) {
                        if ($r[$i].P2 -ne 'n/a') {
                            $ns += $r[$i].P2
                        }
                    }
                    $ns -join ','  # Join the array elements with a comma and return as the value
                )
            }
        
            NtpServers        = @(
                $nt = @()
                for ($i = 5; $i -le 6 ; $i++) {
                    if ($r[$i].P2 -ne 'n/a') {
                        $nt += $r[$i].P2
                    }  
                }
                $nt
            )
 
            #networkSpecs
            ManagementNetwork = [ordered]@{subnet = $mgmtNetworkImport[1].P4
                vLanId                            = [int]"$($mgmtNetworkImport[1].P2)"
                Mtu                               = [int]"$($mgmtNetworkImport[1].P6)"
                portGroupKey                      = $mgmtNetworkImport[1].P3
                gateway                           = $mgmtNetworkImport[1].P5
            }
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
            VmManamegent      = @{
                subnet       = $mgmtNetworkImport[0].P4
                gateway      = $mgmtNetworkImport[0].P5
                vlanId       = [int]"$($mgmtNetworkImport[0].P2)"
                mtu          = [int]"$($mgmtNetworkImport[0].P6)"
                portGroupKey = $mgmtNetworkImport[0].P3
            }
        }

        Nsxt                        = @{
            Managers          = @(
                for ($i = 30; $i -le 32; $i++) {
                    if ($r[$i].P2 -eq 'n/a') {
                        continue
                    }
                    [ordered]@{
                        hostname = $r[$i].P2
                        ip       = $r[$i].P3
                    }
                }
            )

            Password          = @{
                Root  = $credentialsImport[10].P2
                Admin = $credentialsImport[11].P2
                Audit = $credentialsImport[12].P2
            }
            ManagerSize       = $r[33].P2
            vip               = $r[29].P3
            vipFqdn           = $r[29].P2 
            License           = ($deployWithoutLicenseKeys)?"":$licenseImport[4].P2
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
        vSan                        = @{
            ESA           = ($r2[16].P2 -ieq 'yes')
            LicenseFile   = ($deployWithoutLicenseKeys)?"":$licenseImport[2].P2  
            HclFile       = ($r2[17].P2 )?$r2[17].P2 :""
            DatastoreName = $r2[14].P2
            Dedup         = ($r2[15].P2 -ieq 'yes')
        }
    } 
}



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
    $cred = [Management.Automation.PSCredential]::new('admin', $AdminPassword)

    if ($HclFile) {
        if ($UseSSH.isPresent) {
            $hclFiledest = Split-Path -Path $HclFile
            Write-Logger "SCP HCL $($HCLJsonFile) file to $($HclFile) ..."
            Set-SCPItem -ComputerName $CloudbuilderFqdn -Credential $cred -Path $HCLJsonFile -Destination $hclFiledest -AcceptKey
        }
        Write-Logger "Copy-VMGuestFile HCL $($HCLJsonFile) file to $($HclFile) ..."
        Copy-VMGuestFile -Source $HCLJsonFile -Destination $HclFile -GuestCredential $cred -VM $CloudbuilderVM -LocalToGuest -Force
    }
    Write-Logger "Submitting VCF Bringup request ..." 

    $bringupAPIParms = @{
        Uri         = "https://$CloudbuilderFqdn/v1/sddcs"
        Method      = 'POST'
        Body        = $Json
        ContentType = 'application/json'
        Credential  = $cred
    }
    $bringupAPIReturn = Invoke-RestMethod @bringupAPIParms -SkipCertificateCheck
    Write-Logger "Open browser to the VMware Cloud Builder UI (https://${CloudbuilderFqdn}) to monitor deployment progress ..."
}


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
    $answer = $null
    foreach ($VMName in  $Esx.Hosts.Keys) {
     
        $VMIPAddress = $Esx.Hosts[$VMname].Ip
        $vm = Get-VM -Name $VMName -Location $ImportLocation -ErrorAction SilentlyContinue

        $redeploy, $answer = Test-VMForReImport -Vm $vm -Answer $answer

        if (! $redeploy) {
            continue
        }
        $datacenter = $importLocation.Parentfolder | Get-Datacenter 
        $ovfconfig = Get-OvfConfiguration $esx.Ova
        $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
        $ovfconfig.NetworkMapping.$networkMapLabel.value = $esx.VMNetwork1
        $ovfconfig.common.guestinfo.hostname.value = "$VMName.$($NetworkSpecs.DnsSpec.Domain)"
        $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
        $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
        $ovfconfig.common.guestinfo.gateway.value = $NetworkSpecs.ManagementNetwork.gateway
        $ovfconfig.common.guestinfo.dns.value = $NetworkSpecs.DnsSpec.NameServers
        $ovfconfig.common.guestinfo.domain.value = $NetworkSpecs.DnsSpec.Domain
        $ovfconfig.common.guestinfo.ntp.value = $NetworkSpecs.NtpServers -join ","
        $ovfconfig.common.guestinfo.syslog.value = $esx.Syslog
        $ovfconfig.common.guestinfo.password.value = $esx.Password
        $ovfconfig.common.guestinfo.vlan.value = $NetworkSpecs.ManagementNetwork.vLanId
        $ovfconfig.common.guestinfo.ssh.value = $true

        Write-Logger "Deploying Nested ESXi VM $VMName ..."
        $vm = Import-VApp -Source $esx.Ova -OvfConfiguration $ovfconfig -Name $VMName -Location $importLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin 
    
        if (-not $vm) {
            Write-Logger -color red  -message "Deploy of $( $ovfconfig.common.guestinfo.hostname.value) failed."
            @{date = (Get-Date); failure = $true; vapp = $VApp; component = 'ESX' } | ConvertTo-Json | Out-File state.json
            exit
        }

        Write-Logger "Adding vmnic2/vmnic3 to Nested ESXi VMs ..."
        $vmPortGroup = Get-VirtualNetwork -Name $esx.VMNetwork2 -Location $datacenter
        if ($vmPortGroup.NetworkType -eq "Distributed") {
            $vmPortGroup = Get-VDPortgroup -Name $esx.VMNetwork2
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $vmPortGroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -Portgroup $vmPortGroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }
        else {
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $vmPortGroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            New-NetworkAdapter -VM $vm -Type Vmxnet3 -NetworkName $vmPortGroup -StartConnected -confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }

        $vm | New-AdvancedSetting -name "ethernet2.filter4.name" -value "dvfilter-maclearn" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet2.filter4.onFailure" -value "failOpen" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

        $vm | New-AdvancedSetting -name "ethernet3.filter4.name" -value "dvfilter-maclearn" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile
        $vm | New-AdvancedSetting -Name "ethernet3.filter4.onFailure" -value "failOpen" -confirm:$false -ErrorAction SilentlyContinue | Out-File -Append -LiteralPath $verboseLogFile

        Write-Logger "Updating vCPU Count to $($esx.vCPU) & vMEM to $($esx.vMemory) GB ..."
        Set-VM -VM $vm -NumCpu $esx.vCPU -CoresPerSocket $esx.vCPU -MemoryGB $esx.vMemory -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

   

        Write-Logger "Updating vSAN Boot Disk size to $($esx.BootDisk) GB ..."
        Get-HardDisk -VM $vm -Name "Hard disk 1" | Set-HardDisk -CapacityGB $esx.BootDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        # vSAN ESA requires NVMe Controller
        if ($VsanEsa.isPresent) {

            Write-Logger "Updating vSAN Disk Capacity VMDK size to $($esx.ESADisk1) GB  and $($esx.ESADisk2) GB .."
            Get-HardDisk -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $esx.ESADisk1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            Get-HardDisk -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $esx.ESADisk2 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            Write-Logger "Updating storage controller to NVMe for vSAN ESA ..."
            $devices = $vm.ExtensionData.Config.Hardware.Device

            $newControllerKey = -102

            # Reconfigure 1 - Add NVMe Controller & Update Disk Mapping to new controller
            $deviceChanges = @()
            $spec = [VMware.Vim.VirtualMachineConfigSpec]::new()

            $scsiController = $devices | Where-Object { $_.getType().Name -eq "ParaVirtualSCSIController" }
            $scsiControllerDisks = $scsiController.device

            $nvmeControllerAddSpec = [VMware.Vim.VirtualDeviceConfigSpec]::new()
            $nvmeControllerAddSpec.Device = [VMware.Vim.VirtualNVMEController]::new()
            $nvmeControllerAddSpec.Device.Key = $newControllerKey
            $nvmeControllerAddSpec.Device.BusNumber = 0
            $nvmeControllerAddSpec.Operation = 'add'
            $deviceChanges += $nvmeControllerAddSpec

            foreach ($scsiControllerDisk in $scsiControllerDisks) {
                $device = $devices | Where-Object { $_.key -eq $scsiControllerDisk }

                $changeControllerSpec = [VMware.Vim.VirtualDeviceConfigSpec]::new()
                $changeControllerSpec.Operation = 'edit'
                $changeControllerSpec.Device = $device
                $changeControllerSpec.Device.key = $device.key
                $changeControllerSpec.Device.unitNumber = $device.UnitNumber
                $changeControllerSpec.Device.ControllerKey = $newControllerKey
                $deviceChanges += $changeControllerSpec
            }

            $spec.deviceChange = $deviceChanges

            $task = $vm.ExtensionData.ReconfigVM_Task($spec)
            $task1 = Get-Task -Id ("Task-$($task.value)")
            $task1 | Wait-Task | Out-Null

            # Reconfigure 2 - Remove PVSCSI Controller
            $spec = [VMware.Vim.VirtualMachineConfigSpec]::new()
            $scsiControllerRemoveSpec = [VMware.Vim.VirtualDeviceConfigSpec]::new()
            $scsiControllerRemoveSpec.Operation = 'remove'
            $scsiControllerRemoveSpec.Device = $scsiController
            $spec.deviceChange = $scsiControllerRemoveSpec

            $task = $vm.ExtensionData.ReconfigVM_Task($spec)
            $task1 = Get-Task -Id ("Task-$($task.value)")
            $task1 | Wait-Task | Out-Null
        }
        else {
            Write-Logger "Updating vSAN Cache VMDK size to $($esx.CachingvDisk) GB & Capacity VMDK size to $($esx.CapacityvDisk) GB ..."
            Get-HardDisk -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $esx.CachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            Get-HardDisk -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $esx.CapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
        }


        Write-Logger "Powering On $vmname ..."
        $vm | Start-Vm -RunAsync | Out-Null
    }
}

Export-ModuleMember -Function Test-VMForReImport
Export-ModuleMember -Function Write-Logger
Export-ModuleMember -Function Get-TransportZone
Export-ModuleMember -Function ConvertTo-Netmask
Export-ModuleMember -Function Convert-HashtableToPsd1String
Export-ModuleMember -Function Get-JsonWorkload
Export-ModuleMember -Function Import-ExcelVCFData
Export-ModuleMember -Function Invoke-BringUp
Export-ModuleMember -Function Add-VirtualEsx