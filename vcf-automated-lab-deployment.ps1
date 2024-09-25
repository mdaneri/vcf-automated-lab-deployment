param(
    [string]
    $ExcelFile = ".\vcf-ems-Deployment-Parameter11.xlsx"
)
# Author: William Lam
# Website: www.williamlam.com
install-Module -Name ImportExcel -Scope CurrentUser
 
Import-Module -Name ./Utility.psm1



# Cloud Builder Configurations
$CloudbuilderVMHostname = "cloudbuilder"
$CloudbuilderFQDN = "cloudbuilder.vcf.lab.local"
$CloudbuilderIP = "192.168.10.195"
$CloudbuilderAdminUsername = "admin"
$CloudbuilderAdminPassword = "VMw@re123!VMw@re123!"
$CloudbuilderRootPassword = "VMw@re123!VMw@re123!"



# General Deployment Configuration for Nested ESXi & Cloud Builder VM
$VMDatacenter = "Datacenter"
$VMCluster = "Cluster01"
#$ClusterEvcMode = ""
$VMNetwork = "VLAN-10"
$ESXVMNetwork1 = "Trunk"
$ESXVMNetwork2 = "Trunk"
$VMDatastore = "NVMe02"
$VMFolder = "VCF"


# Nested ESXi VM Resources for Management Domain
$NestedESXiMGMTvCPU = "12"
$NestedESXiMGMTvMEM = "78" #GB
$NestedESXiMGMTCachingvDisk = "4" #GB
$NestedESXiMGMTCapacityvDisk = "500" #GB
$NestedESXiMGMTBootDisk = "32" #GB

# Nested ESXi VM Resources for Workload Domain
$NestedESXiWLDVSANESA = $true
$NestedESXiWLDvCPU = "8"
$NestedESXiWLDvMEM = "36" #GB
$NestedESXiWLDCachingvDisk = "4" #GB
$NestedESXiWLDCapacityvDisk = "250" #GB
$NestedESXiWLDBootDisk = "32" #GB

 

#$VMNetmask = "255.255.255.0"
#$NestedESXiManagementNetwork_gateway = "192.168.10.254"
#$nameServers = "192.168.0.250"
#$ntpServers = "192.168.0.1"
#$VMPassword = "VMw@re123!VMw@re123!"
#$domain = "vcf.lab.local"
#$VMSyslog = "172.17.31.182"
 

#### DO NOT EDIT BEYOND HERE ####

$verboseLogFile = "vcf-lab-deployment.log"
$random_string = -join ((65..90) + (97..122) | Get-Random -Count 8 | % { [char]$_ })
$VAppName = "Nested-VCF-Lab-$random_string"
$SeparateNSXSwitch = $false
$VCFVersion = ""




if (Test-Path $ExcelFile) {
    $r = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 5 -EndColumn 7 -DataOnly
    $licenseImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 5 -EndColumn 7 -DataOnly -StartRow 11 -EndRow 15
    $r2 = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Deploy Parameters' -StartColumn 9 -EndColumn 11 -DataOnly
    $credentialsImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'credentials' -DataOnly   
    $mgmtNetworkImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 2 -EndColumn 7 -DataOnly -Raw -StartRow 7 -EndRow 10
    $esxImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 12 -DataOnly -Raw -StartRow 6 -EndRow 7
    $rangeImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 12 -DataOnly -Raw -StartRow 8 -EndRow 10
    $dsImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 2 -EndColumn 7 -DataOnly -Raw -StartRow 12 -EndRow 21
    $overlayImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 13 -DataOnly -Raw -StartRow 22 -EndRow 28
    $thumbprintImport = Import-Excel -Path $ExcelFile -NoHeader -WorksheetName 'Hosts and Networks' -StartColumn 9 -EndColumn 13 -DataOnly -Raw -StartRow 12 -EndRow 18
}




# row   vSphere Resource Pools                                                                                                                            Value
#$r[24] Resource Pool SDDC Management                                                                                                                     sfo-m01-cluster-001-management-001
#$r[25] Resource Pool User Edge                                                                                                                           sfo-m01-cluster-001-compute-002
#$r[26] Resource Pool User VM                                                                                                                             sfo-m01-cluster-001-compute-003


#row Proxy Server Configuration                              No
# 22 Proxy Server                                            n/a
# 23 Proxy Port                                              n/a
# 24 Proxy Username                                          n/a
# 25 Proxy Password                                          n/a
# 26 Proxy Transfer Protocol                                 HTTP
# 27 HTTPS Proxy Certificate (PEM Encoded)…                  n/a
 
# row Secondary vSphere Distributed Switch (Optional)            Value
# 6   Secondary vSphere Distributed Switch - Name *              n/a
# 7   Secondary vSphere Distributed Switch - Transport Zone Type n/a
# 8   Secondary vSphere Distributed Switch - pNICs               vmnic2,vmnic3
# 9   Secondary vSphere Distributed Switch - MTU Size            9000.00
$SiteCode = 'sfo-m01'
$NestedESXiHostnameToIPsForManagementDomain = [ordered]@{
    $esxImport[0].P1 = $esxImport[1].P1
    $esxImport[0].P2 = $esxImport[1].P2
    $esxImport[0].P3 = $esxImport[1].P3
    $esxImport[0].P4 = $esxImport[1].P4
}

$deployWithoutLicenseKeys = $licenseImport[0].P2 -eq 'No' #License Now

$managementDatacenter = $r[18].P2 #Datacenter Name
$managementPoolName = $r[37].P2 #Network Pool Name

# SDDC Manager Configuration
$SddcManagerVcfPassword = $credentialsImport[15].P2 #SDDC Manager Super User *
$SddcManagerRootPassword = $credentialsImport[14].P2 #SDDC Manager Appliance Root Account *
$SddcManagerLocalPassword = $credentialsImport[16].P2 #SDDC Manager Local Account
$SddcManagerIP = $r[36].P2
$SddcManagerHostname = $r[35].P2

#networkSpecs
$NestedESXiManagementNetwork_subnet = $mgmtNetworkImport[1].P4
#$NestedESXiManagementNetwork_gateway
$NestedESXiManagementNetwork_vLanId = $mgmtNetworkImport[1].P2
$NestedESXiManagementNetwork_Mtu = $mgmtNetworkImport[1].P6
$NestedESXiManagementNetwork_portGroupKey = $mgmtNetworkImport[1].P3
$NestedESXiManagementNetwork_gateway = $mgmtNetworkImport[1].P5

$NestedESXivMotionNetwork_subnet = $mgmtNetworkImport[2].P4
$NestedESXivMotionNetwork_vLanId = $mgmtNetworkImport[2].P2
$NestedESXivMotionNetwork_Mtu = $mgmtNetworkImport[2].P6
$NestedESXivMotionNetwork_portGroupKey = $mgmtNetworkImport[2].P3
$NestedESXivMotionNetwork_gateway = $mgmtNetworkImport[2].P5

$NestedESXivMotionRangeStart = $rangeImport[0].p4
$NestedESXivMotionRangeEnd = $rangeImport[0].p2


$NestedESXivSanNetwork_subnet = $mgmtNetworkImport[3].P4
$NestedESXivSanNetwork_vLanId = $mgmtNetworkImport[3].P2
$NestedESXivSanNetwork_Mtu = $mgmtNetworkImport[3].P6
$NestedESXivSanNetwork_portGroupKey = $mgmtNetworkImport[3].P3
$NestedESXivSanNetwork_gateway = $mgmtNetworkImport[3].P5

$NestedESXivSanRangeStart = $rangeImport[1].p4
$NestedESXivSanRangeEnd = $rangeImport[1].p2


$VMPassword = $credentialsImport[5].P2
$VMNetmask = ConvertTo-Netmask -NetworkCIDR $NestedESXiManagementNetwork_subnet
$subdomain = $r2[3].P2
$domain = $r2[3].P2
$hostSpecs = @()
$i = 3
foreach ($key in $NestedESXiHostnameToIPsForManagementDomain ) {
    $hostSpecs += [ordered]@{
        association      = $managementDatacenter
        ipAddressPrivate = [ordered]@{
            ipAddress = $NestedESXiHostnameToIPsForManagementDomain[$key]
        }
        hostname         = $key
        credentials      = [ordered]@{
            username = "root"
            password = $VMPassword
        }
        sshThumbprint    = ($null -eq $thumbprintImport[3].P2 )?"SHA256:DUMMY_VALUE":$thumbprintImport[$i].P2  
        sslThumbprint    = ($null -eq $thumbprintImport[3].P4)?"SHA25_DUMMY_VALUE": $thumbprintImport[$i].P4
    }
    $i++
}
 


#VMManagement
$VmManamegent_subnet = $mgmtNetworkImport[0].P4
$VmManamegent_gateway = $mgmtNetworkImport[0].P5
$VmManamegent_vlanId = $mgmtNetworkImport[0].P2
$VmManamegent_mtu = $mgmtNetworkImport[0].P6
$VmManamegent_portGroupKey = $mgmtNetworkImport[0].P3

<# 
# ESXi Network Configuration
$NestedESXiManagementNetwork_subnet = "192.168.10.0/24" # should match $VMNetwork configuration
$NestedESXiManagementNetwork_vLanId = "10"
$NestedESXivMotionNetwork_subnet = "192.168.11.0/24"
$NestedESXivMotionNetwork_vLanId = "11"
$NestedESXivSANNetworkCidr = "192.168.12.0/24"
$NestedESXivSANNetwork_vLanId = "12"
$NestedESXiNSXTepNetworkCidr = "192.168.13.0/24"
$NestedESXiNSXTepNetwork_vLanId = "13"
#>

#nsxt

$nsxtManagers = @()
for ($i = 30; $i -le 32; $i++) {
    if ($r[30].P2 -eq 'n/a') {
        continue
    }
    $nsxtManagers += [ordered]@{
        hostname = $r[$i].P2
        ip       = $r[$i].P3
    }
}

$rootNsxtManagerPassword = $credentialsImport[10].P2
$nsxtAdminPassword = $credentialsImport[11].P2
$nsxtAuditPassword = $credentialsImport[12].P2
$nsxtManagerSize = $r[33].P2
$nsxtvip = $r[29].P3
$nsxtvipFqdn = $r[29].P2 

$nameServers = @()
for ($i = 3; $i -le 4; $i++) {
    if ($r[$i].P2 -ne 'n/a') {
        $nameServers += $r[$i].P2
    }  
}

$ntpServers = @()
for ($i = 5; $i -le 6 ; $i++) {
    if ($r[$i].P2 -ne 'n/a') {
        $ntpServers += $r[$i].P2
    }  
}
$nsxtLicense = $licenseImport[4].P2
$nsxtTransportVlanId = $overlayImport[0].P2
$nsxtipAddressPoolSpec = [ordered]@{
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


$vsanSpec = [ordered]@{
    licenseFile   = $licenseImport[2].P2
    vsanDedup     = ($r2[15].P2 -ieq 'yes')
    esaConfig     = [ordered]@{
        enabled = ($r2[16].P2 -ieq 'yes')
    }
    hclFile       = $r2[17].P2 
    datastoreName = $r2[14].P2
}


# VCF Configurations
$VCFManagementDomainPoolName = "vcf-m01-rp01"
$VCFManagementDomainJSONFile = "vcf-mgmt.json"
$VCFWorkloadDomainUIJSONFile = "vcf-commission-host-ui.json"
$VCFWorkloadDomainAPIJSONFile = "vcf-commission-host-api.json"

$orderedHashTable = [ordered]@{
    deployWithoutLicenseKeys    = $deployWithoutLicenseKeys
    skipEsxThumbprintValidation = $thumbprintImport[0].P3 -eq 'No'
    managementPoolName          = $managementPoolName
    sddcManagerSpec             = [ordered]@{
        secondUserCredentials = [ordered]@{
            username = "vcf"
            password = $SddcManagerVcfPassword
        }        
        rootUserCredentials   = [ordered]@{
            username = 'root'
            password = $SddcManagerRootPassword
        }
        localUserPassword     = $SddcManagerLocalPassword
        ipAddress             = $SddcManagerIP
        hostname              = $SddcManagerHostname
    }
    sddcId                      = $r[38].P2
    esxLicense                  = $licenseImport[1].P2
    workflowType                = "VCF"
    ceipEnabled                 = ($r2[5].P3 -ieq 'yes')
    fipsEnabled                 = ($r2[6].P3 -ieq 'yes')
    ntpServers                  = $ntpServers
    dnsSpec                     = [ordered]@{
        subdomain  = $subdomain
        domain     = $domain
        nameserver = $nameServers
    }
    networkSpecs                = @(
        [ordered]@{
            networkType  = "MANAGEMENT"
            subnet       = $NestedESXiManagementNetwork_subnet
            vlanId       = $NestedESXiManagementNetwork_vLanId
            mtu          = $NestedESXiManagementNetwork_Mtu
            portGroupKey = $NestedESXiManagementNetwork_portGroupKey
        }
        [ordered]@{
            networkType            = "VMOTION"
            subnet                 = $NestedESXivMotionNetwork_subnet
            gateway                = $NestedESXivMotionNetwork_gateway
            vlanId                 = $NestedESXivMotionNetwork_vLanId
            mtu                    = $NestedESXivMotionNetwork_Mtu
            portGroupKey           = $NestedESXivMotionNetwork_portGroupKey
            includeIpAddressRanges = @(
                [ordered]@{
                    endIpAddress   = $NestedESXivMotionRangeEnd
                    startIpAddress = $NestedESXivMotionRangeStart
                }
            )
        }
        [ordered]@{
            networkType            = "VSAN"
            subnet                 = $NestedESXivSanNetwork_subnet
            gateway                = $NestedESXivSanNetwork_gateway
            vlanId                 = $NestedESXivSanNetwork_vLanId
            mtu                    = $NestedESXivSanNetwork_Mtu
            portGroupKey           = $NestedESXivSanNetwork_portGroupKey
            includeIpAddressRanges = @(
                [ordered]@{
                    endIpAddress   = $NestedESXivSanRangeStart
                    startIpAddress = $NestedESXivSanRangeEnd
                }
            )
        }
        [ordered]@{
            networkType  = "VM_MANAGEMENT"
            subnet       = $VmManamegent_subnet
            gateway      = $VmManamegent_gateway
            vlanId       = $VmManamegent_vlanId
            mtu          = $VmManamegent_mtu
            portGroupKey = $VmManamegent_portGroupKey 
        }
    )
    nsxtSpec                    = [ordered]@{
        nsxtManagerSize         = $nsxtManagerSize
        nsxtManagers            = $nsxtManagers
        rootNsxtManagerPassword = $rootNsxtManagerPassword
        nsxtAdminPassword       = $nsxtAdminPassword
        nsxtAuditPassword       = $nsxtAuditPassword
        vip                     = $nsxtvip
        vipFqdn                 = $nsxtvipFqdn
        nsxtLicense             = $nsxtLicense
        transportVlanId         = $nsxtTransportVlanId
        ipAddressPoolSpec       = $nsxtipAddressPoolSpec
    }
    vsanSpec                    = $vsanSpec
    dvsSpecs                    = @(
        [ordered]@{
            dvsName          = $dsImport[1].P2
            vmnics           = @($dsImport[2].p2 -split ',')
            mtu              = $dsImport[3].P2
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
                transportZones = get-TransportZone -Type $dsImport[4].p2 
            }
        }
    )
    clusterSpec                 = [ordered]@{
        clusterName         = $r[19].P2        
        clusterImageEnabled = $r[20].P2 -eq 'yes'
        clusterEvcMode      = $r[21].P2
        vmFolders           = [ordered]@{
            MANAGEMENT = "$SiteCode-fd-mgmt"
            NETWORKING = "$SiteCode-fd-nsx"
            EDGENODES  = "$SiteCode-fd-edge"
        } 
    }
    pscSpecs                    = @(
        [ordered]@{
            adminUserSsoPassword = $credentialsImport[7].P2
            pscSsoSpec           = [ordered]@{
                ssoDomain = "vsphere.local"
            }
        }
    )
    vcenterSpec                 = [ordered]@{
        licenseFile         = $licenseImport[3].P2
        vcenterIp           = $r[13].P3
        vcenterHostname     = $r[13].P2         
        vmSize              = $r[14].P2
        storageSize         = $r[15].P2
        rootVcenterPassword = $credentialsImport[8].P2
    }
    hostSpecs                   = $hostSpecs
}







# vCenter Server used to deploy VMware Cloud Foundation Lab
$VIServer = "vmw-vc01.lab.local"
$VIUsername = "administrator@vsphere.local"
$VIPassword = "Pata2Pata1!"

# Full Path to both the Nested ESXi & Cloud Builder OVA
$NestedESXiApplianceOVA = "./ova/Nested_ESXi8.0u3_Appliance_Template_v1.ova"
$CloudBuilderOVA = "./ova/VMware-Cloud-Builder-5.2.0.0-24108943_OVF10.ova"

# VCF Licenses or leave blank for evaluation mode (requires VCF 5.1.1 or later)
 
 
 

# SDDC Manager Configuration
#$SddcManagerHostname = "sfo-vcf01"
#$SddcManagerIP = "192.168.10.203"
#$SddcManagerVcfPassword = "VMw@re123!VMw@re123!"
#$SddcManagerRootPassword = "VMw@re123!VMw@re123!"
#$SddcManagerRestPassword = "VMw@re123!VMw@re123!"
#$SddcManagerLocalPassword = "VMw@re123!VMw@re123!"

# Nested ESXi VMs for Workload Domain
#$NestedESXiHostnameToIPsForWorkloadDomain = [ordered]@{
 #   "vcf42-esx05" = "192.168.10.104"
  #  "vcf42-esx06" = "192.168.10.105"
  #  "vcf42-esx07" = "192.168.10.106"
  #  "vcf42-esx08" = "192.168.10.107"
#}
 
<# 
# vCenter Configuration
$VCSAName = "sfo-m01-vc01"
$VCSAIP = "192.168.10.202"
$VCSARootPassword = "VMware1!"
$VCSASSOPassword = "VMware1!"
$EnableVCLM = $true

# NSX Configuration
$NSXManagerVIPHostname = "sfo-m01-nsx01"
$NSXManagerVIPIP = "192.168.10.211"
$NSXManagerNode1Hostname = "sfo-m01-nsx01a"
$NSXManagerNode1IP = "192.168.10.212"
$NSXRootPassword = "VMw@re123!VMw@re123!"
$NSXAdminPassword = "VMw@re123!VMw@re123!"
$NSXAuditPassword = "VMw@re123!VMw@re123!"
#>
 

$credentialsreCheck = 1
$confirmDeployment = 1
$deployNestedESXiVMsForMgmt = 1
$deployNestedESXiVMsForWLD = 0
$deployCloudBuilder = 1
$moveVMsIntovApp = 1
$generateMgmJson = 1
$startVCFBringup = 1
$generateWldHostCommissionJson = 0
$uploadVCFNotifyScript = 0

$srcNotificationScript = "vcf-bringup-notification.sh"
$dstNotificationScript = "/root/vcf-bringup-notification.sh"

$StartTime = Get-Date

 

 
if ($credentialsreCheck -eq 1) {
    # Detect VCF version based on Cloud Builder OVA (support is 5.1.0+)
    if ($CloudBuilderOVA -match "5.2.0") {
        $VCFVersion = "5.2.0"
    }
    elseif ($CloudBuilderOVA -match "5.1.1") {
        $VCFVersion = "5.1.1"
    }
    elseif ($CloudBuilderOVA -match "5.1.0") {
        $VCFVersion = "5.1.0"
    }
    else {
        $VCFVersion = $null
    }

    if ($null -eq $VCFVersion) {
        Write-Host -ForegroundColor Red "`nOnly VCF 5.1.0, 5.1.1 & 5.2 is currently supported ...`n"
        exit
    }

    if ($VCFVersion -ge "5.2.0") {
        write-host "here"
        if ( $CloudbuilderAdminPassword.ToCharArray().count -lt 15 -or $CloudbuilderRootPassword.ToCharArray().count -lt 15) {
            Write-Host -ForegroundColor Red "`nCloud Builder passwords must be 15 characters or longer ...`n"
            exit
        }
    }

    if (!(Test-Path $NestedESXiApplianceOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $NestedESXiApplianceOVA ...`n"
        exit
    }

    if (!(Test-Path $CloudBuilderOVA)) {
        Write-Host -ForegroundColor Red "`nUnable to find $CloudBuilderOVA ...`n"
        exit
    }

    if ($PSVersionTable.PSEdition -ne "Core") {
        Write-Host -ForegroundColor Red "`tPowerShell Core was not detected, please install that before continuing ... `n"
        exit
    }
}

if ($confirmDeployment -eq 1) {
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- VCF Automated Lab Deployment Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "VMware Cloud Foundation Version: "
    Write-Host -ForegroundColor White $VCFVersion
    Write-Host -NoNewline -ForegroundColor Green "Nested ESXi Image Path: "
    Write-Host -ForegroundColor White $NestedESXiApplianceOVA
    Write-Host -NoNewline -ForegroundColor Green "Cloud Builder Image Path: "
    Write-Host -ForegroundColor White $CloudBuilderOVA

    Write-Host -ForegroundColor Yellow "`n---- vCenter Server Deployment Target Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "vCenter Server Address: "
    Write-Host -ForegroundColor White $VIServer
    Write-Host -NoNewline -ForegroundColor Green "VM Network: "
    Write-Host -ForegroundColor White $VMNetwork

    Write-Host -NoNewline -ForegroundColor Green "ESX VM Network 1: "
    Write-Host -ForegroundColor White $ESXVMNetwork1

    Write-Host -NoNewline -ForegroundColor Green "ESX VM Network 2: "
    Write-Host -ForegroundColor White $ESXVMNetwork2

    Write-Host -NoNewline -ForegroundColor Green "VM Storage: "
    Write-Host -ForegroundColor White $VMDatastore
    Write-Host -NoNewline -ForegroundColor Green "VM Cluster: "
    Write-Host -ForegroundColor White $VMCluster
    Write-Host -NoNewline -ForegroundColor Green "VM vApp: "
    Write-Host -ForegroundColor White $VAppName

    Write-Host -ForegroundColor Yellow "`n---- Cloud Builder Configuration ----"
    Write-Host -NoNewline -ForegroundColor Green "Hostname: "
    Write-Host -ForegroundColor White $CloudbuilderVMHostname
    Write-Host -NoNewline -ForegroundColor Green "IP Address: "
    Write-Host -ForegroundColor White $CloudbuilderIP

    if ($deployNestedESXiVMsForMgmt -eq 1) {
        Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration for VCF Management Domain ----"
        Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
        Write-Host -ForegroundColor White $NestedESXiHostnameToIPsForManagementDomain.count
        Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
        Write-Host -ForegroundColor White $NestedESXiHostnameToIPsForManagementDomain.Values
        Write-Host -NoNewline -ForegroundColor Green "vCPU: "
        Write-Host -ForegroundColor White $NestedESXiMGMTvCPU
        Write-Host -NoNewline -ForegroundColor Green "vMEM: "
        Write-Host -ForegroundColor White "$NestedESXiMGMTvMEM GB"
        Write-Host -NoNewline -ForegroundColor Green "Caching VMDK: "
        Write-Host -ForegroundColor White "$NestedESXiMGMTCachingvDisk GB"
        Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
        Write-Host -ForegroundColor White "$NestedESXiMGMTCapacityvDisk GB"
    }

    if ($deployNestedESXiVMsForWLD -eq 1) {
        Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration for VCF Workload Domain ----"
        Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
        Write-Host -ForegroundColor White $NestedESXiHostnameToIPsForWorkloadDomain.count
        Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
        Write-Host -ForegroundColor White $NestedESXiHostnameToIPsForWorkloadDomain.Values
        Write-Host -NoNewline -ForegroundColor Green "vCPU: "
        Write-Host -ForegroundColor White $NestedESXiWLDvCPU
        Write-Host -NoNewline -ForegroundColor Green "vMEM: "
        Write-Host -ForegroundColor White "$NestedESXiWLDvMEM GB"
        Write-Host -NoNewline -ForegroundColor Green "Caching VMDK: "
        Write-Host -ForegroundColor White "$NestedESXiWLDCachingvDisk GB"
        Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
        Write-Host -ForegroundColor White "$NestedESXiWLDCapacityvDisk GB"
    }

    Write-Host -NoNewline -ForegroundColor Green "`nNetmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $NestedESXiManagementNetwork_gateway
    Write-Host -NoNewline -ForegroundColor Green "DNS: "
    Write-Host -ForegroundColor White $nameServers
    Write-Host -NoNewline -ForegroundColor Green "NTP: "
    Write-Host -ForegroundColor White $ntpServers
    Write-Host -NoNewline -ForegroundColor Green "Syslog: "
    Write-Host -ForegroundColor White $VMSyslog

    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if (( 'yes', 'y', 'true', 1 -notcontains $answer)) {
        exit
    }
    Clear-Host
}

if ($deployNestedESXiVMsForMgmt -eq 1 -or $deployNestedESXiVMsForWLD -eq 1 -or $deployCloudBuilder -eq 1 -or $moveVMsIntovApp -eq 1) {
    Write-Logger "Connecting to Management vCenter Server $VIServer ..."
    $viConnection = Connect-VIServer $VIServer -User $VIUsername -Password $VIPassword -WarningAction SilentlyContinue 

    $datastore = Get-Datastore -Server $viConnection -Name $VMDatastore | Select-Object -First 1
    $cluster = Get-Cluster -Server $viConnection -Name $VMCluster
    $vmhost = $cluster | Get-VMHost | Get-Random -Count 1
}

if ($moveVMsIntovApp -eq 1) {
    # Check whether DRS is enabled as that is required to create vApp
    if ((Get-Cluster -Server $viConnection $cluster).DrsEnabled) {

        if (-Not (Get-Folder $VMFolder -ErrorAction Ignore)) {
            Write-Logger "Creating VM Folder $VMFolder ..."
            $folder = New-Folder -Name $VMFolder -Server $viConnection -Location (Get-Datacenter $VMDatacenter | Get-Folder vm)
        }
        $VApp = Get-VApp -Name $VAppName -Server $viConnection -Location $cluster -ErrorAction SilentlyContinue
        if ( $null -eq $VApp) {
            Write-Logger "Creating vApp $VAppName ..."
            $VApp = New-VApp -Name $VAppName -Server $viConnection -Location $cluster -InventoryLocation $folder
        }
        $importLocation = $VApp
    }
    else {
        Write-Logger "vApp $VAppName will NOT be created as DRS is NOT enabled on vSphere Cluster ${cluster} ..."
    }
}
else {
    $importLocation = $VMCluster
}


if ($deployNestedESXiVMsForMgmt -eq 1) {
    $answer = $null
    $NestedESXiHostnameToIPsForManagementDomain.GetEnumerator().foreach({ 
            $VMName = $_.Key
            $VMIPAddress = $_.Value
            $vm = Get-VM -Name $_.Key -Server $viConnection -Location $importLocation -ErrorAction SilentlyContinue

            $redeploy, $answer = Test-VMForReImport -Vm $vm -Answer $answer

            if (! $redeploy) {
                return
            }

            $ovfconfig = Get-OvfConfiguration $NestedESXiApplianceOVA
            $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
            $ovfconfig.NetworkMapping.$networkMapLabel.value = $ESXVMNetwork1
            $ovfconfig.common.guestinfo.hostname.value = "${VMName}.${VMDomain}"
            $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
            $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
            $ovfconfig.common.guestinfo.gateway.value = $NestedESXiManagementNetwork_gateway
            $ovfconfig.common.guestinfo.dns.value = $nameServers
            $ovfconfig.common.guestinfo.domain.value = $domain
            $ovfconfig.common.guestinfo.ntp.value = $ntpServers
            $ovfconfig.common.guestinfo.syslog.value = $VMSyslog
            $ovfconfig.common.guestinfo.password.value = $VMPassword
            $ovfconfig.common.guestinfo.vlan.value = $NestedESXiManagementNetwork_vLanId
            $ovfconfig.common.guestinfo.ssh.value = $true

            Write-Logger "Deploying Nested ESXi VM $VMName ..."
            $vm = Import-VApp -Source $NestedESXiApplianceOVA -OvfConfiguration $ovfconfig -Name $VMName -Location $importLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin 

            Write-Logger "Adding vmnic2/vmnic3 to Nested ESXi VMs ..."
            $vmPortGroup = Get-VirtualNetwork -Name $ESXVMNetwork2 -Location ($cluster | Get-Datacenter)
            if ($vmPortGroup.NetworkType -eq "Distributed") {
                $vmPortGroup = Get-VDPortgroup -Name $ESXVMNetwork2
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

            Write-Logger "Updating vCPU Count to $NestedESXiMGMTvCPU & vMEM to $NestedESXiMGMTvMEM GB ..."
            Set-VM -Server $viConnection -VM $vm -NumCpu $NestedESXiMGMTvCPU -CoresPerSocket $NestedESXiMGMTvCPU -MemoryGB $NestedESXiMGMTvMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            Write-Logger "Updating vSAN Cache VMDK size to $NestedESXiMGMTCachingvDisk GB & Capacity VMDK size to $NestedESXiMGMTCapacityvDisk GB ..."
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $NestedESXiMGMTCachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $NestedESXiMGMTCapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            Write-Logger "Updating vSAN Boot Disk size to $NestedESXiMGMTBootDisk GB ..."
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 1" | Set-HardDisk -CapacityGB $NestedESXiMGMTBootDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            Write-Logger "Powering On $vmname ..."
            $vm | Start-Vm -RunAsync | Out-Null
            
        })
}

if ($deployNestedESXiVMsForWLD -eq 1) {
    $answer = ""
    $NestedESXiHostnameToIPsForWorkloadDomain.GetEnumerator().foreach({ 
            $VMName = $_.Key
            $VMIPAddress = $_.Value
            
            $vm = Get-VM -Name $_.Key -Server $viConnection -Location $importLocation -ErrorAction SilentlyContinue

            $redeploy, $answer = Test-VMForReImport -Vm $vm -Answer $answer

            if (! $redeploy) {
                return
            }
            
            $ovfconfig = Get-OvfConfiguration $NestedESXiApplianceOVA
            $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
            $ovfconfig.NetworkMapping.$networkMapLabel.value = $ESXVMNetwork1
            $ovfconfig.common.guestinfo.hostname.value = "${VMName}.${VMDomain}"
            $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
            $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
            $ovfconfig.common.guestinfo.gateway.value = $NestedESXiManagementNetwork_gateway
            $ovfconfig.common.guestinfo.dns.value = $nameServers
            $ovfconfig.common.guestinfo.domain.value = $domain
            $ovfconfig.common.guestinfo.ntp.value = $ntpServers
            $ovfconfig.common.guestinfo.syslog.value = $VMSyslog
            $ovfconfig.common.guestinfo.password.value = $VMPassword
            $ovfconfig.common.guestinfo.ssh.value = $true

            Write-Logger "Deploying Nested ESXi VM $VMName ..."
            $vm = Import-VApp -Source $NestedESXiApplianceOVA -OvfConfiguration $ovfconfig -Name $VMName -Location $importLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

            Write-Logger "Adding vmnic2/vmnic3 to Nested ESXi VMs ..."
            $vmPortGroup = Get-VirtualNetwork -Name $ESXVMNetwork2 -Location ($cluster | Get-Datacenter)
            if ($vmPortGroup.NetworkType -eq "Distributed") {
                $vmPortGroup = Get-VDPortgroup -Name $ESXVMNetwork2
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

            Write-Logger "Updating vCPU Count to $NestedESXiWLDvCPU & vMEM to $NestedESXiWLDvMEM GB ..."
            Set-VM -Server $viConnection -VM $vm -NumCpu $NestedESXiWLDvCPU -CoresPerSocket $NestedESXiWLDvCPU -MemoryGB $NestedESXiWLDvMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            Write-Logger "Updating vSAN Cache VMDK size to $NestedESXiWLDCachingvDisk GB & Capacity VMDK size to $NestedESXiWLDCapacityvDisk GB ..."
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $NestedESXiWLDCachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $NestedESXiWLDCapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            Write-Logger "Updating vSAN Boot Disk size to $NestedESXiWLDBootDisk GB ..."
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 1" | Set-HardDisk -CapacityGB $NestedESXiWLDBootDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

            # vSAN ESA requires NVMe Controller
            if ($NestedESXiWLDVSANESA) {
                Write-Logger "Updating storage controller to NVMe for vSAN ESA ..."
                $devices = $vm.ExtensionData.Config.Hardware.Device

                $newControllerKey = -102

                # Reconfigure 1 - Add NVMe Controller & Update Disk Mapping to new controller
                $deviceChanges = @()
                $spec = New-Object VMware.Vim.VirtualMachineConfigSpec

                $scsiController = $devices | Where-Object { $_.getType().Name -eq "ParaVirtualSCSIController" }
                $scsiControllerDisks = $scsiController.device

                $nvmeControllerAddSpec = New-Object VMware.Vim.VirtualDeviceConfigSpec
                $nvmeControllerAddSpec.Device = New-Object VMware.Vim.VirtualNVMEController
                $nvmeControllerAddSpec.Device.Key = $newControllerKey
                $nvmeControllerAddSpec.Device.BusNumber = 0
                $nvmeControllerAddSpec.Operation = 'add'
                $deviceChanges += $nvmeControllerAddSpec

                foreach ($scsiControllerDisk in $scsiControllerDisks) {
                    $device = $devices | Where-Object { $_.key -eq $scsiControllerDisk }

                    $changeControllerSpec = New-Object VMware.Vim.VirtualDeviceConfigSpec
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
                $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
                $scsiControllerRemoveSpec = New-Object VMware.Vim.VirtualDeviceConfigSpec
                $scsiControllerRemoveSpec.Operation = 'remove'
                $scsiControllerRemoveSpec.Device = $scsiController
                $spec.deviceChange = $scsiControllerRemoveSpec

                $task = $vm.ExtensionData.ReconfigVM_Task($spec)
                $task1 = Get-Task -Id ("Task-$($task.value)")
                $task1 | Wait-Task | Out-Null
            }

            Write-Logger "Powering On $vmname ..."
            $vm | Start-Vm -RunAsync | Out-Null
        })
}

if ($deployCloudBuilder -eq 1) {
    $answer = ""
    $vm = Get-VM -Name $CloudbuilderVMHostname -Server $viConnection -Location $importLocation -ErrorAction SilentlyContinue

    $redeploy, $answer = Test-VMForReImport -Vm $vm -Answer $answer

    if ( $redeploy) { 
            
        $ovfconfig = Get-OvfConfiguration $CloudBuilderOVA

        $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
        $ovfconfig.NetworkMapping.$networkMapLabel.value = $VMNetwork
        $ovfconfig.common.guestinfo.hostname.value = $CloudbuilderFQDN
        $ovfconfig.common.guestinfo.ip0.value = $CloudbuilderIP
        $ovfconfig.common.guestinfo.netmask0.value = $VMNetmask
        $ovfconfig.common.guestinfo.gateway.value = $NestedESXiManagementNetwork_gateway
        $ovfconfig.common.guestinfo.DNS.value = $nameServers
        $ovfconfig.common.guestinfo.domain.value = $domain
        $ovfconfig.common.guestinfo.searchpath.value = $domain
        $ovfconfig.common.guestinfo.ntp.value = $ntpServers
        $ovfconfig.common.guestinfo.ADMIN_USERNAME.value = $CloudbuilderAdminUsername
        $ovfconfig.common.guestinfo.ADMIN_PASSWORD.value = $CloudbuilderAdminPassword
        $ovfconfig.common.guestinfo.ROOT_PASSWORD.value = $CloudbuilderRootPassword

        Write-Logger "Deploying Cloud Builder VM $CloudbuilderVMHostname ..."
        $vm = Import-VApp -Source $CloudBuilderOVA -OvfConfiguration $ovfconfig -Name $CloudbuilderVMHostname -Location $importLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

        Write-Logger "Powering On $CloudbuilderVMHostname ..."
        $vm | Start-Vm -RunAsync | Out-Null
    }
} 
<# 
if ($generateMgmJson -eq 1) {
    if ($SeparateNSXSwitch) { $useNSX = "false" } else { $useNSX = "true" }

    $esxivMotionNetwork = $NestedESXivMotionNetwork_subnet.split("/")[0]
    $esxivMotionNetworkOctects = $esxivMotionNetwork.split(".")
    $esxivMotionGateway = ($esxivMotionNetworkOctects[0..2] -join '.') + ".1"
    $NestedESXivMotionRangeStart = ($esxivMotionNetworkOctects[0..2] -join '.') + ".101"
    $NestedESXivMotionRangeEnd = ($esxivMotionNetworkOctects[0..2] -join '.') + ".118"

    $esxivSANNetwork = $NestedESXivSANNetworkCidr.split("/")[0]
    $esxivSANNetworkOctects = $esxivSANNetwork.split(".")
    $esxivSANGateway = ($esxivSANNetworkOctects[0..2] -join '.') + ".1"
    $esxivSANStart = ($esxivSANNetworkOctects[0..2] -join '.') + ".101"
    $esxivSANEnd = ($esxivSANNetworkOctects[0..2] -join '.') + ".118"

    $esxiNSXTepNetwork = $NestedESXiNSXTepNetworkCidr.split("/")[0]
    $esxiNSXTepNetworkOctects = $esxiNSXTepNetwork.split(".")
    $esxiNSXTepGateway = ($esxiNSXTepNetworkOctects[0..2] -join '.') + ".1"
    $esxiNSXTepStart = ($esxiNSXTepNetworkOctects[0..2] -join '.') + ".101"
    $esxiNSXTepEnd = ($esxiNSXTepNetworkOctects[0..2] -join '.') + ".118"

    $hostSpecs = @()
    $count = 1
    $NestedESXiHostnameToIPsForManagementDomain.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $VMName = $_.Key
        $VMIPAddress = $_.Value

        $hostSpec = [ordered]@{
            "association"      = "vcf-m01-dc01"
            "ipAddressPrivate" = [ordered]@{
                "ipAddress" = $VMIPAddress
                "cidr"      = $NestedESXiManagementNetwork_subnet
                "gateway"   = $NestedESXiManagementNetwork_gateway
            }
            "hostname"         = $VMName
            "credentials"      = [ordered]@{
                "username" = "root"
                "password" = $VMPassword
            }
            "sshThumbprint"    = "SHA256:DUMMY_VALUE"
            "sslThumbprint"    = "SHA25_DUMMY_VALUE"
            "vSwitch"          = "vSwitch0"
            "serverId"         = "host-$count"
        }
        $hostSpecs += $hostSpec
        $count++
    }

    $vcfConfig = [ordered]@{
        "skipEsxThumbprintValidation" = $true
        "managementPoolName"          = $VCFManagementDomainPoolName
        "sddcId"                      = "vcf-m01"
        "taskName"                    = "workflowconfig/workflowspec-ems.json"
        "esxLicense"                  = "$ESXILicense"
        "ceipEnabled"                 = $true
        "ntpServers"                  = @($ntpServers)
        "dnsSpec"                     = [ordered]@{
            "subdomain"  = $domain
            "domain"     = $domain
            "nameserver" = $nameServers
        }
        "sddcManagerSpec"             = [ordered]@{
            "ipAddress"             = $SddcManagerIP
            "netmask"               = $VMNetmask
            "hostname"              = $SddcManagerHostname
            "localUserPassword"     = "$SddcManagerLocalPassword"
            "vcenterId"             = "vcenter-1"
            "secondUserCredentials" = [ordered]@{
                "username" = "vcf"
                "password" = $SddcManagerVcfPassword
            }
            "rootUserCredentials"   = [ordered]@{
                "username" = "root"
                "password" = $SddcManagerRootPassword
            }
            "restApiCredentials"    = [ordered]@{
                "username" = "admin"
                "password" = $SddcManagerRestPassword
            }
        }
        "networkSpecs"                = @(
            [ordered]@{
                "networkType"    = "MANAGEMENT"
                "subnet"         = $NestedESXiManagementNetwork_subnet
                "gateway"        = $NestedESXiManagementNetwork_gateway
                "vlanId"         = $NestedESXiManagementNetwork_vLanId
                "mtu"            = $NestedESXivMotionNetwork_Mtu
                "portGroupKey"   = $NestedESXivMotionNetwork_portGroupKey
                "standbyUplinks" = @()
                "activeUplinks"  = @("uplink1", "uplink2")
            }
            [ordered]@{
                "networkType"            = "VMOTION"
                "subnet"                 = $NestedESXivMotionNetwork_subnet
                "gateway"                = $NestedESXivMotionNetwork_gateway
                "vlanId"                 = $NestedESXivMotionNetwork_vLanId
                "mtu"                    = $NestedESXivMotionNetwork_Mtu
                "portGroupKey"           = $NestedESXivMotionNetwork_portGroupKey
                "association"            = "vcf-m01-dc01"
                "includeIpAddressRanges" = @(@{"startIpAddress" = $NestedESXivMotionRangeStart; "endIpAddress" = $NestedESXivMotionRangeEnd })
                "standbyUplinks"         = @()
                "activeUplinks"          = @("uplink1", "uplink2")
            }
            [ordered]@{
                "networkType"            = "VSAN"
                "subnet"                 = $NestedESXivSanNetwork_subnet
                "gateway"                = $NestedESXivSanNetwork_gateway
                "vlanId"                 = $NestedESXivSanNetwork_vLanId
                "mtu"                    = $NestedESXivSanNetwork_Mtu
                "portGroupKey"           = $NestedESXivSanNetwork_portGroupKey
                "includeIpAddressRanges" = @(@{"startIpAddress" = $NestedESXivSanRangeStart; "endIpAddress" = $NestedESXivSanRangeEnd })
                "standbyUplinks"         = @()
                "activeUplinks"          = @("uplink1", "uplink2")
            }
        )
        "nsxtSpec"                    = [ordered]@{
            "nsxtManagerSize"                = "small"
            "nsxtManagers"                   = @(@{"hostname" = $NSXManagerNode1Hostname; "ip" = $NSXManagerNode1IP })
            "rootNsxtManagerPassword"        = $NSXRootPassword
            "nsxtAdminPassword"              = $NSXAdminPassword
            "nsxtAuditPassword"              = $NSXAuditPassword
            "rootLoginEnabledForNsxtManager" = $true
            "sshEnabledForNsxtManager"       = $true
            "overLayTransportZone"           = [ordered]@{
                "zoneName"    = "vcf-m01-tz-overlay01"
                "networkName" = "netName-overlay"
            }
            "vlanTransportZone"              = [ordered]@{
                "zoneName"    = "vcf-m01-tz-vlan01"
                "networkName" = "netName-vlan"
            }
            "vip"                            = $NSXManagerVIPIP
            "vipFqdn"                        = $NSXManagerVIPHostname
            "nsxtLicense"                    = $NSXLicense
            "transportVlanId"                = $NestedESXiNSXTepNetwork_vLanId
            "ipAddressPoolSpec"              = [ordered]@{
                "name"        = "vcf-m01-c101-tep01"
                "description" = "ESXi Host Overlay TEP IP Pool"
                "subnets"     = @(
                    @{
                        "ipAddressPoolRanges" = @(@{"start" = $esxiNSXTepStart; "end" = $esxiNSXTepEnd })
                        "cidr"                = $NestedESXiNSXTepNetworkCidr
                        "gateway"             = $esxiNSXTepGateway
                    }
                )
            }
        }
        "vsanSpec"                    = [ordered]@{
            "vsanName"      = "vsan-1"
            "vsanDedup"     = "false"
            "licenseFile"   = $VSANLicense
            "datastoreName" = "vcf-m01-cl01-ds-vsan01"
        }
        "dvSwitchVersion"             = "8.0.0"
        "dvsSpecs"                    = @(
            [ordered]@{
                "dvsName"      = "vcf-m01-cl01-vds01"
                "vcenterId"    = "vcenter-1"
                "vmnics"       = @("vmnic0", "vmnic1")
                "mtu"          = "9000"
                "networks"     = @(
                    "MANAGEMENT",
                    "VMOTION",
                    "VSAN"
                )
                "niocSpecs"    = @(
                    @{"trafficType" = "VSAN"; "value" = "HIGH" }
                    @{"trafficType" = "VMOTION"; "value" = "LOW" }
                    @{"trafficType" = "VDP"; "value" = "LOW" }
                    @{"trafficType" = "VIRTUALMACHINE"; "value" = "HIGH" }
                    @{"trafficType" = "MANAGEMENT"; "value" = "NORMAL" }
                    @{"trafficType" = "NFS"; "value" = "LOW" }
                    @{"trafficType" = "HBR"; "value" = "LOW" }
                    @{"trafficType" = "FAULTTOLERANCE"; "value" = "LOW" }
                    @{"trafficType" = "ISCSI"; "value" = "LOW" }
                )
                "isUsedByNsxt" = $useNSX
            }
        )
        "clusterSpec"                 = [ordered]@{
            "clusterName"         = "vcf-m01-cl01"
            "vcenterName"         = "vcenter-1"
            "clusterEvcMode"      = $ClusterEvcMode
            "vmFolders"           = [ordered] @{
                "MANAGEMENT" = "vcf-m01-fd-mgmt"
                "NETWORKING" = "vcf-m01-fd-nsx"
                "EDGENODES"  = "vcf-m01-fd-edge"
            }
            "clusterImageEnabled" = $EnableVCLM
        }
        "resourcePoolSpecs"           = @(
            [ordered]@{
                "name"                        = "vcf-m01-cl01-rp-sddc-mgmt"
                "type"                        = "management"
                "cpuReservationPercentage"    = 0
                "cpuLimit"                    = -1
                "cpuReservationExpandable"    = $true
                "cpuSharesLevel"              = "normal"
                "cpuSharesValue"              = 0
                "memoryReservationMb"         = 0
                "memoryLimit"                 = -1
                "memoryReservationExpandable" = $true
                "memorySharesLevel"           = "normal"
                "memorySharesValue"           = 0
            }
            [ordered]@{
                "name"                        = "vcf-m01-cl01-rp-sddc-edge"
                "type"                        = "network"
                "cpuReservationPercentage"    = 0
                "cpuLimit"                    = -1
                "cpuReservationExpandable"    = $true
                "cpuSharesLevel"              = "normal"
                "cpuSharesValue"              = 0
                "memoryReservationPercentage" = 0
                "memoryLimit"                 = -1
                "memoryReservationExpandable" = $true
                "memorySharesLevel"           = "normal"
                "memorySharesValue"           = 0
            }
            [ordered]@{
                "name"                        = "vcf-m01-cl01-rp-user-edge"
                "type"                        = "compute"
                "cpuReservationPercentage"    = 0
                "cpuLimit"                    = -1
                "cpuReservationExpandable"    = $true
                "cpuSharesLevel"              = "normal"
                "cpuSharesValue"              = 0
                "memoryReservationPercentage" = 0
                "memoryLimit"                 = -1
                "memoryReservationExpandable" = $true
                "memorySharesLevel"           = "normal"
                "memorySharesValue"           = 0
            }
            [ordered]@{
                "name"                        = "vcf-m01-cl01-rp-user-vm"
                "type"                        = "compute"
                "cpuReservationPercentage"    = 0
                "cpuLimit"                    = -1
                "cpuReservationExpandable"    = $true
                "cpuSharesLevel"              = "normal"
                "cpuSharesValue"              = 0
                "memoryReservationPercentage" = 0
                "memoryLimit"                 = -1
                "memoryReservationExpandable" = $true
                "memorySharesLevel"           = "normal"
                "memorySharesValue"           = 0
            }
        )
        "pscSpecs"                    = @(
            [ordered]@{
                "pscId"                = "psc-1"
                "vcenterId"            = "vcenter-1"
                "adminUserSsoPassword" = $VCSASSOPassword
                "pscSsoSpec"           = @{"ssoDomain" = "vsphere.local" }
            }
        )
        "vcenterSpec"                 = [ordered]@{
            "vcenterIp"           = $VCSAIP
            "vcenterHostname"     = $VCSAName
            "vcenterId"           = "vcenter-1"
            "licenseFile"         = $VCSALicense
            "vmSize"              = "tiny"
            "storageSize"         = ""
            "rootVcenterPassword" = $VCSARootPassword
        }
        "hostSpecs"                   = $hostSpecs
        "excludedComponents"          = @("NSX-V", "AVN", "EBGP")
    }

    if ($SeparateNSXSwitch) {
        $sepNsxSwitchSpec = [ordered]@{
            "dvsName"      = "vcf-m01-nsx-vds01"
            "vcenterId"    = "vcenter-1"
            "vmnics"       = @("vmnic2", "vmnic3")
            "mtu"          = 9000
            "networks"     = @()
            "isUsedByNsxt" = $true

        }
        $vcfConfig.dvsSpecs += $sepNsxSwitchSpec
    }

    # License Later feature only applicable for VCF 5.1.1 and later
    if ($VCFVersion -ge "5.1.1") {
        if ($VCSALicense -eq "" -and $ESXILicense -eq "" -and $VSANLicense -eq "" -and $NSXLicense -eq "") {
            $deployWithoutLicenseKeys = $true
        }
        else {
            $deployWithoutLicenseKeys = $false
        }
        $vcfConfig.add("deployWithoutLicenseKeys", $deployWithoutLicenseKeys)
    }

    Write-Logger "Generating Cloud Builder VCF Management Domain configuration deployment file $VCFManagementDomainJSONFile"
    $vcfConfig | ConvertTo-Json -Depth 20 | Out-File -LiteralPath $VCFManagementDomainJSONFile
}

if ($generateWldHostCommissionJson -eq 1) {
    Write-Logger "Generating Cloud Builder VCF Workload Domain Host Commission file $VCFWorkloadDomainUIJSONFile and $VCFWorkloadDomainAPIJSONFile for SDDC Manager UI and API"

    $commissionHostsUI = @()
    $commissionHostsAPI = @()
    $NestedESXiHostnameToIPsForWorkloadDomain.GetEnumerator() | Sort-Object -Property Value | Foreach-Object {
        $hostFQDN = $_.Key + "." + $domain

        $tmp1 = [ordered] @{
            "hostfqdn"        = $hostFQDN;
            "username"        = "root";
            "password"        = $VMPassword;
            "networkPoolName" = "$VCFManagementDomainPoolName";
            "storageType"     = "VSAN";
        }
        $commissionHostsUI += $tmp1

        $tmp2 = [ordered] @{
            "fqdn"          = $hostFQDN;
            "username"      = "root";
            "password"      = $VMPassword;
            "networkPoolId" = "TBD";
            "storageType"   = "VSAN";
        }
        $commissionHostsAPI += $tmp2
    }

    $vcfCommissionHostConfigUI = @{
        "hostsSpec" = $commissionHostsUI
    }

    $vcfCommissionHostConfigUI | ConvertTo-Json -Depth 2 | Out-File -LiteralPath $VCFWorkloadDomainUIJSONFile
    $commissionHostsAPI | ConvertTo-Json -Depth 2 | Out-File -LiteralPath $VCFWorkloadDomainAPIJSONFile
}
#>
if ($startVCFBringup -eq 1) {
    Write-Logger "Starting VCF Deployment Bringup ..."

    Write-Logger "Waiting for Cloud Builder to be ready ..."
    while (1) {
        $credentialsair = "${CloudbuilderAdminUsername}:${CloudbuilderAdminPassword}"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($credentialsair)
        $base64 = [System.Convert]::ToBase64String($bytes)

        try {
            if ($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri "https://$($CloudbuilderIP)/v1/sddcs" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers @{"Authorization" = "Basic $base64" }
            }
            else {
                $requests = Invoke-WebRequest -Uri "https://$($CloudbuilderIP)/v1/sddcs" -Method GET -TimeoutSec 5 -Headers @{"Authorization" = "Basic $base64" }
            }
            if ($requests.StatusCode -eq 200) {
                Write-Logger "Cloud Builder is now ready!"
                break
            }
        }
        catch {
            Write-Logger "Cloud Builder is not ready yet, sleeping for 120 seconds ..."
            Start-Sleep 120
        }
    }

    Write-Logger "Submitting VCF Bringup request ..."

    #$inputJson = Get-Content -Raw $VCFManagementDomainJSONFile
    $adminPwd = ConvertTo-SecureString $CloudbuilderAdminPassword -AsPlainText -Force
    $cred = New-Object Management.Automation.PSCredential ($CloudbuilderAdminUsername, $adminPwd)
    $bringupAPIParms = @{
        Uri         = "https://${CloudbuilderIP}/v1/sddcs"
        Method      = 'POST'
        Body        = $inputJson
        ContentType = 'application/json'
        Credential  = $cred
    }
    $bringupAPIReturn = Invoke-RestMethod @bringupAPIParms -SkipCertificateCheck
    Write-Logger "Open browser to the VMware Cloud Builder UI (https://${CloudbuilderFQDN}) to monitor deployment progress ..."
}

if ($startVCFBringup -eq 1 -and $uploadVCFNotifyScript -eq 1) {
    if (Test-Path $srcNotificationScript) {
        $cbVM = Get-VM -Server $viConnection $CloudbuilderFQDN

        Write-Logger "Uploading VCF notification script $srcNotificationScript to $dstNotificationScript on Cloud Builder appliance ..."
        Copy-VMGuestFile -Server $viConnection -VM $cbVM -Source $srcNotificationScript -Destination $dstNotificationScript -LocalToGuest -GuestUser "root" -GuestPassword $CloudbuilderRootPassword | Out-Null
        Invoke-VMScript -Server $viConnection -VM $cbVM -ScriptText "chmod +x $dstNotificationScript" -GuestUser "root" -GuestPassword $CloudbuilderRootPassword | Out-Null

        Write-Logger "Configuring crontab to run notification check script every 15 minutes ..."
        Invoke-VMScript -Server $viConnection -VM $cbVM -ScriptText "echo '*/15 * * * * $dstNotificationScript' > /var/spool/cron/root" -GuestUser "root" -GuestPassword $CloudbuilderRootPassword | Out-Null
    }
}

if ($deployNestedESXiVMsForMgmt -eq 1 -or $deployNestedESXiVMsForWLD -eq 1 -or $deployCloudBuilder -eq 1) {
    Write-Logger "Disconnecting from $VIServer ..."
    Disconnect-VIServer -Server $viConnection -Confirm:$false
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

Write-Logger "VCF Lab Deployment Complete!"
Write-Logger "StartTime: $StartTime"
Write-Logger "EndTime: $EndTime"
Write-Logger "Duration: $duration minutes to Deploy Nested ESXi, CloudBuilder & initiate VCF Bringup"
