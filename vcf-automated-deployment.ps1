param(
    [string]
    $ExcelFile = ".\vcf-ems-Deployment-Parameter11.xlsx",
    [string]
    $HCLJsonFile = "$PWD/nested-esxi-vsan-esa-hcl.json",
    [string]
    $VAppName,
    [switch]
    $UseSSH,
    [switch]
    $GenerateMgmJson
)
# Author: William Lam
# Website: www.williamlam.com
install-Module -Name "ImportExcel" -Scope CurrentUser
if ($UseSSH.isPresent) {
    install-module -Name "Posh-SSH"  -Scope CurrentUser
}
Import-Module -Name ./Utility.psm1



# Cloud Builder Configurations
$CloudbuilderVMHostname = "cloudbuilder"
$CloudbuilderFQDN = "cloudbuilder.vcf.lab.local"
$CloudbuilderIP = "192.168.10.195"
$CloudbuilderAdminUsername = "admin"
$CloudbuilderAdminPassword = "Pata2Pata1Pata!"
$CloudbuilderRootPassword = "Pata2Pata1Pata!"



# General Deployment Configuration for Nested ESXi & Cloud Builder VM
$VMDatacenter = "Datacenter"
$VMCluster = "Cluster01"
#$ClusterEvcMode = ""
$VMNetwork = "VLAN-10"
$ESXVMNetwork1 = "Trunk"
$ESXVMNetwork2 = "Trunk"
$VMDatastore = "vSanDatastore"
$VMFolder = "VCF"

 

# Nested ESXi VM Resources for Management Domain
$NestedESXiMGMTvCPU = "12"
$NestedESXiMGMTvMEM = "78" #GB
$NestedESXiMGMTCachingvDisk = "4" #GB
$NestedESXiMGMTCapacityvDisk = "500" #GB
#ESA disks
$NestedESXiESADisk1 = "500" #GB
$NestedESXiESADisk2 = "500" #GB 
$NestedESXiMGMTBootDisk = "32" #GB

 


  
if ([string]::IsNullOrEmpty( $VAppName) ) {
    $random_string = -join ((65..90) + (97..122) | Get-Random -Count 8 | % { [char]$_ })
    $VAppName = "Nested-VCF-Lab-$random_string"
}
$verboseLogFile = "$VAppName-deployment.log"

 




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

 

# vCenter Server used to deploy VMware Cloud Foundation Lab
$VIServer = "vmw-vc01.lab.local"
$VIUsername = "administrator@vsphere.local"
$VIPassword = "Pata2Pata1!"

# Full Path to both the Nested ESXi & Cloud Builder OVA
$NestedESXiApplianceOVA = "./ova/Nested_ESXi8.0u3_Appliance_Template_v1.ova"
$CloudBuilderOVA = "./ova/VMware-Cloud-Builder-5.2.0.0-24108943_OVF10.ova"

# VCF Licenses or leave blank for evaluation mode (requires VCF 5.1.1 or later)

$confirmDeployment = 1
$deployNestedESXiVMsForMgmt = 1
$deployNestedESXiVMsForWLD = 0
$deployCloudBuilder = 1
$moveVMsIntovApp = 1 
$startVCFBringup = 1
$generateWldHostCommissionJson = 0
$uploadVCFNotifyScript = 0

$srcNotificationScript = "vcf-bringup-notification.sh"
$dstNotificationScript = "/root/vcf-bringup-notification.sh"

$StartTime = Get-Date
 
 
 
 
 
        
$inputData = [ordered]@{
    SiteCode                 = 'sfo-m01'
    DeployWithoutLicenseKeys = $licenseImport[0].P2 -eq 'No' #License Now

    Management               = [ordered]@{
        Datacenter = $r[18].P2 #Datacenter Name
        PoolName   = $r[37].P2 #Network Pool Name
    }
    # SDDC Manager Configuration
    SddcManager              = [ordered]@{ 
        Hostname = [ordered]@{ 
            VcfPassword   = $credentialsImport[15].P2 #SDDC Manager Super User *
            RootPassword  = $credentialsImport[14].P2 #SDDC Manager Appliance Root Account *
            LocalPassword = $credentialsImport[16].P2 #SDDC Manager Local Account
            Ip            = $r[36].P2
            Hostname      = $r[35].P2
        }
    }
 
    VCenter                  = [ordered]@{
        Ip        = $r[13].P3
        Hostname  = $r[13].P2   
        License   = $licenseImport[3].P2      
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

    Cluster                  = [ordered]@{
        Name         = $r[19].P2        
        EvcMode      = ""#$r[21].P2
        ImageEnabled = $r[20].P2 -eq 'yes'
    }

    NestedESXi               = [ordered]@{
        Password                         = $credentialsImport[5].P2
        HostnameToIPsForManagementDomain = [ordered]@{
            $esxImport[0].P1 = $esxImport[1].P1
            $esxImport[0].P2 = $esxImport[1].P2
            $esxImport[0].P3 = $esxImport[1].P3
            $esxImport[0].P4 = $esxImport[1].P4
        }
         
    }
    NetworkSpecs             = [ordered]@{
        dnsSpec           = [ordered]@{
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
            vLanId                            = "$($mgmtNetworkImport[1].P2)"
            Mtu                               = "$($mgmtNetworkImport[1].P6)"
            portGroupKey                      = $mgmtNetworkImport[1].P3
            gateway                           = $mgmtNetworkImport[1].P5
        }
        vMotionNetwork    = [ordered]@{
            subnet       = $mgmtNetworkImport[2].P4
            vLanId       = "$($mgmtNetworkImport[2].P2)"
            Mtu          = "$($mgmtNetworkImport[2].P6)"
            portGroupKey = $mgmtNetworkImport[2].P3
            gateway      = $mgmtNetworkImport[2].P5

            Range        = [ordered]@{ 
                Start = $rangeImport[0].p2
                End   = $rangeImport[0].p4
            }
        }
        vSan              = [ordered]@{
            subnet       = $mgmtNetworkImport[3].P4
            vLanId       = "$($mgmtNetworkImport[3].P2)"
            Mtu          = "$($mgmtNetworkImport[3].P6)"
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
            vlanId       = "$($mgmtNetworkImport[0].P2)"
            mtu          = "$($mgmtNetworkImport[0].P6)"
            portGroupKey = $mgmtNetworkImport[0].P3
        }
    }

    Nsxt                     = @{
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
        License           = $licenseImport[4].P2
        TransportVlanId   = "$($overlayImport[0].P2)"
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
    vSan                     = @{
        ESA           = ($r2[16].P2 -ieq 'yes')
        LicenseFile   = $licenseImport[2].P2  
        HclFile       = ($r2[17].P2 )?$r2[17].P2 :""
        DatastoreName = $r2[14].P2
        Dedup         = ($r2[15].P2 -ieq 'yes')
    }
} 

$VMNetmask = ConvertTo-Netmask -NetworkCIDR $inputData.NetworkSpecs.ManagementNetwork.subnet
 
 

$skipEsxThumbprintValidation = $thumbprintImport[0].P3 -eq 'No'

$hostSpecs = @()
$i = 3
foreach ($key in $inputData.NestedESXi.HostnameToIPsForManagementDomain.Keys ) {
    $h = [ordered]@{
        association      = $inputData.Management.Datacenter
        ipAddressPrivate = [ordered]@{
            ipAddress = $inputData.NestedESXi.HostnameToIPsForManagementDomain[$key]
            cidr      = $inputData.NetworkSpecs.ManagementNetwork.subnet
            gateway   = $inputData.NetworkSpecs.ManagementNetwork.gateway
        }
        hostname         = $key
        credentials      = [ordered]@{
            username = "root"
            password = $inputData.NestedESXi.Password
        } 

        vSwitch          = "vSwitch0"
        serverId         = "host-$($i-2)"
    }
    if (!$skipEsxThumbprintValidation) {
        $h['sshThumbprint'] = ($null -eq $thumbprintImport[3].P2 )?"SHA256:DUMMY_VALUE":$thumbprintImport[$i].P2  
        $h['sslThumbprint'] = ($null -eq $thumbprintImport[3].P4)?"SHA25_DUMMY_VALUE": $thumbprintImport[$i].P4
    }

    $hostSpecs += $h
    $i++
}
 
 
 

 

# VCF Configurations
$VCFManagementDomainPoolName = "vcf-m01-rp01"
$VCFManagementDomainJSONFile = "vcf-mgmt.json"
$VCFWorkloadDomainUIJSONFile = "vcf-commission-host-ui.json"
$VCFWorkloadDomainAPIJSONFile = "vcf-commission-host-api.json"

$orderedHashTable = [ordered]@{
    deployWithoutLicenseKeys    = $inputData.deployWithoutLicenseKeys
    skipEsxThumbprintValidation = $skipEsxThumbprintValidation
    managementPoolName          = $inputData.Management.PoolName
    sddcManagerSpec             = [ordered]@{
        secondUserCredentials = [ordered]@{
            username = "vcf"
            password = $inputData.SddcManager.Hostname.VcfPassword
        }        
        ipAddress             = $inputData.SddcManager.Hostname.Ip
        hostname              = $inputData.SddcManager.Hostname.Hostname
        rootUserCredentials   = [ordered]@{
            username = 'root'
            password = $inputData.SddcManager.Hostname.RootPassword
        }
        localUserPassword     = $inputData.SddcManager.Hostname.LocalPassword        
    }
    sddcId                      = $r[38].P2
    esxLicense                  = $licenseImport[1].P2
    workflowType                = "VCF"
    ceipEnabled                 = ($r2[5].P3 -ieq 'yes')
    fipsEnabled                 = ($r2[6].P3 -ieq 'yes')
    ntpServers                  = $inputdata.NetworkSpecs.NtpServers
    dnsSpec                     = $inputData.NetworkSpecs.DnsSpec 
    networkSpecs                = @(
        [ordered]@{
            networkType  = "MANAGEMENT"
            subnet       = $inputData.NetworkSpecs.ManagementNetwork.subnet
            gateway      = $inputData.NetworkSpecs.ManagementNetwork.gateway
            vlanId       = $inputData.NetworkSpecs.ManagementNetwork.vLanId
            mtu          = $inputData.NetworkSpecs.ManagementNetwork.Mtu
            portGroupKey = $inputData.NetworkSpecs.ManagementNetwork.portGroupKey    
        }
        [ordered]@{
            networkType            = "VMOTION"
            subnet                 = $inputData.NetworkSpecs.vMotionNetwork.subnet
            gateway                = $inputData.NetworkSpecs.vMotionNetwork.gateway
            vlanId                 = $inputData.NetworkSpecs.vMotionNetwork.vLanId
            mtu                    = $inputData.NetworkSpecs.vMotionNetwork.Mtu
            portGroupKey           = $inputData.NetworkSpecs.vMotionNetwork.portGroupKey
            includeIpAddressRanges = @(
                [ordered]@{
                    endIpAddress   = $inputData.NetworkSpecs.vMotionNetwork.Range.End
                    startIpAddress = $inputData.NetworkSpecs.vMotionNetwork.Range.Start
                }
            )
        }
        [ordered]@{
            networkType            = "VSAN"
            subnet                 = $inputData.NetworkSpecs.vSan.subnet
            gateway                = $inputData.NetworkSpecs.vSan.gateway
            vlanId                 = $inputData.NetworkSpecs.vSan.vLanId
            mtu                    = $inputData.NetworkSpecs.vSan.Mtu
            portGroupKey           = $inputData.NetworkSpecs.vSan.portGroupKey
            includeIpAddressRanges = @(
                [ordered]@{
                    endIpAddress   = $inputData.NetworkSpecs.vSan.Range.Start
                    startIpAddress = $inputData.NetworkSpecs.vSan.Range.End
                }
            )
        }
        [ordered]@{
            networkType  = "VM_MANAGEMENT"
            subnet       = $inputData.NetworkSpecs.VmManamegent.subnet
            gateway      = $inputData.NetworkSpecs.VmManamegent.gateway
            vlanId       = $inputData.NetworkSpecs.VmManamegent.vlanId
            mtu          = $inputData.NetworkSpecs.VmManamegent.mtu
            portGroupKey = $inputData.NetworkSpecs.VmManamegent.portGroupKey 
        }
    )
    nsxtSpec                    = [ordered]@{
        nsxtManagerSize         = $inputdata.Nsxt.ManagerSize
        nsxtManagers            = $inputdata.Nsxt.Managers
        rootNsxtManagerPassword = $inputdata.Nsxt.Password.Root
        nsxtAdminPassword       = $inputdata.Nsxt.Password.Admin
        nsxtAuditPassword       = $inputdata.Nsxt.Password.Audit
        vip                     = $inputdata.Nsxt.vip
        vipFqdn                 = $inputdata.Nsxt.vipFqdn
        nsxtLicense             = $inputdata.Nsxt.License
        transportVlanId         = $inputdata.Nsxt.TransportVlanId
        ipAddressPoolSpec       = $inputdata.Nsxt.ipAddressPoolSpec
    }
    vsanSpec                    = [ordered]@{
        licenseFile   = $inputdata.vSan.LicenseFile
        vsanDedup     = (($inputdata.vSan.ESA)? $false : ($inputdata.vSan.Dedup))
        esaConfig     = [ordered]@{
            enabled = $inputdata.vSan.ESA
        }
        hclFile       = $inputdata.vSan.HclFile 
        datastoreName = $inputdata.vSan.DatastoreName
    }

    resourcePoolSpecs           = @( 
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
    )
    dvsSpecs                    = @(
        [ordered]@{
            dvsName          = $dsImport[1].P2
            vmnics           = @($dsImport[2].p2 -split ',')
            mtu              = "$($dsImport[3].P2)"
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
                transportZones = get-TransportZone -Type $inputdata.Nsxt.TransportType -SiteCode $inputdata.SiteCode
            }
        }
    )
    clusterSpec                 = [ordered]@{
        clusterName         = $inputdata.Cluster.Name     
        clusterEvcMode      = $inputdata.Cluster.EvcMode
        clusterImageEnabled = $inputdata.Cluster.ImageEnabled
        vmFolders           = [ordered]@{
            MANAGEMENT = "$($inputdata.SiteCode)-fd-mgmt"
            NETWORKING = "$($inputdata.SiteCode)-fd-nsx"
            EDGENODES  = "$($inputdata.SiteCode)-fd-edge"
        } 
    }
    pscSpecs                    = @(
        [ordered]@{
            adminUserSsoPassword = $inputdata.VCenter.Password.Admin
            pscSsoSpec           = [ordered]@{
                ssoDomain = $inputdata.VCenter.SsoDomain 
            }
        }
    )
    vcenterSpec                 = [ordered]@{
        vcenterIp           = $inputdata.VCenter.Ip 
        vcenterHostname     = $inputdata.VCenter.Hostname 
        licenseFile         = $inputdata.VCenter.License     
        vmSize              = $inputdata.VCenter.Size.Vm  
        storageSize         = $inputdata.VCenter.Size.Storage  
        rootVcenterPassword = $inputdata.VCenter.Password.Root
    }
    hostSpecs                   = $hostSpecs
}





 
 
 

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
        Write-Host -ForegroundColor White $inputData.NestedESXi.HostnameToIPsForManagementDomain.count
        Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
        Write-Host -ForegroundColor White $inputData.NestedESXi.HostnameToIPsForManagementDomain.Values
        Write-Host -NoNewline -ForegroundColor Green "vCPU: "
        Write-Host -ForegroundColor White $NestedESXiMGMTvCPU
        Write-Host -NoNewline -ForegroundColor Green "vMEM: "
        Write-Host -ForegroundColor White "$NestedESXiMGMTvMEM GB"
        if ($inputdata.vSan.ESA) {
            Write-Host -NoNewline -ForegroundColor Green "Disk Objeck 1 VMDK: "
            Write-Host -ForegroundColor White "$NestedESXiESADisk1 GB"
            Write-Host -NoNewline -ForegroundColor Green "Disk Objeck 2 VMDK: "
            Write-Host -ForegroundColor White "$NestedESXiESADisk2 GB"
        }
        else {
            Write-Host -NoNewline -ForegroundColor Green "Caching VMDK: "
            Write-Host -ForegroundColor White "$NestedESXiMGMTCachingvDisk GB"
            Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
            Write-Host -ForegroundColor White "$NestedESXiMGMTCapacityvDisk GB"
        }
    }

    

    Write-Host -NoNewline -ForegroundColor Green "`nNetmask "
    Write-Host -ForegroundColor White $VMNetmask
    Write-Host -NoNewline -ForegroundColor Green "Gateway: "
    Write-Host -ForegroundColor White $inputData.NetworkSpecs.ManagementNetwork.gateway
    Write-Host -NoNewline -ForegroundColor Green "DNS: "
    Write-Host -ForegroundColor White $inputData.NetworkSpecs.DnsSpec.NameServers
    Write-Host -NoNewline -ForegroundColor Green "NTP: "
    Write-Host -ForegroundColor White $inputdata.NetworkSpecs.NtpServers
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
    $inputData.NestedESXi.HostnameToIPsForManagementDomain.GetEnumerator().foreach({ 
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
            $ovfconfig.common.guestinfo.hostname.value = "$VMName.$($inputData.NetworkSpecs.DnsSpec.Domain)"
            $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
            $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
            $ovfconfig.common.guestinfo.gateway.value = $inputData.NetworkSpecs.ManagementNetwork.gateway
            $ovfconfig.common.guestinfo.dns.value = $inputData.NetworkSpecs.DnsSpec.NameServers
            $ovfconfig.common.guestinfo.domain.value = $inputData.NetworkSpecs.DnsSpec.Domain
            $ovfconfig.common.guestinfo.ntp.value = $inputdata.NetworkSpecs.NtpServers -join ","
            $ovfconfig.common.guestinfo.syslog.value = $VMSyslog
            $ovfconfig.common.guestinfo.password.value = $inputData.NestedESXi.Password
            $ovfconfig.common.guestinfo.vlan.value = $inputData.NetworkSpecs.ManagementNetwork.vLanId
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

           

            Write-Logger "Updating vSAN Boot Disk size to $NestedESXiMGMTBootDisk GB ..."
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 1" | Set-HardDisk -CapacityGB $NestedESXiMGMTBootDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            # vSAN ESA requires NVMe Controller
            if ($inputdata.vSan.ESA) {

                Write-Logger "Updating vSAN Disk Capacity VMDK size to $NestedESXiESADisk1 GB  and $NestedESXiESADisk2 GB .."
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $NestedESXiESADisk1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $NestedESXiESADisk2 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

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
                Write-Logger "Updating vSAN Cache VMDK size to $NestedESXiMGMTCachingvDisk GB & Capacity VMDK size to $NestedESXiMGMTCapacityvDisk GB ..."
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $NestedESXiMGMTCachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $NestedESXiMGMTCapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
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
        $ovfconfig.common.guestinfo.gateway.value = $inputData.NetworkSpecs.ManagementNetwork.gateway
        $ovfconfig.common.guestinfo.DNS.value = $inputData.NetworkSpecs.DnsSpec.NameServers
        $ovfconfig.common.guestinfo.domain.value = $inputData.NetworkSpecs.DnsSpec.Domain
        $ovfconfig.common.guestinfo.searchpath.value = $inputData.NetworkSpecs.DnsSpec.Domain
        $ovfconfig.common.guestinfo.ntp.value = $inputdata.NetworkSpecs.NtpServers -join ","
        $ovfconfig.common.guestinfo.ADMIN_USERNAME.value = $CloudbuilderAdminUsername
        $ovfconfig.common.guestinfo.ADMIN_PASSWORD.value = $CloudbuilderAdminPassword
        $ovfconfig.common.guestinfo.ROOT_PASSWORD.value = $CloudbuilderRootPassword

        Write-Logger "Deploying Cloud Builder VM $CloudbuilderVMHostname ..."
        $CloudbuilderVM = Import-VApp -Source $CloudBuilderOVA -OvfConfiguration $ovfconfig -Name $CloudbuilderVMHostname -Location $importLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin

        Write-Logger "Powering On $CloudbuilderVMHostname ..."
        $CloudbuilderVM | Start-Vm -RunAsync | Out-Null
    }
}
  

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
            Write-Logger "Cloud Builder is not ready yet, sleeping for 30 seconds ..."
            Start-Sleep 30
        }
    }
    $adminPwd = ConvertTo-SecureString $CloudbuilderAdminPassword -AsPlainText -Force
    $cred = [Management.Automation.PSCredential]::new($CloudbuilderAdminUsername, $adminPwd)

    if ($inputdata.vSan.HclFile) {
        Start-Sleep 10
        if ($UseSSH.isPresent) {
            $hclFiledest = Split-Path -Path $inputdata.vSan.HclFile
            Write-Logger "SCP HCL ($HCLJsonFile) file to $inputdata.vSan.HclFile ..."
            Set-SCPItem -ComputerName $CloudbuilderIP -Credential $cred -Path $HCLJsonFile -Destination $hclFiledest -AcceptKey
        }
        Write-Logger "Copy-VMGuestFile HCL ($HCLJsonFile) file to $inputdata.vSan.HclFile ..."
        Copy-VMGuestFile -Source $HCLJsonFile -Destination $inputdata.vSan.HclFile -GuestCredential $cred -VM $CloudbuilderVM -LocalToGuest 
    }
    Write-Logger "Submitting VCF Bringup request ..."

    $inputJson = $orderedHashTable | convertto-json  -Depth 10 #Get-Content -Raw $VCFManagementDomainJSONFile

    if ($GenerateMgmJson.isPresent) {
        $inputJson | out-file "$VAppName.json"
    }

    $bringupAPIParms = @{
        Uri         = "https://${CloudbuilderIP}/v1/sddcs"
        Method      = 'POST'
        Body        = $inputJson
        ContentType = 'application/json'
        Credential  = $cred
    }
    Start-Sleep 10
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

if ($deployNestedESXiVMsForMgmt -eq 1 -or $deployCloudBuilder -eq 1) {
    Write-Logger "Disconnecting from $VIServer ..."
    Disconnect-VIServer -Server $viConnection -Confirm:$false
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

Write-Logger "VCF Lab Deployment Complete!"
Write-Logger "StartTime: $StartTime"
Write-Logger "EndTime: $EndTime"
Write-Logger "Duration: $duration minutes to Deploy Nested ESXi, CloudBuilder & initiate VCF Bringup"
