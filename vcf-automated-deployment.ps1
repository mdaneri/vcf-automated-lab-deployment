[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium", DefaultParameterSetName = 'Psd1File')]
[CmdletBinding(DefaultParameterSetName = 'UsernamePassword')] 
param(
    # Parameter set for using VIUsername and VIPassword
    [Parameter(ParameterSetName = 'UsernamePassword', Mandatory = $false)]
    [string]$VIUsername = 'administrator@vsphere.local',

    [Parameter(ParameterSetName = 'UsernamePassword', Mandatory = $false, ValueFromPipeline = $true )]
    [SecureString]$VIPassword,

    # Alternative parameter set using PSCredential
    [Parameter(ParameterSetName = 'Credential', Mandatory = $true)]
    [PSCredential]$VICredential,

    # ConfigurationFile applicable to both UsernamePassword and Credential sets
    [Parameter(ParameterSetName = 'UsernamePassword', Mandatory = $false)]
    [Parameter(ParameterSetName = 'Credential', Mandatory = $false)]
    [string]$ConfigurationFile,

    [string]
    $HCLJsonFile = "$PWD/nested-esxi-vsan-esa-hcl.json",
    
    [string]
    $VAppName,
    
    [switch]
    $UseSSH,
    
    [switch]
    $GenerateJson,
    
    [switch]
    $GeneratePsd1,
    
    [switch]
    $VCFBringup,
    
    [switch]
    $NoVapp,

    [string]
    $VIServer = "vmw-vc01.lab.local",

    [switch]   
    $NoCloudBuilderDeploy,

    [switch]
    $NoNestedMgmtEsx,

    [switch]
    $NestedWldEsx,
    
    [string]
    $EsxOVA,

    [string]
    $CloudBuilderOVA  
)

if ($ExcelFile) {
    install-Module -Name "ImportExcel" -Scope CurrentUser
}
if ($UseSSH) {
    install-module -Name "Posh-SSH"  -Scope CurrentUser
}
Import-Module -Name ./Utility.psm1

#if ([string]::IsNullOrEmpty( $VAppName) ) {
#$random_string = -join ((65..90) + (97..122) | Get-Random -Count 8 | % { [char]$_ })
# $VAppName = "Nested-VCF-Lab-$random_string"
#}
$script:verboseLogFile = "$VAppName-deployment.log"

 


 


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

 

# VCF Licenses or leave blank for evaluation mode (requires VCF 5.1.1 or later)

  
$uploadVCFNotifyScript = 0

$srcNotificationScript = "vcf-bringup-notification.sh"
$dstNotificationScript = "/root/vcf-bringup-notification.sh"

$StartTime = Get-Date
 
if ($ConfigurationFile) {
    if (Test-Path $ConfigurationFile) {
        switch ( [System.IO.Path]::GetExtension($ConfigurationFile)) {
            '.psd1' {
                $FileContent = Get-Content -Path $ConfigurationFile -Raw
                # Use Invoke-Expression to evaluate the content as a hashtable
                try {
                    $inputData = Invoke-Expression $FileContent
                }
                catch {
                    Write-Error "Failed to load configuration data: $_"
                }
            }
            '.xlsx' {
                $inputData = Import-ExcelVCFData -Path $ConfigurationFile 
            }
            '.json' {
                $inputData = Import-ExcelVCFData -Path $ConfigurationFile 
            }
        }
    }
    else {
        Write-Host -ForegroundColor Red "`nThe file '$ConfigurationFile' does not exist ...`n"
        exit 1
    }

    if ($null -eq $inputData ) {
        Write-Host -ForegroundColor Red "`n'$ConfigurationFile' return an enpty configuration ...`n"
        exit 1
    }
}

$VMNetmask = ConvertTo-Netmask -NetworkCIDR $inputData.NetworkSpecs.ManagementNetwork.subnet

# Detect VCF version based on Cloud Builder OVA (support is 5.1.0+)
if ($inputData.VirtualDeployment.CloudBuilder.Ova -match "5.2.0") {
    $VCFVersion = "5.2.0"
}
elseif ($inputData.VirtualDeployment.CloudBuilder.Ova -match "5.1.1") {
    $VCFVersion = "5.1.1"
}
elseif ($inputData.VirtualDeployment.CloudBuilder.Ova -match "5.1.0") {
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
    if ( $inputData.VirtualDeployment.Cloudbuilder.AdminPassword.ToCharArray().count -lt 15 -or $inputData.VirtualDeployment.Cloudbuilder.RootPassword.ToCharArray().count -lt 15) {
        Write-Host -ForegroundColor Red "`nCloud Builder passwords must be 15 characters or longer ...`n"
        exit
    }
}

if (!(Test-Path $inputData.VirtualDeployment.Esx.Ova)) {
    Write-Host -ForegroundColor Red "`nUnable to find $($inputData.VirtualDeployment.Esx.Ova) ...`n"
    exit
}

if (!(Test-Path $inputData.VirtualDeployment.CloudBuilder.Ova)) {
    Write-Host -ForegroundColor Red "`nUnable to find $($inputData.VirtualDeployment.CloudBuilder.Ova) ...`n"
    exit
}

if ($PSVersionTable.PSEdition -ne "Core") {
    Write-Host -ForegroundColor Red "`tPowerShell Core was not detected, please install that before continuing ... `n"
    exit
} 

if ($PSCmdlet.ShouldProcess($VIServer, "Deploy VCF")) { 
    Write-Host -ForegroundColor Magenta "`nPlease confirm the following configuration will be deployed:`n"

    Write-Host -ForegroundColor Yellow "---- VCF Automated Lab Deployment Configuration ---- "
    Write-Host -NoNewline -ForegroundColor Green "VMware Cloud Foundation Version: "
    Write-Host -ForegroundColor White $VCFVersion
    Write-Host -NoNewline -ForegroundColor Green "Nested ESXi Image Path: "
    Write-Host -ForegroundColor White $inputData.VirtualDeployment.Esx.Ova
    Write-Host -NoNewline -ForegroundColor Green "Cloud Builder Image Path: "
    Write-Host -ForegroundColor White $inputData.VirtualDeployment.CloudBuilder.Ova

    if (-not ($VCFBringup -or $NoCloudBuilderDeploy -or $NoNestedMgmtEsx -or $NestedWldEsx) ) {
        Write-Host -NoNewline -ForegroundColor Magenta "`nDo you want deploy VMware Cloud Foundation ? "
        do {
            $readAnswer = Read-Host -Prompt "[Y]es/[N]o"
        }until ( 'y', 'n' -contains $readAnswer )
        $VCFBringup = $readAnswer -eq 'y' 

        Write-Host -NoNewline -ForegroundColor Magenta "`nDo you want import the VMware CloudBuilder ? "
        do {
            $readAnswer = Read-Host -Prompt "[Y]es/[N]o"
        }until ( 'y', 'n' -contains $readAnswer )
        $NoCloudBuilderDeploy = $readAnswer -eq 'n' 

        Write-Host -NoNewline -ForegroundColor Magenta "`nDo you want create the Management VMware ESX virtual hosts ? "
        do {
            $readAnswer = Read-Host -Prompt "[Y]es/[N]o"
        }until ( 'y', 'n' -contains $readAnswer )
        $NoNestedMgmtEsx = $readAnswer -eq 'n' 

        Write-Host  -NoNewline -ForegroundColor Magenta "`nDo you want import the Workload Vmware ESX virtual hosts ? "
        do {
            $readAnswer = Read-Host -Prompt "[Y]es/[N]o"
        }until ( 'y', 'n' -contains $readAnswer )
        $NestedWldEsx = $readAnswer -eq 'y' 
    }

    if ( (-not $NoVapp) -and ((-not $NoCloudBuilderDeploy) -or (-not $NoNestedMgmtEsx) -or $NestedWldEsx)) {
        while ( [string]::IsNullOrEmpty($VAppName)) {
            Write-Host -NoNewline -ForegroundColor Magenta "`nPlease specify the vApp name : "
            $VAppName = Read-Host  
        }
    }
    $exportFileName = $VAppName 
    if ([string]::IsNullOrEmpty($exportFileName) -and ($GeneratePsd1 -or $GenerateJson)) {
        while ( [string]::IsNullOrEmpty($exportFileName)) {
            Write-Host -NoNewline -ForegroundColor Magenta "`nPlease specify the filename for the exported configuration : "
            $exportFileName = Read-Host  
        }
    }

    if ($GenerateJson) { 
        Write-Logger "Export the JSON workload to the file '$exportFileName.json'."
    }
     
    if ($GeneratePsd1) {
        Write-Logger "Export the Configuration to the file '$exportFileName.psd1'."
    }

    if ($VCFBringup) {
        Write-Host -ForegroundColor Yellow "`n---- vCenter Server Deployment Target Configuration ----"
        Write-Host -NoNewline -ForegroundColor Green "vCenter Server Address: "
        Write-Host -ForegroundColor White $VIServer
        Write-Host -NoNewline -ForegroundColor Green "VM Network: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Cloudbuilder.PortGroup

        Write-Host -NoNewline -ForegroundColor Green "ESX VM Network 1: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.ESX.VMNetwork1

        Write-Host -NoNewline -ForegroundColor Green "ESX VM Network 2: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.ESX.VMNetwork2

        Write-Host -NoNewline -ForegroundColor Green "VM Storage: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.VMDatastore
        Write-Host -NoNewline -ForegroundColor Green "VM Cluster: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.VMCluster
        Write-Host -NoNewline -ForegroundColor Green "VM Folder: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.VMFolder
    }
    
    if ((-not $NoCloudBuilderDeploy) -or (-not $NoNestedMgmtEsx) -or $NestedWldEsx) {
        Write-Host -NoNewline -ForegroundColor Green "VM vApp: "
        Write-Host -ForegroundColor White $VAppName
    }
    
    if (-not $NoCloudBuilderDeploy) {
        Write-Host -ForegroundColor Yellow "`n---- Cloud Builder Configuration ----"
        Write-Host -NoNewline -ForegroundColor Green "VM Name: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Cloudbuilder.VMName
        Write-Host -NoNewline -ForegroundColor Green "Hostname: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Cloudbuilder.Hostname
        Write-Host -NoNewline -ForegroundColor Green "IP Address: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Cloudbuilder.Ip
        Write-Host -NoNewline -ForegroundColor Green "PortGroup: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Cloudbuilder.PortGroup
    }

    if (-not $NoNestedMgmtEsx) {
        Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration for VCF Management Domain ----"
        Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Esx.Hosts.count
        Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
        Write-Host -ForegroundColor White ($inputData.VirtualDeployment.Esx.Hosts.Ip -join ', ')
        Write-Host -NoNewline -ForegroundColor Green "vCPU: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Esx.vCPU
        Write-Host -NoNewline -ForegroundColor Green "vMEM: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.vMemory) GB"
        Write-Host -NoNewline -ForegroundColor Green "Boot Disk VMDK: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.BootDisk) GB"
        if ($inputdata.vSan.ESA) {
            Write-Host -NoNewline -ForegroundColor Green "Disk Objeck 1 VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.ESADisk1) GB"
            Write-Host -NoNewline -ForegroundColor Green "Disk Objeck 2 VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.ESADisk2) GB"
        }
        else {
            Write-Host -NoNewline -ForegroundColor Green "Caching VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.CachingvDisk) GB"
            Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.CapacityvDisk) GB"
        }
        Write-Host -NoNewline -ForegroundColor Green "Network Pool 1: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.VMNetwork1)"
        Write-Host -NoNewline -ForegroundColor Green "Network Pool 2: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.VMNetwork2)"
        Write-Host -NoNewline -ForegroundColor Green "Netmask "
        Write-Host -ForegroundColor White $VMNetmask
        Write-Host -NoNewline -ForegroundColor Green "Gateway: "
        Write-Host -ForegroundColor White $inputData.NetworkSpecs.ManagementNetwork.gateway
        Write-Host -NoNewline -ForegroundColor Green "DNS: "
        Write-Host -ForegroundColor White $inputData.NetworkSpecs.DnsSpec.NameServers
        Write-Host -NoNewline -ForegroundColor Green "NTP: "
        Write-Host -ForegroundColor White $inputdata.NetworkSpecs.NtpServers
        Write-Host -NoNewline -ForegroundColor Green "Syslog: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Syslog
    }


    if ($NestedWldEsx) {
        Write-Host -ForegroundColor Yellow "`n---- vESXi Configuration for VCF Workload Domain ----"
        Write-Host -NoNewline -ForegroundColor Green "# of Nested ESXi VMs: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.WldEsx.Hosts.count
        Write-Host -NoNewline -ForegroundColor Green "IP Address(s): "
        Write-Host -ForegroundColor White ($inputData.VirtualDeployment.WldEsx.Hosts.Ip -join ', ')
        Write-Host -NoNewline -ForegroundColor Green "vCPU: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.WldEsx.vCPU
        Write-Host -NoNewline -ForegroundColor Green "vMEM: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.vMemory) GB"
        Write-Host -NoNewline -ForegroundColor Green "Boot Disk VMDK: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.BootDisk) GB"
        if ($inputdata.vSan.ESA) {
            Write-Host -NoNewline -ForegroundColor Green "Disk Objeck 1 VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.ESADisk1) GB"
            Write-Host -NoNewline -ForegroundColor Green "Disk Objeck 2 VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.ESADisk2) GB"
        }
        else {
            Write-Host -NoNewline -ForegroundColor Green "Caching VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.CachingvDisk) GB"
            Write-Host -NoNewline -ForegroundColor Green "Capacity VMDK: "
            Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.CapacityvDisk) GB"
        }
        Write-Host -NoNewline -ForegroundColor Green "Network Pool 1: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.VMNetwork1)"
        Write-Host -NoNewline -ForegroundColor Green "Network Pool 2: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.WldEsx.VMNetwork2)"
        Write-Host -NoNewline -ForegroundColor Green "Netmask "
        Write-Host -ForegroundColor White $VMNetmask
        Write-Host -NoNewline -ForegroundColor Green "Gateway: "
        Write-Host -ForegroundColor White $inputData.NetworkSpecs.ManagementNetwork.gateway
        Write-Host -NoNewline -ForegroundColor Green "DNS: "
        Write-Host -ForegroundColor White $inputData.NetworkSpecs.DnsSpec.NameServers
        Write-Host -NoNewline -ForegroundColor Green "NTP: "
        Write-Host -ForegroundColor White $inputdata.NetworkSpecs.NtpServers
        Write-Host -NoNewline -ForegroundColor Green "Syslog: "
        Write-Host -ForegroundColor White $inputData.VirtualDeployment.Syslog
    }
    Write-Host -ForegroundColor Magenta "`nWould you like to proceed with this deployment?`n"
    $answer = Read-Host -Prompt "Do you accept (Y or N)"
    if (( 'yes', 'y', 'true', 1 -notcontains $answer)) {
        exit
    }
    Clear-Host
}

if (!(( $NoNestedMgmtEsx) -and ( $NoCloudBuilderDeploy) -and (! $NestedWldEsx) -and (!$VCFBringup) )) {

    # Determine which parameter set is being used
    switch ($PSCmdlet.ParameterSetName) {
        'UsernamePassword' {
            Write-Logger "Using Username and Password for authentication ..."
            if ($null -eq $VIPassword) {
                $VIPassword = Read-Host -Prompt "Password for $($VIUsername):" -AsSecureString
            }
            # Perform authentication with VIUsername and VIPassword
            $credential = New-Object System.Management.Automation.PSCredential($VIUsername, $VIPassword)            
        }

        'Credential' {
            Write-Logger "Using PSCredential for authentication ..."
            # Use the provided VICredential
            $credential = $VICredential
        }
    }


    Write-Logger "Connecting to Management vCenter Server $VIServer ..."
    $viConnection = Connect-VIServer $VIServer -Credential $credential -WarningAction SilentlyContinue 
    if (!$viConnection) {
        Write-Logger -color red  -message "Login user:$($credential.UserName)  Failed" 
        exit
    }

    $datastore = Get-Datastore -Server $viConnection -Name $inputData.VirtualDeployment.VMDatastore | Select-Object -First 1
    $cluster = Get-Cluster -Server $viConnection -Name $inputData.VirtualDeployment.VMCluster
    $vmhost = $cluster | Get-VMHost | Get-Random -Count 1
}

if (!(( $NoNestedMgmtEsx) -and ( $NoCloudBuilderDeploy) -and (! $NestedWldEsx))) {
    if (-not $NoVapp ) {
        # Check whether DRS is enabled as that is required to create vApp
        if ((Get-Cluster -Server $viConnection $cluster).DrsEnabled) {

            if (-Not (Get-Folder $inputData.VirtualDeployment.VMFolder -ErrorAction Ignore)) {
                Write-Logger "Creating VM Folder $($inputData.VirtualDeployment.VMFolder) ..."
                $folder = New-Folder -Name $inputData.VirtualDeployment.VMFolder -Server $viConnection -Location (Get-Datacenter $inputData.VirtualDeployment.VMDatacenter | Get-Folder vm)
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
        $importLocation = $inputData.VirtualDeployment.VMCluster
    }
}


if (-not $NoNestedMgmtEsx  ) {  
    Write-Logger "Deploying $($inputData.VirtualDeployment.Esx.Hosts.Count) Managament ESX hosts ..."
    Add-VirtualEsx   -ImportLocation $importLocation -Esx $inputData.VirtualDeployment.Esx -NetworkSpecs $inputData.NetworkSpecs -VsanEsa:$inputData.vSan.ESA
}

if ( $NestedWldEsx  ) {  
    if ($null -eq $inputData.VirtualDeployment.WldEsx) {
        Write-Host -ForegroundColor Red "`nNo information available for the Workload ESX ...`n"
        exit
    }
    Write-Logger "Deploying $($inputData.VirtualDeployment.WldEsx.Hosts.Count) Workload ESX hosts ..."
    Add-VirtualEsx   -ImportLocation $importLocation -Esx $inputData.VirtualDeployment.WldEsx -NetworkSpecs $inputData.NetworkSpecs -VsanEsa:$inputData.vSan.ESA
    $VCFWorkloadDomainUIJSONFile = "$VAppName-WorkloadDomainUi.json"
    $VCFWorkloadDomainAPIJSONFile = "$VAppName-WorkloadDomainApi.json"
    Write-Logger "Generating Cloud Builder VCF Workload Domain Host Commission file $VCFWorkloadDomainUIJSONFile and $VCFWorkloadDomainAPIJSONFile for SDDC Manager UI and API"
    $commissionHostsUI = @()
    $commissionHostsAPI = @()
    foreach ($name in $inputData.VirtualDeployment.WldEsx.Hosts.keys) {
        $hostFQDN = "$name.$($inputData.NetworkSpecs.DnsSpec.Domain)"

        $tmp1 = [ordered] @{
            "hostfqdn"        = $hostFQDN
            "username"        = "root"
            "password"        = $inputData.VirtualDeployment.WldEsx.Password
            "networkPoolName" = $InputData.Management.PoolName
            "storageType"     = "VSAN"
        }
        $commissionHostsUI += $tmp1

        $tmp2 = [ordered] @{
            "fqdn"          = $hostFQDN
            "username"      = "root"
            "password"      = $inputData.VirtualDeployment.WldEsx.Password
            "networkPoolId" = "TBD"
            "storageType"   = "VSAN"
        }
        $commissionHostsAPI += $tmp2
    }

    $vcfCommissionHostConfigUI = @{
        "hostsSpec" = $commissionHostsUI
    }

    $vcfCommissionHostConfigUI | ConvertTo-Json -Depth 2 | Out-File -LiteralPath $VCFWorkloadDomainUIJSONFile
    $commissionHostsAPI | ConvertTo-Json -Depth 2 | Out-File -LiteralPath $VCFWorkloadDomainAPIJSONFile

}
if (-not $NoCloudBuilderDeploy) {
    $answer = ""
    $CloudbuilderVM = Get-VM -Name $inputData.VirtualDeployment.Cloudbuilder.VMName -Server $viConnection -Location $importLocation -ErrorAction SilentlyContinue

    $redeploy, $answer = Test-VMForReImport -Vm $CloudbuilderVM -Answer $answer

    if ( $redeploy) { 
            
        $ovfconfig = Get-OvfConfiguration $inputData.VirtualDeployment.CloudBuilder.Ova

        $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
        $ovfconfig.NetworkMapping.$networkMapLabel.value = $inputData.VirtualDeployment.Cloudbuilder.PortGroup
        $ovfconfig.common.guestinfo.hostname.value = $inputData.VirtualDeployment.Cloudbuilder.Hostname
        $ovfconfig.common.guestinfo.ip0.value = $inputData.VirtualDeployment.Cloudbuilder.Ip
        $ovfconfig.common.guestinfo.netmask0.value = $VMNetmask
        $ovfconfig.common.guestinfo.gateway.value = $inputData.NetworkSpecs.ManagementNetwork.gateway
        $ovfconfig.common.guestinfo.DNS.value = $inputData.NetworkSpecs.DnsSpec.NameServers
        $ovfconfig.common.guestinfo.domain.value = $inputData.NetworkSpecs.DnsSpec.Domain
        $ovfconfig.common.guestinfo.searchpath.value = $inputData.NetworkSpecs.DnsSpec.Domain
        $ovfconfig.common.guestinfo.ntp.value = $inputdata.NetworkSpecs.NtpServers -join ","
        $ovfconfig.common.guestinfo.ADMIN_USERNAME.value = $CloudbuilderAdminUsername
        $ovfconfig.common.guestinfo.ADMIN_PASSWORD.value = $inputData.VirtualDeployment.Cloudbuilder.AdminPassword
        $ovfconfig.common.guestinfo.ROOT_PASSWORD.value = $inputData.VirtualDeployment.Cloudbuilder.RootPassword

        Write-Logger "Deploying Cloud Builder VM $($inputData.VirtualDeployment.Cloudbuilder.VMName) ..."
        $CloudbuilderVM = Import-VApp -Source $inputData.VirtualDeployment.CloudBuilder.Ova -OvfConfiguration $ovfconfig -Name $inputData.VirtualDeployment.Cloudbuilder.VMName -Location $importLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin 
        if (-not $CloudbuilderVM) {
            Write-Logger -color red  -message "Deploy of $($inputData.VirtualDeployment.Cloudbuilder.VMName) failed."
            @{date = (Get-Date); failure = $true; vapp = $VApp; component = 'CloudBuilder' } | ConvertTo-Json | Out-File state.json
            exit
        }
        Write-Logger "Powering On $($inputData.VirtualDeployment.Cloudbuilder.VMName) ..."
        $CloudbuilderVM | Start-Vm -RunAsync | Out-Null
    }
}
  

if ($GeneratePsd1) {
    Write-Logger "Saving the Configuration file '$exportFileName.psd1' ..."
    Convert-HashtableToPsd1String -Hashtable $inputData | Out-File "$exportFileName.psd1"
}

if ($GenerateJson -or $VCFBringup) { 
    Write-Logger "Generate the JSON workload ..."
    $orderedHashTable = Get-JsonWorkload -InputData $inputData
    $inputJson = $orderedHashTable | ConvertTo-Json  -Depth 10
 
    if ($GenerateJson) { 
        Write-Logger "Saving the JSON workload file '$exportFileName.json' ..."
        $inputJson | out-file "$exportFileName.json"
    } 

    if ($VCFBringup) {
        Write-Logger "Starting VCF Deployment Bringup ..." 
         

        Write-Logger "Waiting for Cloud Builder to be ready ..."
        while (1) {
            $credentialsair = "admin:$($inputData.VirtualDeployment.Cloudbuilder.AdminPassword)"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($credentialsair)
            $base64 = [System.Convert]::ToBase64String($bytes)

            try {
                if ($PSVersionTable.PSEdition -eq "Core") {
                    $requests = Invoke-WebRequest -Uri "https://$($inputData.VirtualDeployment.Cloudbuilder.Ip)/v1/sddcs" -Method GET -SkipCertificateCheck -TimeoutSec 5 -Headers @{"Authorization" = "Basic $base64" }
                }
                else {
                    $requests = Invoke-WebRequest -Uri "https://$($inputData.VirtualDeployment.Cloudbuilder.Ip)/v1/sddcs" -Method GET -TimeoutSec 5 -Headers @{"Authorization" = "Basic $base64" }
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
 
        # Convert password to secure string and create PSCredential
        $esxPasswd = ConvertTo-SecureString -String $inputData.VirtualDeployment.Esx.Password -AsPlainText -Force
        $cred = [Management.Automation.PSCredential]::new('root', $esxPasswd)

        # Define the server name
        $serverName = "$($inputData.VirtualDeployment.Esx.keys[0]).$($NetworkSpecs.DnsSpec.Domain)"

        # Start the job to run Get-vSANHcl with necessary parameters
        $job = Start-Job -ScriptBlock { 
            param (
                [string]$serverName, 
                [Management.Automation.PSCredential]$cred
            )
            Get-vSANHcl -Server $serverName -Credential $cred 
        } -ArgumentList $serverName, $cred

        # Wait for the job to complete
        Wait-Job -Job $job

        # Get the result
        $result = Receive-Job -Job $job

        # Output result and clean up
        Write-Output "Job result: $result"
        Remove-Job -Job $job


        Start-Sleep 60 
        Invoke-BringUp -HclFile $inputdata.vSan.HclFile `
            -CloudbuilderFqdn $inputData.VirtualDeployment.Cloudbuilder.Ip `
            -AdminPassword $(ConvertTo-SecureString -String $inputData.VirtualDeployment.Cloudbuilder.AdminPassword -AsPlainText -Force) `
            -Json $inputJson   
    }

}

if ($VCFBringup -and $uploadVCFNotifyScript -eq 1) {
    if (Test-Path $srcNotificationScript) {
        $cbVM = Get-VM -Server $viConnection $inputData.VirtualDeployment.Cloudbuilder.Hostname

        Write-Logger "Uploading VCF notification script $srcNotificationScript to $dstNotificationScript on Cloud Builder appliance ..."
        Copy-VMGuestFile -Server $viConnection -VM $cbVM -Source $srcNotificationScript -Destination $dstNotificationScript -LocalToGuest -GuestUser "root" -GuestPassword $inputData.VirtualDeployment.Cloudbuilder.RootPassword | Out-Null
        Invoke-VMScript -Server $viConnection -VM $cbVM -ScriptText "chmod +x $dstNotificationScript" -GuestUser "root" -GuestPassword $inputData.VirtualDeployment.Cloudbuilder.RootPassword | Out-Null

        Write-Logger "Configuring crontab to run notification check script every 15 minutes ..."
        Invoke-VMScript -Server $viConnection -VM $cbVM -ScriptText "echo '*/15 * * * * $dstNotificationScript' > /var/spool/cron/root" -GuestUser "root" -GuestPassword $inputData.VirtualDeployment.Cloudbuilder.RootPassword | Out-Null
    }
}

if ($deployNestedESXiVMsForMgmt -eq 1 -or (-not $NoCloudBuilderDeploy)) {
    Write-Logger "Disconnecting from $VIServer ..."
    Disconnect-VIServer -Server $viConnection -Confirm:$false
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

Write-Logger "VCF Lab Deployment Complete!"
Write-Logger "StartTime: $StartTime"
Write-Logger "EndTime: $EndTime"
Write-Logger "Duration: $duration minutes to Deploy Nested ESXi, CloudBuilder & initiate VCF Bringup"
