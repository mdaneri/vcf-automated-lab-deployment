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

    [string]
    $EsxOVA,

    [string]
    $CloudBuilderOVA  
)
# Author: William Lam
# Website: www.williamlam.com

if ($ExcelFile) {
    install-Module -Name "ImportExcel" -Scope CurrentUser
}
if ($UseSSH.isPresent) {
    install-module -Name "Posh-SSH"  -Scope CurrentUser
}
Import-Module -Name ./Utility.psm1

if ([string]::IsNullOrEmpty( $VAppName) ) {
    $random_string = -join ((65..90) + (97..122) | Get-Random -Count 8 | % { [char]$_ })
    $VAppName = "Nested-VCF-Lab-$random_string"
}
$verboseLogFile = "$VAppName-deployment.log"

 


 


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
                $inputData = Import-PowerShellDataFile -Path $ConfigurationFile
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
    
    if ((-not $NoCloudBuilderDeploy.IsPresent) -or (-not $NoNestedMgmtEsx.IsPresent)) {
        Write-Host -NoNewline -ForegroundColor Green "VM vApp: "
        Write-Host -ForegroundColor White $VAppName
    }
    
    if (-not $NoCloudBuilderDeploy.IsPresent) {
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

    if (-not $NoNestedMgmtEsx.IsPresent) {
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
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.VMNetwork1) GB"
        Write-Host -NoNewline -ForegroundColor Green "Network Pool 2: "
        Write-Host -ForegroundColor White "$($inputData.VirtualDeployment.Esx.VMNetwork2) GB"
     

    

        Write-Host -NoNewline -ForegroundColor Green "`nNetmask "
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

if ((-not $NoNestedMgmtEsx) -or (-not $NoCloudBuilderDeploy.IsPresent)) {

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
 

    if (-not $NoVapp.IsPresent ) {
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


if (-not $NoNestedMgmtEsx.IsPresent  ) {
    $answer = $null
    $inputData.VirtualDeployment.Esx.Hosts.GetEnumerator().foreach({ 
            $VMName = $_.Key
            $VMIPAddress = $_.Value.Ip
            $vm = Get-VM -Name $_.Key -Server $viConnection -Location $importLocation -ErrorAction SilentlyContinue

            $redeploy, $answer = Test-VMForReImport -Vm $vm -Answer $answer

            if (! $redeploy) {
                return
            }

            $ovfconfig = Get-OvfConfiguration $inputData.VirtualDeployment.Esx.Ova
            $networkMapLabel = ($ovfconfig.ToHashTable().keys | Where-Object { $_ -Match "NetworkMapping" }).replace("NetworkMapping.", "").replace("-", "_").replace(" ", "_")
            $ovfconfig.NetworkMapping.$networkMapLabel.value = $inputData.VirtualDeployment.ESX.VMNetwork1
            $ovfconfig.common.guestinfo.hostname.value = "$VMName.$($inputData.NetworkSpecs.DnsSpec.Domain)"
            $ovfconfig.common.guestinfo.ipaddress.value = $VMIPAddress
            $ovfconfig.common.guestinfo.netmask.value = $VMNetmask
            $ovfconfig.common.guestinfo.gateway.value = $inputData.NetworkSpecs.ManagementNetwork.gateway
            $ovfconfig.common.guestinfo.dns.value = $inputData.NetworkSpecs.DnsSpec.NameServers
            $ovfconfig.common.guestinfo.domain.value = $inputData.NetworkSpecs.DnsSpec.Domain
            $ovfconfig.common.guestinfo.ntp.value = $inputdata.NetworkSpecs.NtpServers -join ","
            $ovfconfig.common.guestinfo.syslog.value = $inputData.VirtualDeployment.Syslog
            $ovfconfig.common.guestinfo.password.value = $inputData.VirtualDeployment.Esx.Password
            $ovfconfig.common.guestinfo.vlan.value = $inputData.NetworkSpecs.ManagementNetwork.vLanId
            $ovfconfig.common.guestinfo.ssh.value = $true

            Write-Logger "Deploying Nested ESXi VM $VMName ..."
            $vm = Import-VApp -Source $inputData.VirtualDeployment.Esx.Ova -OvfConfiguration $ovfconfig -Name $VMName -Location $importLocation -VMHost $vmhost -Datastore $datastore -DiskStorageFormat thin 
            
            if (-not $vm) {
                Write-Logger -color red  -message "Deploy of $( $ovfconfig.common.guestinfo.hostname.value) failed."
                @{date = (Get-Date); failure = $true; vapp = $VApp; component = 'ESX' } | ConvertTo-Json | Out-File state.json
                exit
            }

            Write-Logger "Adding vmnic2/vmnic3 to Nested ESXi VMs ..."
            $vmPortGroup = Get-VirtualNetwork -Name $inputData.VirtualDeployment.ESX.VMNetwork2 -Location ($cluster | Get-Datacenter)
            if ($vmPortGroup.NetworkType -eq "Distributed") {
                $vmPortGroup = Get-VDPortgroup -Name $inputData.VirtualDeployment.ESX.VMNetwork2
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

            Write-Logger "Updating vCPU Count to $($inputData.VirtualDeployment.Esx.vCPU) & vMEM to $($inputData.VirtualDeployment.Esx.vMemory) GB ..."
            Set-VM -Server $viConnection -VM $vm -NumCpu $inputData.VirtualDeployment.Esx.vCPU -CoresPerSocket $inputData.VirtualDeployment.Esx.vCPU -MemoryGB $inputData.VirtualDeployment.Esx.vMemory -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

           

            Write-Logger "Updating vSAN Boot Disk size to $($inputData.VirtualDeployment.Esx.BootDisk) GB ..."
            Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 1" | Set-HardDisk -CapacityGB $inputData.VirtualDeployment.Esx.BootDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            # vSAN ESA requires NVMe Controller
            if ($inputdata.vSan.ESA) {

                Write-Logger "Updating vSAN Disk Capacity VMDK size to $($inputData.VirtualDeployment.Esx.ESADisk1) GB  and $($inputData.VirtualDeployment.Esx.ESADisk2) GB .."
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $inputData.VirtualDeployment.Esx.ESADisk1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $inputData.VirtualDeployment.Esx.ESADisk2 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

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
                Write-Logger "Updating vSAN Cache VMDK size to $($inputData.VirtualDeployment.Esx.CachingvDisk) GB & Capacity VMDK size to $($inputData.VirtualDeployment.Esx.CapacityvDisk) GB ..."
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 2" | Set-HardDisk -CapacityGB $inputData.VirtualDeployment.Esx.CachingvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
                Get-HardDisk -Server $viConnection -VM $vm -Name "Hard disk 3" | Set-HardDisk -CapacityGB $inputData.VirtualDeployment.Esx.CapacityvDisk -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
            }


            Write-Logger "Powering On $vmname ..."
            $vm | Start-Vm -RunAsync | Out-Null
            
        })
}

if (-not $NoCloudBuilderDeploy.IsPresent) {
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
  

if ($GeneratePsd1.isPresent) {
    Write-Logger "Saving the Configuration file '$VAppName.psd1' ..."
    Convert-HashtableToPsd1String -Hashtable $inputData | Out-File "$VAppName.psd1"
}



if ($GenerateJson.isPresent -or $VCFBringup.IsPresent) { 
    Write-Logger "Generate the JSON workload ..."
    $orderedHashTable = Get-JsonWorkload -InputData $inputData
    $inputJson = $orderedHashTable | ConvertTo-Json  -Depth 10
 
    if ($GenerateJson.isPresent) { 
        Write-Logger "Saving the JSON workload file '$VAppName.json' ..."
        $inputJson | out-file "$VAppName.json"
    } 

    if ($VCFBringup.IsPresent) {
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

    
    
      #  Start-Sleep 60 
        Invoke-BringUp -HclFile $inputdata.vSan.HclFile `
            -CloudbuilderFqdn $inputData.VirtualDeployment.Cloudbuilder.Ip `
            -AdminPassword $(ConvertTo-SecureString -String $inputData.VirtualDeployment.Cloudbuilder.AdminPassword -AsPlainText -Force) `
            -Json $inputJson  
        <#$adminPwd = ConvertTo-SecureString $inputData.VirtualDeployment.Cloudbuilder.AdminPassword -AsPlainText -Force
        $cred = [Management.Automation.PSCredential]::new('admin', $adminPwd)

        if ($inputdata.vSan.HclFile) {
            if ($UseSSH.isPresent) {
                $hclFiledest = Split-Path -Path $inputdata.vSan.HclFile
                Write-Logger "SCP HCL $($HCLJsonFile) file to $($inputdata.vSan.HclFile) ..."
                Set-SCPItem -ComputerName $inputData.VirtualDeployment.Cloudbuilder.Ip -Credential $cred -Path $HCLJsonFile -Destination $hclFiledest -AcceptKey
            }
            Write-Logger "Copy-VMGuestFile HCL $($HCLJsonFile) file to $($inputdata.vSan.HclFile) ..."
            Copy-VMGuestFile -Source $HCLJsonFile -Destination $inputdata.vSan.HclFile -GuestCredential $cred -VM $CloudbuilderVM -LocalToGuest -Force
        }
        Write-Logger "Submitting VCF Bringup request ..." 
    
        $bringupAPIParms = @{
            Uri         = "https://$($inputData.VirtualDeployment.Cloudbuilder.Ip)/v1/sddcs"
            Method      = 'POST'
            Body        = $inputJson
            ContentType = 'application/json'
            Credential  = $cred
        }
        $bringupAPIReturn = Invoke-RestMethod @bringupAPIParms -SkipCertificateCheck
        Write-Logger "Open browser to the VMware Cloud Builder UI (https://${Hostname}) to monitor deployment progress ..."
        #>
    }

}

if ($VCFBringup.IsPresent -and $uploadVCFNotifyScript -eq 1) {
    if (Test-Path $srcNotificationScript) {
        $cbVM = Get-VM -Server $viConnection $inputData.VirtualDeployment.Cloudbuilder.Hostname

        Write-Logger "Uploading VCF notification script $srcNotificationScript to $dstNotificationScript on Cloud Builder appliance ..."
        Copy-VMGuestFile -Server $viConnection -VM $cbVM -Source $srcNotificationScript -Destination $dstNotificationScript -LocalToGuest -GuestUser "root" -GuestPassword $inputData.VirtualDeployment.Cloudbuilder.RootPassword | Out-Null
        Invoke-VMScript -Server $viConnection -VM $cbVM -ScriptText "chmod +x $dstNotificationScript" -GuestUser "root" -GuestPassword $inputData.VirtualDeployment.Cloudbuilder.RootPassword | Out-Null

        Write-Logger "Configuring crontab to run notification check script every 15 minutes ..."
        Invoke-VMScript -Server $viConnection -VM $cbVM -ScriptText "echo '*/15 * * * * $dstNotificationScript' > /var/spool/cron/root" -GuestUser "root" -GuestPassword $inputData.VirtualDeployment.Cloudbuilder.RootPassword | Out-Null
    }
}

if ($deployNestedESXiVMsForMgmt -eq 1 -or (-not $NoCloudBuilderDeploy.IsPresent)) {
    Write-Logger "Disconnecting from $VIServer ..."
    Disconnect-VIServer -Server $viConnection -Confirm:$false
}

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes, 2)

Write-Logger "VCF Lab Deployment Complete!"
Write-Logger "StartTime: $StartTime"
Write-Logger "EndTime: $EndTime"
Write-Logger "Duration: $duration minutes to Deploy Nested ESXi, CloudBuilder & initiate VCF Bringup"
