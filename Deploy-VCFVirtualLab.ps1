<#
.SYNOPSIS
    Automated VMware Cloud Foundation (VCF) Deployment Script.

.DESCRIPTION
    This script automates the deployment of VMware Cloud Foundation (VCF) in a lab environment. 
    It includes support for deploying nested ESXi hosts, configuring and deploying Cloud Builder,
    and initiating the VCF bringup process. Additionally, it provides options to export the configuration
    to JSON or Psd1 format and to generate workload domain commissioning files.

.PARAMETER VIUsername
    Specifies the vCenter Server username for connecting to the management vCenter. Default is 'administrator@vsphere.local'.

.PARAMETER VIPassword
    Specifies the vCenter Server password as a SecureString. Can be piped from input or provided directly. If not provided, it will prompt for input.

.PARAMETER VICredential
    Specifies a PSCredential object for authentication in place of `VIUsername` and `VIPassword`.

.PARAMETER ConfigurationFile
    Specifies the path to a configuration file, which can be in `.psd1`, `.xlsx`, or `.json` format, 
    containing setup parameters for VCF deployment.

.PARAMETER VAppName
    Specifies the name of the vApp to use for organizing VMs if DRS is enabled.

.PARAMETER UseSSH
    Indicates that SSH is available for file transfer, enabling SCP for HCL file upload to Cloud Builder.

.PARAMETER GenerateJsonFile
    When set, exports the workload configuration to a JSON file.

.PARAMETER GeneratePsd1File
    When set, exports the workload configuration to a Psd1 file.

.PARAMETER VCFBringup
    When set, initiates the VCF bringup process after deployment.

.PARAMETER NoVapp
    Prevents creation of a vApp, even if DRS is enabled.

.PARAMETER VIServer
    Specifies the management vCenter Server FQDN. Default is 'vmw-vc01.lab.local'.

.PARAMETER NoCloudBuilderDeploy
    Prevents the deployment of Cloud Builder.

.PARAMETER NoNestedMgmtEsx
    Prevents the deployment of nested management ESXi hosts.

.PARAMETER NestedWldEsx
    Enables deployment of nested workload domain ESXi hosts.

.PARAMETER EsxOVA
    Specifies the path to the ESXi OVA file for deploying nested hosts.

.PARAMETER CloudBuilderOVA
    Specifies the path to the Cloud Builder OVA file for deployment.

.PARAMETER ExportFileName
    Specifies the base name for exported configuration files (JSON and/or Psd1).

.EXAMPLE
    # Example with VIPassword - Deploy VCF, export configuration, and initiate bringup
    $password = ConvertTo-SecureString "YourPassword" -AsPlainText -Force
    .\Deploy-VCFVirtualLab.ps1 -VIUsername "administrator@vsphere.local" -VIPassword $password -ConfigurationFile "C:\Configs\VCFConfig.psd1" `
        -VCFBringup -VAppName "VCF_Lab" -EsxOVA "C:\OVAs\esxi.ova" -CloudBuilderOVA "C:\OVAs\cloudbuilder.ova" -GenerateJsonFile

.EXAMPLE
    # Example with VIPassword via pipeline
    ConvertTo-SecureString "YourPassword" -AsPlainText -Force |
     .\Deploy-VCFVirtualLab.ps1 -VIUsername "administrator@vsphere.local" -ConfigurationFile "C:\Configs\VCFConfig.xlsx" `
        -VAppName "VCF_Lab" -EsxOVA "C:\OVAs\esxi.ova" -CloudBuilderOVA "C:\OVAs\cloudbuilder.ova" -NoNestedMgmtEsx

.EXAMPLE
    # Example with VICredential - Deploy VCF and skip bringup
    $credential = New-Object System.Management.Automation.PSCredential("administrator@vsphere.local", (ConvertTo-SecureString "YourPassword" -AsPlainText -Force))
    .\Deploy-VCFVirtualLab.ps1 -VICredential $credential -ConfigurationFile "C:\Configs\VCFConfig.xlsx" `
        -VAppName "VCF_Lab" -EsxOVA "C:\OVAs\esxi.ova" -CloudBuilderOVA "C:\OVAs\cloudbuilder.ova" -NoVapp -NoCloudBuilderDeploy

.NOTES
    - This script requires VMware PowerCLI and the ImportExcel module (if using .xlsx configuration files).
    - For SCP file transfers, the Posh-SSH module is needed.
    - Ensure sufficient permissions and network connectivity to the vCenter Server and Cloud Builder.
    - Only VCF versions 5.1.0, 5.1.1, 5.2.0, and 5.2.1 are currently supported by this script.

    Unsupported Parameters from Excel Spreadsheet:
    - Proxy Server Configuration:
        - Proxy Server
        - Proxy Port
        - Proxy Username
        - Proxy Password
        - Proxy Transfer Protocol (only HTTP is supported)
        - HTTPS Proxy Certificate (PEM Encoded)

    - Secondary vSphere Distributed Switch (Optional):
        - Name
        - Transport Zone Type
        - Physical NICs (pNICs)
        - MTU Size

.LINK
    https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html
#>
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

    # [string]
    #$HCLJsonFile = "$PWD/nested-esxi-vsan-esa-hcl.json",
    
    [string]
    $VAppName,
    
    [switch]
    $UseSSH,
    
    [switch]
    $GenerateJsonFile,
    
    [switch]
    $GeneratePsd1File,
    
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

# Conditionally install and import required modules
if ($ExcelFile) {
    install-Module -Name "ImportExcel" -Scope CurrentUser
}
if ($UseSSH) {
    install-module -Name "Posh-SSH"  -Scope CurrentUser
}
Import-Module -Name ./Utility.psm1  
  
$uploadVCFNotifyScript = 0

$srcNotificationScript = "vcf-bringup-notification.sh"
$dstNotificationScript = "/root/vcf-bringup-notification.sh"

$StartTime = Get-Date

# Load configuration file (supports .psd1, .xlsx, .json formats)
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
        Write-Logger -ForegroundColor Red "`nThe file '$ConfigurationFile' does not exist ...`n"
        exit 1
    }

    if ($null -eq $inputData ) {
        Write-Host -ForegroundColor Red "`n'$ConfigurationFile' return an enpty configuration ...`n"
        exit 1
    }
}

# Detect VCF version based on Cloud Builder OVA (support is 5.1.0+)
if ($inputData.VirtualDeployment.CloudBuilder.Ova -match "5.2.1") {
    $VCFVersion = "5.2.1"
}
elseif ($inputData.VirtualDeployment.CloudBuilder.Ova -match "5.2.0") {
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

# VCF version validation and password checks for Cloud Builder
if ($null -eq $VCFVersion) {
    Write-Host -ForegroundColor Red "`nOnly VCF 5.1.0, 5.1.1, 5.2.0 and 5.2.1 are currently supported ...`n"
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
    # Summarize the deployment configuration for user confirmation
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
    if ([string]::IsNullOrEmpty($exportFileName) -and ($GeneratePsd1File -or $GenerateJsonFile)) {
        while ( [string]::IsNullOrEmpty($exportFileName)) {
            Write-Host -NoNewline -ForegroundColor Magenta "`nPlease specify the filename for the exported configuration : "
            $exportFileName = Read-Host  
        }
    }

    
    # Define the export path based on the current working directory and the export file name
    $path = Join-Path -Path $PWD -ChildPath $exportFileName
     
    # Check if the export path directory exists; if not, create it
    Write-Host "Checking if the export path $path directory exists ..."
    if (!(Test-Path -Path $path)) {
        Write-Host "Creating the export path $path ..."
        New-Item -Path $path -ItemType Directory -ErrorAction Stop | Out-Null
    }

    # Start the logging process and specify the path for log files
    Start-Logger -Path $path 

    # Log the intent to export the JSON workload file if the option is enabled
    if ($GenerateJsonFile) { 
        Write-Logger "Export the JSON workload to the file '$(Join-Path -Path $path -ChildPath "$exportFileName.json")'."
    }
 
    # Log the intent to export the configuration file in PSD1 format if the option is enabled
    if ($GeneratePsd1File) {
        Write-Logger "Export the Configuration to the file '$(Join-Path -Path $path -ChildPath "$exportFileName.psd1")'."
    }

    # Display a summary of the configuration and deployment options chosen
    Show-Summary -InputData $InputData `
        -VCFBringup:$VCFBringup `
        -NoCloudBuilderDeploy:$NoCloudBuilderDeploy `
        -NoNestedMgmtEsx:$NoNestedMgmtEsx `
        -NestedWldEsx:$NestedWldEsx
    
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
        Write-Logger -ForegroundColor red  -message "Login user:$($credential.UserName)  Failed" 
        exit
    }

    $datastore = Get-Datastore -Server $viConnection -Name $inputData.VirtualDeployment.VMDatastore | Select-Object -First 1
    $cluster = Get-Cluster -Server $viConnection -Name $inputData.VirtualDeployment.VMCluster
    $vmhost = $cluster | Get-VMHost | Get-Random -Count 1
}

if (!(( $NoNestedMgmtEsx) -and ( $NoCloudBuilderDeploy) -and (! $NestedWldEsx))) {
    # Check and create vApp if required
    if (-not $NoVapp ) {
        # Check whether DRS is enabled as that is required to create vApp
        if ((Get-Cluster -Server $viConnection $cluster).DrsEnabled) {

            if (-Not (Get-Folder $inputData.VirtualDeployment.VMFolder -ErrorAction Ignore)) {
                Write-Logger "Creating VM Folder $($inputData.VirtualDeployment.VMFolder) ..."
                $vmFolder = New-Folder -Name $inputData.VirtualDeployment.VMFolder -Server $viConnection -Location (Get-Datacenter $inputData.VirtualDeployment.VMDatacenter | Get-Folder vm)
            }
            $VApp = Get-VApp -Name $VAppName -Server $viConnection -Location $cluster -ErrorAction SilentlyContinue
            if ( $null -eq $VApp) {
                Write-Logger "Creating vApp $VAppName ..."
                $VApp = New-VApp -Name $VAppName -Server $viConnection -Location $cluster -InventoryLocation $vmFolder
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

# Deploy nested management and workload ESXi hosts
if (-not $NoNestedMgmtEsx  ) {  
    Write-Logger "Deploying $($inputData.VirtualDeployment.Esx.Hosts.Count) Managament ESX hosts ..."
    Add-VirtualEsx -ImportLocation $importLocation -Esx $inputData.VirtualDeployment.Esx -NetworkSpecs $inputData.NetworkSpecs -VsanEsa:$inputData.vSan.ESA  -VMHost $vmhost -Datastore  $Datastore 
}

# If the Nested Workload ESXi deployment is requested, proceed with the following actions
if ($NestedWldEsx) {  

    # Check if Workload ESXi information is provided; if not, log an error and exit
    if ($null -eq $inputData.VirtualDeployment.WldEsx) {
        Write-Logger -ForegroundColor Red "`nNo information available for the Workload ESX ...`n"
        exit
    }

    # Log the start of deploying Workload ESXi hosts with the count from input data
    Write-Logger "Deploying $($inputData.VirtualDeployment.WldEsx.Hosts.Count) Workload ESX hosts ..."

    # Call the Add-VirtualEsx function to handle the deployment of Workload ESXi hosts
    Add-VirtualEsx -ImportLocation $importLocation -Esx $inputData.VirtualDeployment.WldEsx -NetworkSpecs $inputData.NetworkSpecs `
        -VsanEsa:$inputData.vSan.ESA -VMHost $vmhost -Datastore $Datastore 

    # Export the configuration for the Workload Domain in both API and UI formats for SDDC Manager
    Export-CommissionFile -InputData $InputData -Path $Path -ExportFileName $ExportFileName
}

# If the Cloud Builder deployment is not skipped, proceed to deploy it
if (-not $NoCloudBuilderDeploy) {

    # Call the Add-CloudBuilder function to handle the deployment of the Cloud Builder VM
    Add-CloudBuilder -InputData $InputData -ImportLocation $ImportLocation -VMHost $vmhost -Datastore $Datastore 
}

 
# Export configurations (JSON or Psd1) as specified by user
if ($GeneratePsd1File) {
    $exportPsd1 = Join-Path -Path $path -ChildPath "$exportFileName.psd1"
    Write-Logger "Saving the Configuration file '$exportPsd1' ..."
    Convert-HashtableToPsd1String -Hashtable $inputData | Out-File "$exportPsd1"
}

# If JSON file generation or VCF Bringup is requested, perform the following actions
if ($GenerateJsonFile -or $VCFBringup) { 

    # Retrieve the vSAN HCL from the first ESXi host and save it to the specified path
    Get-FirstEsxHcl -InputData $inputData -Path $path 
    
    # If JSON file generation is enabled, define the export path and save the JSON workload file
    if ($GenerateJsonFile) { 
        $exportJson = Join-Path -Path $path -ChildPath "$exportFileName.json"
        Write-Logger "Saving the JSON workload file '$exportJson' ..."

        # Convert the workload to JSON format and export it to the specified path
        Get-JsonWorkload -InputData $inputData | ConvertTo-Json  -Depth 10 | out-file $exportJson
    } 

    # VCF Bringup initiation if requested
    if ($VCFBringup) {
        Write-Logger "Starting VCF Deployment Bringup ..."          
        # Initial brief delay to allow the Cloud Builder API service to initialize
        Start-Sleep 5
        
        # Log the start of the Cloud Builder readiness check
        Write-Logger "Waiting for Cloud Builder to be ready ..."  
          
        # Loop to repeatedly check Cloud Builder's readiness
        while ($true) {
            try { 
                # Attempt a GET request to the Cloud Builder's API to check for a successful response            
                $requests = Invoke-WebRequest -Uri "https://$($inputData.VirtualDeployment.Cloudbuilder.Ip)/v1/sddcs" -Method GET -SkipCertificateCheck `
                    -TimeoutSec 5 -Authentication Basic -Credential $inputData.VirtualDeployment.Cloudbuilder.AdminCredential
               
                # If status code 200 is returned, Cloud Builder is ready, and deployment can proceed
                if ($requests.StatusCode -eq 200) {
                    Write-Logger "Cloud Builder is now ready! waiting for 60 seconds ..."
                    
                    # Additional wait to ensure all services on Cloud Builder are fully up
                    Start-Sleep 60 
                    break
                }
            }
            catch {
                # If the request fails, log and wait before retrying
                Write-Logger "Cloud Builder is not ready yet, sleeping for 30 seconds ..."
                Start-Sleep 30
            }
        }
        # Invoke the bringup process once Cloud Builder is ready 
        Invoke-BringUp -InputData $inputdata -Path $path
    }

}

# Optional upload of notification script to Cloud Builder
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

# Disconnect from vCenter and display completion message
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
