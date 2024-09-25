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


Export-ModuleMember -Function Test-VMForReImport
Export-ModuleMember -Function Write-Logger
Export-ModuleMember -Function Get-TransportZone
Export-ModuleMember -Function ConvertTo-Netmask