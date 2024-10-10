@{

    "NetworkSpecs"      = @{
        "dnsSpec"           = @{
            "Domain"      = 'vcf.lab.local'
            "NameServers" = '192.168.0.250'
            "Subdomain"   = 'vcf.lab.local'
        }

        "ManagementNetwork" = @{
            "gateway"      = '192.168.10.254'
            "Mtu"          = 9000
            "portGroupKey" = 'SDDC-DPortGroup-Mgmt'
            "subnet"       = '192.168.10.0/24'
            "vLanId"       = 10
        }

        "NtpServers"        = @(
            '192.168.0.1'
        )
    }
    "VirtualDeployment" = @{
        "WldEsx" = @{
            "Ova"           = "./ova/Nested_ESXi8.0u3_Appliance_Template_v1.ova"
            "Password"      = "Pata2Pata1Pata!"
            "Syslog"        = "192.168.1.1"
            "vCPU"          = 12
            "vMemory"       = 78
            "VMNetwork1"    = "Trunk"
            "VMNetwork2"    = "Trunk"
            "BootDisk"      = 32
            "CachingvDisk"  = 500
            "CapacityvDisk" = 500
            "ESADisk1"      = 500
            "ESADisk2"      = 500
            "Hosts"         = @{
                "vcf42-esx05" = @{
                    "Ip"            = "192.168.10.104"
                    "SshThumbprint" = "SHA256:DUMMY_VALUE"
                    "SslThumbprint" = "SHA256:DUMMY_VALUE"
                }

                "vcf42-esx06" = @{
                    "Ip"            = "192.168.10.105"
                    "SshThumbprint" = "SHA256:DUMMY_VALUE"
                    "SslThumbprint" = "SHA256:DUMMY_VALUE"
                }

                "vcf42-esx07" = @{
                    "Ip"            = "192.168.10.106"
                    "SshThumbprint" = "SHA256:DUMMY_VALUE"
                    "SslThumbprint" = "SHA256:DUMMY_VALUE"
                }

                "vcf42-esx08" = @{
                    "Ip"            = "192.168.10.107"
                    "SshThumbprint" = "SHA256:DUMMY_VALUE"
                    "SslThumbprint" = "SHA256:DUMMY_VALUE"
                }

            }

             
        }
    }
}
 