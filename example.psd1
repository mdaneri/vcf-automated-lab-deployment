[ordered]@{
	"VirtualDeployment"           = [ordered]@{
		"VMCluster"    = 'Cluster01'
		"VMDatastore"  = 'vSanDatastore'
		"VMFolder"     = 'VCF'
		"Cloudbuilder" = [ordered]@{
			"RootPassword"  = 'Pata2Pata1Pata!'
			"Ip"            = '192.168.10.195'
			"Ova"           = './ova/VMware-Cloud-Builder-5.2.0.0-24108943_OVF10.ova'
			"Hostname"      = 'cloudbuilder.vcf.lab.local'
			"VMName"        = 'cloudbuilder'
			"PortGroup"     = 'VLAN-10'
			"AdminPassword" = 'Pata2Pata1Pata!'
		}

		"WldEsx"       = [ordered]@{
			"Hosts"         = [ordered]@{
				"vcf42-esx05" = [ordered]@{
					"Ip"            = '192.168.10.104'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'vcf42-esx05'
				}

				"vcf42-esx07" = [ordered]@{
					"Ip"            = '192.168.10.106'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'vcf42-esx07'
				}

				"vcf42-esx08" = [ordered]@{
					"Ip"            = '192.168.10.107'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'vcf42-esx08'
				}

				"vcf42-esx06" = [ordered]@{
					"Ip"            = '192.168.10.105'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'vcf42-esx06'
				}

			}

			"CachingvDisk"  = 500
			"Ova"           = './ova/Nested_ESXi8.0u3_Appliance_Template_v1.ova'
			"ESADisk1"      = 500
			"VMNetwork1"    = 'Trunk'
			"vCPU"          = 6
			"BootDisk"      = 32
			"Password"      = 'Pata2Pata1Pata!'
			"CapacityvDisk" = 500
			"Syslog"        = '192.168.1.1'
			"VMNetwork2"    = 'Trunk'
			"ESADisk2"      = 500
			"vMemory"       = 32
		}

		"VMDatacenter" = 'Datacenter'
		"Esx"          = [ordered]@{
			"Hosts"         = [ordered]@{
				"vcf42-esx04" = [ordered]@{
					"Ip"            = '192.168.10.103'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
				}

				"vcf42-esx01" = [ordered]@{
					"Ip"            = '192.168.10.100'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
				}

				"vcf42-esx03" = [ordered]@{
					"Ip"            = '192.168.10.102'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
				}

				"vcf42-esx02" = [ordered]@{
					"Ip"            = '192.168.10.101'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
				}

			}

			"CachingvDisk"  = 500
			"Ova"           = './ova/Nested_ESXi8.0u3_Appliance_Template_v1.ova'
			"ESADisk1"      = 500
			"VMNetwork1"    = 'Trunk'
			"vCPU"          = 12
			"BootDisk"      = 32
			"Password"      = 'Pata2Pata1Pata!'
			"CapacityvDisk" = 500
			"Syslog"        = '192.168.1.1'
			"VMNetwork2"    = 'Trunk'
			"ESADisk2"      = 500
			"vMemory"       = 78
		}

	}

	"Nsxt"                        = [ordered]@{
		"ManagerSize"       = 'small'
		"ipAddressPoolSpec" = [ordered]@{
			"description" = 'ESXi Host Overlay TEP IP Pool'
			"subnets"     = @(
				[ordered]@{
					"cidr"                = '192.168.13.0/24'
					"gateway"             = '192.168.13.254'
					"ipAddressPoolRanges" = @(
						[ordered]@{
							"start" = '192.168.13.1'
							"end"   = '192.168.13.8'
						}

					)
				}

			)
			"name"        = 'sfo01-m01-cl01-tep01'
		}

		"Managers"          = @(
			[ordered]@{
				"ip"       = '192.168.10.212'
				"hostname" = 'sfo-m01-nsx01a'
			}

		)
		"TransportType"     = 'Overlay/VLAN'
		"DvsName"           = 'sfo-m01-cluster-001-vds-001'
		"vipFqdn"           = 'sfo-m01-nsx01'
		"License"           = ''
		"vip"               = '192.168.10.211'
		"Mtu"               = 9000
		"Password"          = [ordered]@{
			"Audit" = 'Pata2Pata1Pata!'
			"Root"  = 'Pata2Pata1Pata!'
			"Admin" = 'Pata2Pata1Pata!'
		}

		"Vmnics"            = @(
			'vmnic0'
			'vmnic1'
		)
		"TransportVlanId"   = 13
	}

	"SkipEsxThumbprintValidation" = $True
	"workflowType"                = 'VCF'
	"FipsEnabled"                 = $False
	"SddcId"                      = 'sfo-m01'
	"Cluster"                     = [ordered]@{
		"EvcMode"      = 'amd-zen'
		"ImageEnabled" = $True
		"Name"         = 'sfo-m01-cluster-001'
	}

	"vSan"                        = [ordered]@{
		"DatastoreName" = 'sfo-m01-cluster-001-vsan'
		"LicenseFile"   = ''
		"HclFile"       = '/home/admin/nested-esxi-vsan-esa-hcl.json'
		"Dedup"         = $True
		"ESA"           = $True
	}

	"Management"                  = [ordered]@{
		"Datacenter" = 'sfo-m01-datacenter'
		"PoolName"   = 'networkpool-001'
	}

	"VCenter"                     = [ordered]@{
		"Hostname"  = 'sfo-m01-vc01'
		"Password"  = [ordered]@{
			"Root"  = 'Pata2Pata1Pata!'
			"Admin" = 'Pata2Pata1Pata!'
		}

		"Size"      = [ordered]@{
			"Vm"      = 'small'
			"Storage" = $null
		}

		"Ip"        = '192.168.10.202'
		"License"   = ''
		"SsoDomain" = 'vsphere.local'
	}

	"DeployWithoutLicenseKeys"    = $True
	"NetworkSpecs"                = [ordered]@{
		"DnsSpec"           = [ordered]@{
			"Subdomain"   = 'vcf.lab.local'
			"NameServers" = '192.168.0.250'
			"Domain"      = 'vcf.lab.local'
		}

		"VmManamegent"      = [ordered]@{
			"vlanId"       = 10
			"subnet"       = '192.168.10.0/24'
			"portGroupKey" = 'SDDC-DPortGroup-VM-Mgmt'
			"gateway"      = '192.168.10.254'
			"mtu"          = 9000
		}

		"NtpServers"        = @(
			'192.168.0.1'
		)
		"vSan"              = [ordered]@{
			"subnet"       = '192.168.12.0/24'
			"portGroupKey" = 'SDDC-DPortGroup-VSAN'
			"Range"        = [ordered]@{
				"Start" = '192.168.12.100'
				"End"   = '192.168.12.10'
			}

			"Mtu"          = 9000
			"gateway"      = '192.168.12.254'
			"vLanId"       = 12
		}

		"vMotionNetwork"    = [ordered]@{
			"subnet"       = '192.168.11.0/24'
			"portGroupKey" = 'SDDC-DPortGroup-vMotion'
			"Range"        = [ordered]@{
				"Start" = '192.168.11.10'
				"End"   = '192.168.11.100'
			}

			"Mtu"          = 9000
			"gateway"      = '192.168.11.254'
			"vLanId"       = 11
		}

		"ManagementNetwork" = [ordered]@{
			"portGroupKey" = 'SDDC-DPortGroup-Mgmt'
			"subnet"       = '192.168.10.0/24'
			"Mtu"          = 9000
			"gateway"      = '192.168.10.254'
			"vLanId"       = 10
		}

	}

	"EsxLicense"                  = ''
	"SddcManager"                 = [ordered]@{
		"Hostname" = [ordered]@{
			"VcfPassword"   = 'Pata2Pata1Pata!'
			"LocalPassword" = 'Pata2Pata1Pata!'
			"Ip"            = '192.168.10.203'
			"Hostname"      = 'sfo-vcf01'
			"RootPassword"  = 'Pata2Pata1Pata!'
		}

	}

	"CeipEnabled"                 = $False
}

