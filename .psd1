[ordered]@{
	"CeipEnabled" = $False
	"Cluster" = 	[ordered]@{
		"EvcMode" = 'amd-zen'
		"ImageEnabled" = $True
		"Name" = 'sfo-m01-cluster-001'
	}

	"DeployWithoutLicenseKeys" = $True
	"EsxLicense" = ''
	"FipsEnabled" = $False
	"Management" = 	[ordered]@{
		"Datacenter" = 'sfo-m01-datacenter'
		"PoolName" = 'networkpool-001'
	}

	"NetworkSpecs" = 	[ordered]@{
		"DnsSpec" = 		[ordered]@{
			"Domain" = 'vcf.lab.local'
			"NameServers" = '192.168.0.250'
			"Subdomain" = 'vcf.lab.local'
		}

		"ManagementNetwork" = 		[ordered]@{
			"gateway" = '192.168.10.254'
			"Mtu" = 9000
			"portGroupKey" = 'SDDC-DPortGroup-Mgmt'
			"subnet" = '192.168.10.0/24'
			"vLanId" = 10
		}

		"NtpServers" = @(
			'192.168.0.1'
		)
		"VmManamegent" = 		[ordered]@{
			"gateway" = '192.168.10.254'
			"mtu" = 9000
			"portGroupKey" = 'SDDC-DPortGroup-VM-Mgmt'
			"subnet" = '192.168.10.0/24'
			"vlanId" = 10
		}

		"vMotionNetwork" = 		[ordered]@{
			"gateway" = '192.168.11.254'
			"Mtu" = 9000
			"portGroupKey" = 'SDDC-DPortGroup-vMotion'
			"Range" = 			[ordered]@{
				"End" = '192.168.11.100'
				"Start" = '192.168.11.10'
			}

			"subnet" = '192.168.11.0/24'
			"vLanId" = 11
		}

		"vSan" = 		[ordered]@{
			"gateway" = '192.168.12.254'
			"Mtu" = 9000
			"portGroupKey" = 'SDDC-DPortGroup-VSAN'
			"Range" = 			[ordered]@{
				"End" = '192.168.12.10'
				"Start" = '192.168.12.100'
			}

			"subnet" = '192.168.12.0/24'
			"vLanId" = 12
		}

	}

	"Nsxt" = 	[ordered]@{
		"DvsName" = 'sfo-m01-cluster-001-vds-001'
		"ipAddressPoolSpec" = 		[ordered]@{
			"description" = 'ESXi Host Overlay TEP IP Pool'
			"name" = 'sfo01-m01-cl01-tep01'
			"subnets" = @(
								[ordered]@{
					"cidr" = '192.168.13.0/24'
					"gateway" = '192.168.13.254'
					"ipAddressPoolRanges" = @(
																[ordered]@{
							"end" = '192.168.13.8'
							"start" = '192.168.13.1'
						}

					)
				}

			)
		}

		"License" = ''
		"Managers" = @(
						[ordered]@{
				"hostname" = 'sfo-m01-nsx01a'
				"ip" = '192.168.10.212'
			}

		)
		"ManagerSize" = 'small'
		"Mtu" = 9000
		"Password" = 		[ordered]@{
			"Admin" = 'Pata2Pata1Pata!'
			"Audit" = 'Pata2Pata1Pata!'
			"Root" = 'Pata2Pata1Pata!'
		}

		"TransportType" = 'Overlay/VLAN'
		"TransportVlanId" = 13
		"vip" = '192.168.10.211'
		"vipFqdn" = 'sfo-m01-nsx01'
		"Vmnics" = @(
			'vmnic0'
			'vmnic1'
		)
	}

	"SddcId" = 'sfo-m01'
	"SddcManager" = 	[ordered]@{
		"Hostname" = 		[ordered]@{
			"Hostname" = 'sfo-vcf01'
			"Ip" = '192.168.10.203'
			"LocalPassword" = 'Pata2Pata1Pata!'
			"RootPassword" = 'Pata2Pata1Pata!'
			"VcfPassword" = 'Pata2Pata1Pata!'
		}

	}

	"SkipEsxThumbprintValidation" = $True
	"VCenter" = 	[ordered]@{
		"Hostname" = 'sfo-m01-vc01'
		"Ip" = '192.168.10.202'
		"License" = ''
		"Password" = 		[ordered]@{
			"Admin" = 'Pata2Pata1Pata!'
			"Root" = 'Pata2Pata1Pata!'
		}

		"Size" = 		[ordered]@{
			"Storage" = $null
			"Vm" = 'small'
		}

		"SsoDomain" = 'vsphere.local'
	}

	"VirtualDeployment" = 	[ordered]@{
		"Cloudbuilder" = 		[ordered]@{
			"AdminPassword" = 'Pata2Pata1Pata!'
			"Hostname" = 'cloudbuilder.vcf.lab.local'
			"Ip" = '192.168.10.195'
			"Ova" = './ova/VMware-Cloud-Builder-5.2.0.0-24108943_OVF10.ova'
			"PortGroup" = 'VLAN-10'
			"RootPassword" = 'Pata2Pata1Pata!'
			"VMName" = 'cloudbuilder'
		}

		"Esx" = 		[ordered]@{
			"BootDisk" = 32
			"CachingvDisk" = 500
			"CapacityvDisk" = 500
			"ESADisk1" = 500
			"ESADisk2" = 500
			"Hosts" = 			[ordered]@{
				"vcf42-esx01" = 				[ordered]@{
					"Ip" = '192.168.10.100'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

				"vcf42-esx02" = 				[ordered]@{
					"Ip" = '192.168.10.101'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

				"vcf42-esx03" = 				[ordered]@{
					"Ip" = '192.168.10.102'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

				"vcf42-esx04" = 				[ordered]@{
					"Ip" = '192.168.10.103'
					"SshThumbprint" = 'SHA256:DUMMY_VALUE'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

			}

			"Ova" = './ova/Nested_ESXi8.0u3_Appliance_Template_v1.ova'
			"Password" = 'Pata2Pata1Pata!'
			"Syslog" = '192.168.1.1'
			"vCPU" = 12
			"vMemory" = 78
			"VMNetwork1" = 'Trunk'
			"VMNetwork2" = 'Trunk'
		}

		"VMCluster" = 'Cluster01'
		"VMDatacenter" = 'Datacenter'
		"VMDatastore" = 'vSanDatastore'
		"VMFolder" = 'VCF'
		"WldEsx" = 		[ordered]@{
			"BootDisk" = 32
			"CachingvDisk" = 500
			"CapacityvDisk" = 500
			"ESADisk1" = 500
			"ESADisk2" = 500
			"Hosts" = 			[ordered]@{
				"vcf42-esx05" = 				[ordered]@{
					"Ip" = '192.168.10.104'
					"SshThumbprint" = 'vcf42-esx05'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

				"vcf42-esx06" = 				[ordered]@{
					"Ip" = '192.168.10.105'
					"SshThumbprint" = 'vcf42-esx06'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

				"vcf42-esx07" = 				[ordered]@{
					"Ip" = '192.168.10.106'
					"SshThumbprint" = 'vcf42-esx07'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

				"vcf42-esx08" = 				[ordered]@{
					"Ip" = '192.168.10.107'
					"SshThumbprint" = 'vcf42-esx08'
					"SslThumbprint" = 'SHA25_DUMMY_VALUE'
				}

			}

			"Ova" = './ova/Nested_ESXi8.0u3_Appliance_Template_v1.ova'
			"Password" = 'Pata2Pata1Pata!'
			"Syslog" = '192.168.1.1'
			"vCPU" = 6
			"vMemory" = 32
			"VMNetwork1" = 'Trunk'
			"VMNetwork2" = 'Trunk'
		}

	}

	"vSan" = 	[ordered]@{
		"DatastoreName" = 'sfo-m01-cluster-001-vsan'
		"Dedup" = $True
		"ESA" = $True
		"HclFile" = '/home/admin/nested-esxi-vsan-esa-hcl.json'
		"LicenseFile" = ''
	}

	"workflowType" = 'VCF'
}

