package kops

import (
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func schemaMetadata() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
					ForceNew: true,
				},
				"creation_timestamp": schemaStringComputed(),
			},
		},
	}
}

func schemaClusterSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"channel":                 schemaStringOptional(),
				"cluster_dnsdomain":       schemaStringOptional(),
				"config_base":             schemaStringOptional(),
				"config_store":            schemaStringOptional(),
				"dnszone":                 schemaStringOptional(),
				"key_store":               schemaStringOptional(),
				"kubernetes_version":      schemaStringRequired(),
				"master_internal_name":    schemaStringOptional(),
				"master_public_name":      schemaStringOptional(),
				"project":                 schemaStringOptional(),
				"secret_store":            schemaStringOptional(),
				"service_cluster_iprange": schemaStringOptional(),
				"sshkey_name":             schemaStringOptional(),
				"network_id":              schemaStringOptional(),
				"network_cidr":            schemaCIDRStringOptional(),
				"networking":              schemaStringInSliceRequired([]string{"canal", "kuberouter"}),
				"non_masquerade_cidr":     schemaCIDRStringOptional(),
				"ssh_access":              schemaStringSliceOptional(),
				"kubernetes_api_access":   schemaStringSliceOptional(),
				"additional_policies":     schemaStringMap(),
				"subnet":                  schemaClusterSubnet(),
				"topology":                schemaClusterTopology(),
				"etcd_cluster":            schemaClusterEtcdCluster(),
			},
		},
	}
}

func schemaClusterSubnet() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": schemaStringRequired(),
				"zone": schemaStringRequired(),
				"cidr": schemaCIDRStringRequired(),
				"type": schemaStringInSliceRequired([]string{"Public", "Private", "Utility"}),
			},
		},
	}
}

func schemaClusterTopology() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"masters": schemaStringOptional(),
				"nodes":   schemaStringOptional(),
				"bastion": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"bastion_public_name":  schemaStringOptional(),
							"idle_timeout_seconds": schemaIntOptional(),
						},
					},
				},
				"dns": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"type": schemaStringInSliceOptional([]string{"Public", "Private"}),
						},
					},
				},
			},
		},
	}
}

func schemaClusterEtcdCluster() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": schemaStringRequired(),
				//"provider": schemaStringInSliceOptional([]string{"Manager", "Legacy"}),
				"etcd_member": {
					Type: schema.TypeList, Required: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name":             schemaStringRequired(),
							"instance_group":   schemaStringRequired(),
							"volume_type":      schemaStringOptional(),
							"kms_key_id":       schemaStringOptional(),
							"volume_iops":      schemaIntOptional(),
							"volume_size":      schemaIntOptional(),
							"encrypted_volume": schemaBoolOptional(),
						},
					},
				},
				"version":                 schemaStringOptional(),
				"image":                   schemaStringOptional(),
				"enable_etcd_tls":         schemaBoolOptional(),
				"enable_tls_auth":         schemaBoolOptional(),
				"leader_election_timeout": schemaIntOptional(),
				"heartbeat_interval":      schemaIntOptional(),
				"backups": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"backup_store": schemaStringOptional(),
							"image":        schemaStringOptional(),
						},
					},
				},
				"manager": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"image": schemaStringOptional(),
						},
					},
				},
			},
		},
	}
}

func schemaStringOptional() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
	}
}

func schemaStringRequired() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
	}
}

func schemaStringComputed() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Computed: true,
	}
}

func schemaCIDRStringRequired() *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.CIDRNetwork(1, 32),
	}
}

func schemaCIDRStringOptional() *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Optional:     true,
		ValidateFunc: validation.CIDRNetwork(1, 32),
	}
}

func schemaStringInSliceRequired(slice []string) *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.StringInSlice(slice, false),
	}
}

func schemaStringInSliceOptional(slice []string) *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Optional:     true,
		ValidateFunc: validation.StringInSlice(slice, false),
	}
}

func schemaIntOptional() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeInt,
		Optional: true,
	}
}

func schemaBoolOptional() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeBool,
		Optional: true,
	}
}

func schemaStringSliceOptional() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem:     &schema.Schema{Type: schema.TypeString},
	}
}

func schemaStringMap() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeMap,
		Optional: true,
	}
}
