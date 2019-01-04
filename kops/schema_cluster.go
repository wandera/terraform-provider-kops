package kops

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func schemaClusterSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"channel":                 schemaStringOptionalComputed(),
				"cloud_provider":          schemaStringRequired(),
				"cluster_dnsdomain":       schemaStringOptionalComputed(),
				"config_base":             schemaStringComputed(),
				"config_store":            schemaStringOptionalComputed(),
				"dnszone":                 schemaStringOptionalComputed(),
				"key_store":               schemaStringOptionalComputed(),
				"kubernetes_version":      schemaStringRequired(),
				"master_internal_name":    schemaStringOptionalComputed(),
				"master_public_name":      schemaStringOptionalComputed(),
				"project":                 schemaStringOptional(),
				"secret_store":            schemaStringOptionalComputed(),
				"service_cluster_iprange": schemaStringOptionalComputed(),
				"sshkey_name":             schemaStringOptional(),
				"network_id":              schemaStringOptional(),
				"network_cidr":            schemaCIDRStringOptional(),
				"non_masquerade_cidr":     schemaCIDRStringOptional(),
				"ssh_access":              schemaStringSliceOptional(),
				"kubernetes_api_access":   schemaStringSliceOptional(),
				"additional_policies":     schemaStringMap(),
				"subnet":                  schemaClusterSubnet(),
				"topology":                schemaClusterTopology(),
				"etcd_cluster":            schemaClusterEtcdCluster(),
				"networking":              schemaNetworkingSpec(),
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
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"masters": schemaStringOptionalDefault("public"),
				"nodes":   schemaStringOptionalDefault("public"),
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
					Required: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"type": schemaStringInSliceOptionaDefault([]string{"Public", "Private"}, "Public"),
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

func schemaNetworkingSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": schemaStringRequired(),
			},
		},
	}
}
