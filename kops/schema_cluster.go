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
				"kube_api_server":         schemaKubeApiServer(),
				"kube_dns":                schemaKubeDNS(),
				"kube_proxy":              schemaKubeProxy(),
				"kube_scheduler":          schemaKubeScheduler(),
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

func schemaKubeApiServer() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"address":                                  schemaStringOptionalComputed(),
				"api_server_count":                         schemaIntOptional(),
				"audit_log_format":                         schemaStringOptionalComputed(),
				"audit_log_max_age":                        schemaIntOptional(),
				"audit_log_max_backups":                    schemaIntOptional(),
				"audit_log_max_size":                       schemaIntOptional(),
				"audit_log_path":                           schemaStringOptionalComputed(),
				"audit_policy_file":                        schemaStringOptionalComputed(),
				"authentication_token_webhook_cache_ttl":   schemaStringOptionalComputed(),
				"authentication_token_webhook_config_file": schemaStringOptionalComputed(),
				"authorization_mode":                       schemaStringOptionalComputed(),
				"authorization_rbac_super_user":            schemaStringOptionalComputed(),
				"allow_privileged":                         schemaBoolOptional(),
				"anonymous_auth":                           schemaBoolOptional(),
				"basic_auth_file":                          schemaStringOptionalComputed(),
				"bind_address":                             schemaStringOptionalComputed(),
				"client_ca_file":                           schemaStringOptionalComputed(),
				"cloud_provider":                           schemaStringOptionalComputed(),
				"disable_admission_plugins":                schemaStringSliceOptional(),
				"enable_admission_plugins":                 schemaStringSliceOptional(),
				"enable_aggregator_routing":                schemaBoolOptional(),
				"enable_bootstrap_auth_token":              schemaBoolOptional(),
				"etcd_ca_file":                             schemaStringOptionalComputed(),
				"etcd_cert_file":                           schemaStringOptionalComputed(),
				"etcd_key_file":                            schemaStringOptionalComputed(),
				"etcd_quorum_read":                         schemaBoolOptional(),
				"etcd_servers":                             schemaStringSliceOptional(),
				"etcd_servers_overrides":                   schemaStringSliceOptional(),
				"experimental_encryption_provider_config":  schemaStringOptionalComputed(),
				"feature_gates":                            schemaStringMap(),
				"insecure_bind_address":                    schemaStringOptionalComputed(),
				"insecure_port":                            schemaIntOptional(),
				"image":                                    schemaStringOptionalComputed(),
				"kubelet_client_certificate":               schemaStringOptionalComputed(),
				"kubelet_client_key":                       schemaStringOptionalComputed(),
				"kubelet_preferred_address_types":          schemaStringSliceOptional(),
				"log_level":                                schemaIntOptional(),
				"max_requests_inflight":                    schemaIntOptional(),
				"mix_request_timeout":                      schemaIntOptional(),
				"oidc_ca_file":                             schemaStringOptionalComputed(),
				"oidc_client_id":                           schemaStringOptionalComputed(),
				"oidc_groups_claim":                        schemaStringOptionalComputed(),
				"oidc_groups_prefix":                       schemaStringOptionalComputed(),
				"oidc_issuer_url":                          schemaStringOptionalComputed(),
				"oidc_username_claim":                      schemaStringOptionalComputed(),
				"oidc_username_prefix":                     schemaStringOptionalComputed(),
				"proxy_client_cert_file":                   schemaStringOptionalComputed(),
				"proxy_client_key_file":                    schemaStringOptionalComputed(),
				"requestheader_allowed_names":              schemaStringSliceOptional(),
				"requestheader_client_ca_file":             schemaStringOptionalComputed(),
				"requestheader_extra_header_prefixes":      schemaStringSliceOptional(),
				"requestheader_group_headers":              schemaStringSliceOptional(),
				"requestheader_username_headers":           schemaStringSliceOptional(),
				"runtime_config":                           schemaStringMap(),
				"secure_port":                              schemaIntOptional(),
				"service_cluster_ip_range":                 schemaStringOptionalComputed(),
				"service_node_port_range":                  schemaStringOptionalComputed(),
				"storage_backend":                          schemaStringOptionalComputed(),
				"tls_cert_file":                            schemaStringOptionalComputed(),
				"tls_private_key_file":                     schemaStringOptionalComputed(),
				"token_auth_file":                          schemaStringOptionalComputed(),
			},
		},
	}
}

func schemaKubeDNS() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"cache_max_concurrent": schemaIntOptional(),
				"cache_max_size":       schemaIntOptional(),
				"domain":               schemaStringOptionalComputed(),
				"image":                schemaStringOptionalComputed(),
				"provider":             schemaStringOptionalComputed(),
				"replicas":             schemaIntOptional(),
				"server_ip":            schemaStringOptionalComputed(),
				"stub_domains":         schemaStringMap(),
				"upstream_nameservers": schemaStringSliceOptional(),
			},
		},
	}
}

func schemaKubeProxy() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"bind_address":           schemaStringOptionalComputed(),
				"conntrack_max_per_core": schemaIntOptional(),
				"conntrack_min":          schemaIntOptional(),
				"cluster_cidr":           schemaStringOptionalComputed(),
				"cpu_limit":              schemaStringOptionalComputed(),
				"cpu_request":            schemaStringOptionalComputed(),
				"enabled":                schemaBoolOptional(),
				"feature_gates":          schemaStringMap(),
				"hostname_override":      schemaStringOptionalComputed(),
				"image":                  schemaStringOptionalComputed(),
				"log_level":              schemaIntOptional(),
				"master":                 schemaStringOptionalComputed(),
				"memory_limit":           schemaStringOptionalComputed(),
				"memory_request":         schemaStringOptionalComputed(),
				"proxy_mode":             schemaStringOptionalComputed(),
			},
		},
	}
}

func schemaKubeScheduler() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"feature_gates":         schemaStringMap(),
				"image":                 schemaStringOptionalComputed(),
				"leader_election":       schemaLeaderElection(),
				"log_level":             schemaIntOptional(),
				"master":                schemaStringOptionalComputed(),
				"use_policy_config_map": schemaBoolOptional(),
			},
		},
	}
}

func schemaLeaderElection() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"leader_elect": schemaBoolOptional(),
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
