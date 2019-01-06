package kops

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func schemaInstanceGroupSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"role":                         schemaStringInSliceRequired([]string{"Master", "Node", "Bastion"}),
				"machine_type":                 schemaStringOptionalComputed(),
				"image":                        schemaStringOptionalComputed(),
				"min_size":                     schemaIntOptional(),
				"max_size":                     schemaIntOptional(),
				"root_volume_size":             schemaIntOptional(),
				"root_volume_type":             schemaStringOptional(),
				"root_volume_iops":             schemaIntOptional(),
				"root_volume_optimization":     schemaBoolOptional(),
				"subnets":                      schemaStringSliceRequired(),
				"zones":                        schemaStringSliceRequired(),
				"cloud_labels":                 schemaStringMap(),
				"node_labels":                  schemaStringMap(),
				"additional_security_groups":   schemaStringSliceOptional(),
				"additional_user_data":         schemaUserData(),
				"associate_public_ip":          schemaBoolOptional(),
				"detailed_instance_monitoring": schemaBoolOptional(),
				"external_load_balancer":       schemaLoadBalancer(),
				"file_asset":                   schemaFileAsset(),
				"hook":                         schemaHook(),
				"kubelet":                      schemaKubelet(),
			},
		},
	}
}

func schemaKubelet() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"api_servers":                            schemaStringOptionalComputed(),
				"authorization_mode":                     schemaStringOptionalComputed(),
				"allow_privileged":                       schemaBoolOptional(),
				"anonymous_auth":                         schemaBoolOptional(),
				"authentication_token_webhook":           schemaBoolOptional(),
				"authentication_token_webhook_cache_ttl": schemaStringOptionalComputed(),
				"babysit_daemons":                        schemaBoolOptional(),
				"bootstrap_kubeconfig":                   schemaStringOptionalComputed(),
				"cgroup_root":                            schemaStringOptionalComputed(),
				"client_ca_file":                         schemaStringOptionalComputed(),
				"cloud_provider":                         schemaStringOptionalComputed(),
				"cluster_dns":                            schemaStringOptionalComputed(),
				"cluster_domain":                         schemaStringOptionalComputed(),
				"configure_cbr0":                         schemaBoolOptional(),
				"docker_disable_shared_pid":              schemaBoolOptional(),
				"enable_custom_metrics":                  schemaBoolOptional(),
				"enable_debugging_handlers":              schemaBoolOptional(),
				"enforce_node_allocatable":               schemaStringOptionalComputed(),
				"eviction_hard":                          schemaStringOptionalComputed(),
				"eviction_max_pod_grace_period":          schemaIntOptional(),
				"eviction_minimum_reclaim":               schemaStringOptionalComputed(),
				"eviction_pressure_transition_period":    schemaStringOptionalComputed(),
				"eviction_soft":                          schemaStringOptionalComputed(),
				"eviction_soft_grace_period":             schemaStringOptionalComputed(),
				"experimental_allowed_unsafe_sysctls":    schemaStringSliceOptional(),
				"fail_swap_on":                           schemaBoolOptional(),
				"feature_gates":                          schemaStringMap(),
				"hairpin_mode":                           schemaStringOptionalComputed(),
				"hostname_override":                      schemaStringOptionalComputed(),
				"image_gc_high_threshold_percent":        schemaIntOptional(),
				"image_gc_low_threshold_percent":         schemaIntOptional(),
				"image_pull_progress_deadline":           schemaStringOptionalComputed(),
				"kubeconfig_path":                        schemaStringOptionalComputed(),
				"kubelet_cgroups":                        schemaStringOptionalComputed(),
				"kube_reserved":                          schemaStringMap(),
				"kube_reserved_cgroup":                   schemaStringOptionalComputed(),
				"log_level":                              schemaIntOptional(),
				"max_pods":                               schemaIntOptional(),
				"network_plugin_mtu":                     schemaIntOptional(),
				"network_plugin_name":                    schemaStringOptionalComputed(),
				"node_labels":                            schemaStringMap(),
				"node_status_update_frequency":           schemaStringOptionalComputed(),
				"non_masquerade_cidr":                    schemaStringOptionalComputed(),
				"nvidia_gpus":                            schemaIntOptional(),
				"pod_cidr":                               schemaStringOptionalComputed(),
				"pod_infra_container_image":              schemaStringOptionalComputed(),
				"pod_manifest_path":                      schemaStringOptionalComputed(),
				"read_only_port":                         schemaIntOptional(),
				"reconcile_cidr":                         schemaBoolOptional(),
				"register_node":                          schemaBoolOptional(),
				"register_schedulable":                   schemaBoolOptional(),
				"require_kubeconfig":                     schemaBoolOptional(),
				"resolver_config":                        schemaStringOptionalComputed(),
				"root_dir":                               schemaStringOptionalComputed(),
				"runtime_request_timeout":                schemaStringOptionalComputed(),
				"runtime_cgroups":                        schemaStringOptionalComputed(),
				"seccomp_profile_root":                   schemaStringOptionalComputed(),
				"serialize_image_pulls":                  schemaBoolOptional(),
				"streaming_connection_idle_timeout":      schemaStringOptionalComputed(),
				"system_cgroups":                         schemaStringOptionalComputed(),
				"system_reserved":                        schemaStringMap(),
				"system_reserved_cgroup":                 schemaStringOptionalComputed(),
				"taints":                                 schemaStringSliceOptional(),
				"tls_cert_file":                          schemaStringOptionalComputed(),
				"tls_private_key_file":                   schemaStringOptionalComputed(),
				"volume_plugin_directory":                schemaStringOptionalComputed(),
				"volume_stats_agg_period":                schemaStringOptionalComputed(),
			},
		},
	}
}

func schemaUserData() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name":    schemaStringRequired(),
				"type":    schemaStringRequired(),
				"content": schemaStringRequired(),
			},
		},
	}
}

func schemaLoadBalancer() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"load_balancer_name": schemaStringOptional(),
				"target_group_arn":   schemaStringOptional(),
			},
		},
	}
}

func schemaFileAsset() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name":      schemaStringRequired(),
				"path":      schemaStringRequired(),
				"content":   schemaStringRequired(),
				"is_base64": schemaBoolOptional(),
				"roles":     schemaStringSliceRequired(),
			},
		},
	}
}

func schemaHook() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name":           schemaStringRequired(),
				"disabled":       schemaBoolOptional(),
				"manifest":       schemaStringRequired(),
				"before":         schemaStringSliceOptional(),
				"requires":       schemaStringSliceOptional(),
				"roles":          schemaStringSliceRequired(),
				"exec_container": schemaExecContainer(),
			},
		},
	}
}

func schemaExecContainer() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"image":       schemaStringRequired(),
				"command":     schemaStringSliceRequired(),
				"environment": schemaStringMap(),
			},
		},
	}
}
