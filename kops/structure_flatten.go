package kops

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	kopsapi "k8s.io/kops/pkg/apis/kops"
	"strings"
)

func flattenObjectMeta(cluster v1.ObjectMeta) []map[string]interface{} {
	data := make(map[string]interface{})

	data["name"] = cluster.Name
	data["creation_timestamp"] = cluster.CreationTimestamp.String()

	return []map[string]interface{}{data}
}

func flattenClusterSpec(cluster kopsapi.ClusterSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	data["channel"] = cluster.Channel
	data["cloud_provider"] = cluster.CloudProvider
	data["cluster_dnsdomain"] = cluster.ClusterDNSDomain
	data["config_base"] = cluster.ConfigBase
	data["config_store"] = cluster.ConfigStore
	data["dnszone"] = cluster.DNSZone
	data["key_store"] = cluster.KeyStore
	if cluster.KubeAPIServer != nil {
		data["kube_api_server"] = flattenKubeApiServer(cluster.KubeAPIServer)
	}
	if cluster.KubeDNS != nil {
		data["kube_dns"] = flattenKubeDNS(cluster.KubeDNS)
	}
	if cluster.KubeProxy != nil {
		data["kube_proxy"] = flattenKubeProxy(cluster.KubeProxy)
	}
	if cluster.KubeScheduler != nil {
		data["kube_scheduler"] = flattenKubeScheduler(cluster.KubeScheduler)
	}
	data["kubernetes_version"] = cluster.KubernetesVersion
	data["master_internal_name"] = cluster.MasterInternalName
	data["master_public_name"] = cluster.MasterPublicName
	data["network_cidr"] = cluster.NetworkCIDR
	data["network_id"] = cluster.NetworkID
	data["non_masquerade_cidr"] = cluster.NonMasqueradeCIDR
	data["project"] = cluster.Project
	data["secret_store"] = cluster.SecretStore
	data["service_cluster_iprange"] = cluster.ServiceClusterIPRange
	data["sshkey_name"] = cluster.SSHKeyName
	data["networking"] = flattenNetworkingSpec(cluster.Networking)
	data["subnet"] = flattenClusterSubnet(cluster.Subnets)
	if cluster.Topology != nil {
		data["topology"] = flattenClusterTopology(cluster.Topology)
	}
	data["ssh_access"] = cluster.SSHAccess
	data["kubernetes_api_access"] = cluster.KubernetesAPIAccess
	data["additional_policies"] = *cluster.AdditionalPolicies
	data["etcd_cluster"] = flattenEtcdClusterSpec(cluster.EtcdClusters)

	return []map[string]interface{}{data}
}

func flattenKubeApiServer(api *kopsapi.KubeAPIServerConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["address"] = api.Address
	if api.APIServerCount != nil {
		data["api_server_count"] = *api.APIServerCount
	}
	if api.AuditLogFormat != nil {
		data["audit_log_format"] = *api.AuditLogFormat
	}
	if api.AuditLogMaxAge != nil {
		data["audit_log_max_age"] = *api.AuditLogMaxAge
	}
	if api.AuditLogMaxBackups != nil {
		data["audit_log_max_backups"] = *api.AuditLogMaxBackups
	}
	if api.AuditLogMaxSize != nil {
		data["audit_log_max_size"] = *api.AuditLogMaxSize
	}
	if api.AuditLogPath != nil {
		data["audit_log_path"] = *api.AuditLogPath
	}
	data["audit_policy_file"] = api.AuditPolicyFile
	if api.AuthenticationTokenWebhookCacheTTL != nil {
		data["authentication_token_webhook_cache_ttl"] = *api.AuthenticationTokenWebhookCacheTTL
	}
	if api.AuthenticationTokenWebhookConfigFile != nil {
		data["authentication_token_webhook_config_file"] = *api.AuthenticationTokenWebhookConfigFile
	}
	if api.AuthorizationMode != nil {
		data["authorization_mode"] = *api.AuthorizationMode
	}
	if api.AuthorizationRBACSuperUser != nil {
		data["authorization_rbac_super_user"] = *api.AuthorizationRBACSuperUser
	}
	if api.AllowPrivileged != nil {
		data["allow_privileged"] = *api.AllowPrivileged
	}
	if api.AnonymousAuth != nil {
		data["anonymous_auth"] = *api.AnonymousAuth
	}
	data["basic_auth_file"] = api.BasicAuthFile
	data["bind_address"] = api.BindAddress
	data["client_ca_file"] = api.ClientCAFile
	data["cloud_provider"] = api.CloudProvider
	data["disable_admission_plugins"] = api.DisableAdmissionPlugins
	data["enable_admission_plugins"] = api.EnableAdmissionPlugins
	if api.EnableAggregatorRouting != nil {
		data["enable_aggregator_routing"] = *api.EnableAggregatorRouting
	}
	if api.EnableBootstrapAuthToken != nil {
		data["enable_bootstrap_auth_token"] = *api.EnableBootstrapAuthToken
	}
	data["etcd_ca_file"] = api.EtcdCAFile
	data["etcd_cert_file"] = api.EtcdCertFile
	data["etcd_key_file"] = api.EtcdKeyFile
	if api.EtcdQuorumRead != nil {
		data["etcd_quorum_read"] = *api.EtcdQuorumRead
	}
	data["etcd_servers"] = api.EtcdServers
	data["etcd_servers_overrides"] = api.EtcdServersOverrides
	if api.ExperimentalEncryptionProviderConfig != nil {
		data["experimental_encryption_provider_config"] = *api.ExperimentalEncryptionProviderConfig
	}
	data["feature_gates"] = api.FeatureGates
	data["insecure_bind_address"] = api.InsecureBindAddress
	data["insecure_port"] = int(api.InsecurePort)
	data["image"] = api.Image
	data["kubelet_client_certificate"] = api.KubeletClientCertificate
	data["kubelet_client_key"] = api.KubeletClientKey
	data["kubelet_preferred_address_types"] = api.KubeletPreferredAddressTypes
	data["log_level"] = int(api.LogLevel)
	data["max_requests_inflight"] = int(api.MaxRequestsInflight)
	if api.MinRequestTimeout != nil {
		data["mix_request_timeout"] = int(*api.MinRequestTimeout)
	}
	if api.OIDCCAFile != nil {
		data["oidc_ca_file"] = *api.OIDCCAFile
	}
	if api.OIDCClientID != nil {
		data["oidc_client_id"] = *api.OIDCClientID
	}
	if api.OIDCGroupsClaim != nil {
		data["oidc_groups_claim"] = *api.OIDCGroupsClaim
	}
	if api.OIDCGroupsPrefix != nil {
		data["oidc_groups_prefix"] = *api.OIDCGroupsPrefix
	}
	if api.OIDCIssuerURL != nil {
		data["oidc_issuer_url"] = *api.OIDCIssuerURL
	}
	if api.OIDCUsernameClaim != nil {
		data["oidc_username_claim"] = *api.OIDCUsernameClaim
	}
	if api.OIDCUsernamePrefix != nil {
		data["oidc_username_prefix"] = *api.OIDCUsernamePrefix
	}
	if api.ProxyClientCertFile != nil {
		data["proxy_client_cert_file"] = *api.ProxyClientCertFile
	}
	if api.ProxyClientKeyFile != nil {
		data["proxy_client_key_file"] = *api.ProxyClientKeyFile
	}
	data["requestheader_allowed_names"] = api.RequestheaderAllowedNames
	data["requestheader_client_ca_file"] = api.RequestheaderClientCAFile
	data["requestheader_extra_header_prefixes"] = api.RequestheaderExtraHeaderPrefixes
	data["requestheader_group_headers"] = api.RequestheaderGroupHeaders
	data["requestheader_username_headers"] = api.RequestheaderUsernameHeaders
	data["runtime_config"] = api.RuntimeConfig
	data["secure_port"] = int(api.SecurePort)
	data["service_cluster_ip_range"] = api.ServiceClusterIPRange
	data["service_node_port_range"] = api.ServiceNodePortRange
	if api.StorageBackend != nil {
		data["storage_backend"] = *api.StorageBackend
	}
	data["tls_cert_file"] = api.TLSCertFile
	data["tls_private_key_file"] = api.TLSPrivateKeyFile
	data["token_auth_file"] = api.TokenAuthFile
	return []map[string]interface{}{data}
}

func flattenKubeDNS(dns *kopsapi.KubeDNSConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["cache_max_concurrent"] = dns.CacheMaxConcurrent
	data["cache_max_size"] = dns.CacheMaxSize
	data["domain"] = dns.Domain
	data["image"] = dns.Image
	data["provider"] = dns.Provider
	data["replicas"] = dns.Replicas
	data["server_ip"] = dns.ServerIP
	data["stub_domains"] = flattenStubDomains(dns.StubDomains)
	data["upstream_nameservers"] = dns.UpstreamNameservers
	return []map[string]interface{}{data}
}

func flattenStubDomains(domains map[string][]string) map[string]interface{} {
	data := make(map[string]interface{})
	for key, val := range domains {
		data[key] = strings.Join(val, ",")
	}
	return data
}

func flattenKubeProxy(proxy *kopsapi.KubeProxyConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["bind_address"] = proxy.BindAddress
	if proxy.ConntrackMaxPerCore != nil {
		data["conntrack_max_per_core"] = proxy.ConntrackMaxPerCore
	}
	if proxy.ConntrackMin != nil {
		data["conntrack_min"] = proxy.ConntrackMin
	}
	data["cluster_cidr"] = proxy.ClusterCIDR
	data["cpu_limit"] = proxy.CPULimit
	data["cpu_request"] = proxy.CPURequest
	if proxy.Enabled != nil {
		data["enabled"] = proxy.Enabled
	}
	data["feature_gates"] = proxy.FeatureGates
	data["hostname_override"] = proxy.HostnameOverride
	data["image"] = proxy.Image
	data["log_level"] = proxy.LogLevel
	data["master"] = proxy.Master
	data["memory_limit"] = proxy.MemoryLimit
	data["memory_request"] = proxy.MemoryRequest
	data["proxy_mode"] = proxy.ProxyMode
	return []map[string]interface{}{data}
}

func flattenKubeScheduler(scheduler *kopsapi.KubeSchedulerConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["feature_gates"] = scheduler.FeatureGates
	data["image"] = scheduler.Image
	if scheduler.LeaderElection != nil {
		data["leader_election"] = flattenLeaderElection(scheduler.LeaderElection)
	}
	data["log_level"] = int(scheduler.LogLevel)
	data["master"] = scheduler.Master
	if scheduler.UsePolicyConfigMap != nil {
		data["use_policy_config_map"] = *scheduler.UsePolicyConfigMap
	}
	return []map[string]interface{}{data}
}

func flattenLeaderElection(leader *kopsapi.LeaderElectionConfiguration) []map[string]interface{} {
	data := make(map[string]interface{})
	if leader.LeaderElect != nil {
		data["leader_elect"] = *leader.LeaderElect
	}
	return []map[string]interface{}{data}
}

func flattenNetworkingSpec(spec *kopsapi.NetworkingSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	if spec.Classic != nil {
		data["name"] = "classic"
	}
	if spec.Kubenet != nil {
		data["name"] = "kubenet"
	}
	if spec.External != nil {
		data["name"] = "external"
	}
	if spec.CNI != nil {
		data["name"] = "cni"
	}
	if spec.Kopeio != nil {
		data["name"] = "kopeio"
	}
	if spec.Weave != nil {
		data["name"] = "weave"
	}
	if spec.Flannel != nil {
		data["name"] = "flannel"
	}
	if spec.Calico != nil {
		data["name"] = "calico"
	}
	if spec.Canal != nil {
		data["name"] = "canal"
	}
	if spec.Kuberouter != nil {
		data["name"] = "kuberouter"
	}
	if spec.Romana != nil {
		data["name"] = "romana"
	}
	if spec.AmazonVPC != nil {
		data["name"] = "amazonvpc"
	}
	if spec.Cilium != nil {
		data["name"] = "cilium"
	}

	return []map[string]interface{}{data}
}

func flattenClusterSubnet(subnets []kopsapi.ClusterSubnetSpec) []map[string]interface{} {
	var data []map[string]interface{}
	for _, subnet := range subnets {
		data = append(data, map[string]interface{}{
			"name": subnet.Name,
			"cidr": subnet.CIDR,
			"zone": subnet.Zone,
			"type": string(subnet.Type),
		})
	}
	return data
}

func flattenClusterTopology(topology *kopsapi.TopologySpec) []map[string]interface{} {
	data := make(map[string]interface{})
	data["masters"] = topology.Masters
	data["nodes"] = topology.Nodes
	if topology.Bastion != nil {
		data["bastion"] = []map[string]interface{}{
			{
				"bastion_public_name":  topology.Bastion.BastionPublicName,
				"idle_timeout_seconds": int(*topology.Bastion.IdleTimeoutSeconds),
			},
		}
	}
	data["dns"] = []map[string]interface{}{
		{
			"type": topology.DNS.Type,
		},
	}
	return []map[string]interface{}{data}
}

func flattenEtcdClusterSpec(etcdClusters []*kopsapi.EtcdClusterSpec) []map[string]interface{} {
	var data []map[string]interface{}

	for _, cluster := range etcdClusters {
		cl := make(map[string]interface{})

		cl["name"] = cluster.Name

		//if cluster.Provider != nil {
		//	cl["provider"] = cluster.Provider
		//}

		// build etcd_members
		var members []map[string]interface{}
		for _, member := range cluster.Members {
			mem := make(map[string]interface{})
			mem["name"] = member.Name
			mem["instance_group"] = *member.InstanceGroup
			if member.VolumeType != nil {
				mem["volume_type"] = *member.VolumeType
			}
			if member.VolumeIops != nil {
				mem["volume_iops"] = int(*member.VolumeIops)
			}
			if member.VolumeSize != nil {
				mem["volume_size"] = int(*member.VolumeSize)
			}
			if member.KmsKeyId != nil {
				mem["kms_key_id"] = *member.KmsKeyId
			}
			if member.EncryptedVolume != nil {
				mem["encrypted_volume"] = *member.EncryptedVolume
			}
			members = append(members, mem)
		}
		cl["etcd_member"] = members

		cl["enable_etcd_tls"] = cluster.EnableEtcdTLS
		cl["enable_tls_auth"] = cluster.EnableTLSAuth
		cl["version"] = cluster.Version
		if cluster.LeaderElectionTimeout != nil {
			cl["leader_election_timeout"] = cluster.LeaderElectionTimeout
		}
		if cluster.HeartbeatInterval != nil {
			cl["heartbeat_interval"] = cluster.HeartbeatInterval
		}
		cl["image"] = cluster.Image
		if cluster.Backups != nil {
			cl["backups"] = []map[string]interface{}{
				{
					"backup_store": cluster.Backups.BackupStore,
					"image":        cluster.Backups.Image,
				},
			}
		}
		if cluster.Manager != nil {
			cl["manager"] = []map[string]interface{}{
				{
					"image": cluster.Manager.Image,
				},
			}
		}

		data = append(data, cl)
	}

	return data
}

func flattenInstanceGroupSpec(ig kopsapi.InstanceGroupSpec) []map[string]interface{} {
	data := make(map[string]interface{})
	data["role"] = ig.Role
	data["machine_type"] = ig.MachineType
	data["image"] = ig.Image
	data["subnets"] = ig.Subnets
	data["zones"] = ig.Zones
	if ig.RootVolumeSize != nil {
		data["root_volume_size"] = *ig.RootVolumeSize
	}
	if ig.RootVolumeType != nil {
		data["root_volume_type"] = *ig.RootVolumeType
	}
	if ig.RootVolumeIops != nil {
		data["root_volume_iops"] = *ig.RootVolumeIops
	}
	if ig.RootVolumeOptimization != nil {
		data["root_volume_optimization"] = *ig.RootVolumeOptimization
	}
	if ig.MinSize != nil {
		data["min_size"] = *ig.MinSize
	}
	if ig.MaxSize != nil {
		data["max_size"] = *ig.MaxSize
	}
	data["cloud_labels"] = ig.CloudLabels
	data["node_labels"] = ig.NodeLabels
	data["additional_security_groups"] = ig.AdditionalSecurityGroups
	data["additional_user_data"] = flattenAdditionalUserData(ig.AdditionalUserData)
	if ig.AssociatePublicIP != nil {
		data["associate_public_ip"] = *ig.AssociatePublicIP
	}
	if ig.DetailedInstanceMonitoring != nil {
		data["detailed_instance_monitoring"] = *ig.DetailedInstanceMonitoring
	}
	data["external_load_balancer"] = flattenExternalLoadBalancer(ig.ExternalLoadBalancers)
	data["file_asset"] = flattenFileAsset(ig.FileAssets)
	data["hook"] = flattenHook(ig.Hooks)
	data["kubelet"] = flattenKubeletSpec(ig.Kubelet)
	return []map[string]interface{}{data}
}

func flattenKubeletSpec(spec *kopsapi.KubeletConfigSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	if spec != nil {
		data["api_servers"] = spec.APIServers
		data["authorization_mode"] = spec.AuthorizationMode
		if spec.AllowPrivileged != nil {
			data["allow_privileged"] = *spec.AllowPrivileged
		}
		if spec.AnonymousAuth != nil {
			data["anonymous_auth"] = *spec.AnonymousAuth
		}
		if spec.AuthenticationTokenWebhook != nil {
			data["authentication_token_webhook"] = *spec.AuthenticationTokenWebhook
		}
		if spec.AuthenticationTokenWebhookCacheTTL != nil {
			data["authentication_token_webhook_cache_ttl"] = spec.AuthenticationTokenWebhookCacheTTL.Duration.String()
		}
		if spec.BabysitDaemons != nil {
			data["babysit_daemons"] = *spec.BabysitDaemons
		}
		data["bootstrap_kubeconfig"] = spec.BootstrapKubeconfig
		data["cgroup_root"] = spec.CgroupRoot
		data["client_ca_file"] = spec.ClientCAFile
		data["cloud_provider"] = spec.CloudProvider
		data["cluster_dns"] = spec.ClusterDNS
		data["cluster_domain"] = spec.ClusterDomain
		if spec.ConfigureCBR0 != nil {
			data["configure_cbr0"] = *spec.ConfigureCBR0
		}
		if spec.DockerDisableSharedPID != nil {
			data["docker_disable_shared_pid"] = *spec.DockerDisableSharedPID
		}
		if spec.EnableCustomMetrics != nil {
			data["enable_custom_metrics"] = *spec.EnableCustomMetrics
		}
		if spec.EnableDebuggingHandlers != nil {
			data["enable_debugging_handlers"] = *spec.EnableDebuggingHandlers
		}
		data["enforce_node_allocatable"] = spec.EnforceNodeAllocatable
		if spec.EvictionHard != nil {
			data["eviction_hard"] = *spec.EvictionHard
		}
		data["eviction_max_pod_grace_period"] = spec.EvictionMaxPodGracePeriod
		data["eviction_minimum_reclaim"] = spec.EvictionMinimumReclaim
		if spec.EvictionPressureTransitionPeriod != nil {
			data["eviction_pressure_transition_period"] = spec.EvictionPressureTransitionPeriod.Duration.String()
		}

		data["eviction_soft"] = spec.EvictionSoft
		data["eviction_soft_grace_period"] = spec.EvictionSoftGracePeriod
		data["experimental_allowed_unsafe_sysctls"] = spec.ExperimentalAllowedUnsafeSysctls
		if spec.FailSwapOn != nil {
			data["fail_swap_on"] = *spec.FailSwapOn
		}

		data["feature_gates"] = spec.FeatureGates
		data["hairpin_mode"] = spec.HairpinMode
		data["hostname_override"] = spec.HostnameOverride
		if spec.ImageGCHighThresholdPercent != nil {
			data["image_gc_high_threshold_percent"] = int(*spec.ImageGCHighThresholdPercent)
		}
		if spec.ImageGCLowThresholdPercent != nil {
			data["image_gc_low_threshold_percent"] = int(*spec.ImageGCLowThresholdPercent)
		}
		if spec.ImagePullProgressDeadline != nil {
			data["image_pull_progress_deadline"] = spec.ImagePullProgressDeadline.Duration.String()
		}
		data["kubeconfig_path"] = spec.KubeconfigPath
		data["kubelet_cgroups"] = spec.KubeletCgroups
		data["kube_reserved"] = spec.KubeReserved
		data["kube_reserved_cgroup"] = spec.KubeReservedCgroup
		if spec.LogLevel != nil {
			data["log_level"] = int(*spec.LogLevel)
		}
		if spec.MaxPods != nil {
			data["max_pods"] = int(*spec.MaxPods)
		}
		if spec.NetworkPluginMTU != nil {
			data["network_plugin_mtu"] = int(*spec.NetworkPluginMTU)
		}

		data["network_plugin_name"] = spec.NetworkPluginName

		data["node_labels"] = spec.NodeLabels
		if spec.NodeStatusUpdateFrequency != nil {
			data["node_status_update_frequency"] = spec.NodeStatusUpdateFrequency.Duration.String()
		}
		data["non_masquerade_cidr"] = spec.NonMasqueradeCIDR
		data["nvidia_gpus"] = spec.NvidiaGPUs

		data["pod_cidr"] = spec.PodCIDR
		data["pod_infra_container_image"] = spec.PodInfraContainerImage
		data["pod_manifest_path"] = spec.PodManifestPath
		if spec.ReadOnlyPort != nil {
			data["read_only_port"] = int(*spec.ReadOnlyPort)
		}
		if spec.ReconcileCIDR != nil {
			data["reconcile_cidr"] = *spec.ReconcileCIDR
		}
		if spec.RegisterNode != nil {
			data["register_node"] = *spec.RegisterNode
		}
		if spec.RegisterSchedulable != nil {
			data["register_schedulable"] = *spec.RegisterSchedulable
		}
		if spec.RequireKubeconfig != nil {
			data["require_kubeconfig"] = *spec.RequireKubeconfig
		}
		if spec.ResolverConfig != nil {
			data["resolver_config"] = *spec.ResolverConfig
		}
		data["root_dir"] = spec.RootDir
		if spec.RuntimeRequestTimeout != nil {
			data["runtime_request_timeout"] = spec.RuntimeRequestTimeout.Duration.String()
		}
		data["runtime_cgroups"] = spec.RuntimeCgroups
		if spec.SeccompProfileRoot != nil {
			data["seccomp_profile_root"] = *spec.SeccompProfileRoot
		}
		if spec.SerializeImagePulls != nil {
			data["serialize_image_pulls"] = *spec.SerializeImagePulls
		}
		if spec.StreamingConnectionIdleTimeout != nil {
			data["streaming_connection_idle_timeout"] = spec.StreamingConnectionIdleTimeout.Duration.String()
		}
		data["system_cgroups"] = spec.SystemCgroups
		data["system_reserved"] = spec.SystemReserved
		data["system_reserved_cgroup"] = spec.SystemReservedCgroup
		data["taints"] = spec.Taints
		data["tls_cert_file"] = spec.TLSCertFile
		data["tls_private_key_file"] = spec.TLSPrivateKeyFile
		data["volume_plugin_directory"] = spec.VolumePluginDirectory
		if spec.VolumeStatsAggPeriod != nil {
			data["volume_stats_agg_period"] = spec.VolumeStatsAggPeriod.Duration.String()
		}
	}

	return []map[string]interface{}{data}
}

func flattenHook(specs []kopsapi.HookSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, hook := range specs {
		data["name"] = hook.Name
		data["disabled"] = hook.Disabled
		data["manifest"] = hook.Manifest
		data["before"] = hook.Before
		data["requires"] = hook.Requires

		roles := make([]string, len(hook.Roles))
		for i, role := range hook.Roles {
			roles[i] = string(role)
		}

		data["roles"] = roles
		data["exec_container"] = flattenExecContainerSpec(hook.ExecContainer)
	}

	return []map[string]interface{}{data}
}

func flattenExecContainerSpec(action *kopsapi.ExecContainerAction) interface{} {
	data := make(map[string]interface{})

	if action != nil {
		data["image"] = action.Image
		data["command"] = action.Command
		data["environment"] = action.Environment
	}

	return []map[string]interface{}{data}
}

func flattenAdditionalUserData(ud []kopsapi.UserData) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, userData := range ud {
		data["name"] = userData.Name
		data["type"] = userData.Type
		data["content"] = userData.Content
	}

	return []map[string]interface{}{data}
}

func flattenExternalLoadBalancer(bl []kopsapi.LoadBalancer) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, balancer := range bl {
		data["load_balancer_name"] = *balancer.LoadBalancerName
		data["target_group_arn"] = *balancer.TargetGroupARN
	}

	return []map[string]interface{}{data}
}

func flattenFileAsset(specs []kopsapi.FileAssetSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, fa := range specs {
		data["name"] = fa.Name
		data["path"] = fa.Path
		data["content"] = fa.Content
		data["is_base64"] = fa.IsBase64
		data["roles"] = fa.Roles
	}

	return []map[string]interface{}{data}
}
