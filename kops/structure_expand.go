package kops

import (
	"encoding/json"
	"log"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	kopsapi "k8s.io/kops/pkg/apis/kops"
)

func expandObjectMeta(data map[string]interface{}) v1.ObjectMeta {
	meta := v1.ObjectMeta{}
	meta.Name = data["name"].(string)
	timestamp, _ := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", data["creation_timestamp"].(string))
	meta.CreationTimestamp = v1.Time{Time: timestamp}

	s, _ := json.Marshal(meta)
	log.Printf("[DEBUG] Metadata: %s", string(s))

	return meta
}

func expandClusterSpec(data map[string]interface{}) kopsapi.ClusterSpec {
	clusterspec := kopsapi.ClusterSpec{}
	clusterspec.Channel = data["channel"].(string)
	clusterspec.CloudProvider = data["cloud_provider"].(string)
	clusterspec.ClusterDNSDomain = data["cluster_dnsdomain"].(string)
	clusterspec.ConfigBase = data["config_base"].(string)
	clusterspec.ConfigStore = data["config_store"].(string)
	clusterspec.DNSZone = data["dnszone"].(string)
	clusterspec.KeyStore = data["key_store"].(string)
	clusterspec.KubernetesVersion = data["kubernetes_version"].(string)
	clusterspec.MasterInternalName = data["master_internal_name"].(string)
	clusterspec.MasterPublicName = data["master_public_name"].(string)
	clusterspec.NetworkCIDR = data["network_cidr"].(string)
	clusterspec.NetworkID = data["network_id"].(string)
	clusterspec.NonMasqueradeCIDR = data["non_masquerade_cidr"].(string)
	clusterspec.Project = data["project"].(string)
	clusterspec.SecretStore = data["secret_store"].(string)
	clusterspec.ServiceClusterIPRange = data["service_cluster_iprange"].(string)
	clusterspec.SSHKeyName = data["sshkey_name"].(string)

	if top, ok := data["kubernetes_api_access"]; ok {
		clusterspec.KubernetesAPIAccess = expandStringSlice(top)
	}
	if top, ok := data["ssh_access"]; ok {
		clusterspec.SSHAccess = expandStringSlice(top)
	}

	if top, ok := data["subnet"]; ok {
		clusterspec.Subnets = expandClusterSubnetSpec(top.([]interface{}))
	}

	if top, ok := data["networking"]; ok {
		clusterspec.Networking = expandNetworkingSpec(top.([]interface{}))
	}

	if top, ok := data["etcd_cluster"]; ok {
		clusterspec.EtcdClusters = expandEtcdClusterSpec(top.([]interface{}))
	}

	if top, ok := data["topology"]; ok {
		clusterspec.Topology = expandClusterTopology(top.([]interface{}))
	}

	if top, ok := data["additional_policies"]; ok {
		ap := expandStringMap(top)
		clusterspec.AdditionalPolicies = &ap
	}

	spec, _ := json.Marshal(clusterspec)
	log.Printf("[DEBUG] Spec: %s", string(spec))

	return clusterspec
}

func expandStringMap(data interface{}) map[string]string {
	ret := make(map[string]string)
	if data != nil {
		d := data.(map[string]interface{})
		for key, val := range d {
			ret[key] = val.(string)
		}
	}
	return ret
}

func expandStringSlice(data interface{}) []string {
	var ret []string
	if data != nil {
		d := data.([]interface{})
		for _, val := range d {
			ret = append(ret, val.(string))
		}
	}
	return ret
}

func expandClusterTopology(data []interface{}) *kopsapi.TopologySpec {
	if len(data) > 0 {
		topology := &kopsapi.TopologySpec{}
		conv := data[0].(map[string]interface{})
		topology.Masters = conv["masters"].(string)
		topology.Nodes = conv["nodes"].(string)
		topology.Bastion = expandBastionSpec(conv["bastion"].([]interface{}))
		topology.DNS = expandDNSSpec(conv["dns"].([]interface{}))
		return topology
	}
	return nil
}

func expandBastionSpec(data []interface{}) *kopsapi.BastionSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		bastion := &kopsapi.BastionSpec{}
		name := d["bastion_public_name"].(string)
		timeout := int64(d["idle_timeout_seconds"].(int))

		bastion.BastionPublicName = name
		bastion.IdleTimeoutSeconds = &timeout
		return bastion
	}
	return nil
}

func expandDNSSpec(data []interface{}) *kopsapi.DNSSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		dnsSpec := &kopsapi.DNSSpec{}
		switch d["type"].(string) {
		case "Private":
			dnsSpec.Type = kopsapi.DNSTypePrivate
		case "Public":
			dnsSpec.Type = kopsapi.DNSTypePublic
		}
		return dnsSpec
	}
	return nil
}

func expandClusterSubnetSpec(data []interface{}) []kopsapi.ClusterSubnetSpec {
	var subnets []kopsapi.ClusterSubnetSpec
	for _, s := range data {
		conv := s.(map[string]interface{})
		subnets = append(subnets, kopsapi.ClusterSubnetSpec{
			Name: conv["name"].(string),
			CIDR: conv["cidr"].(string),
			Zone: conv["zone"].(string),
			Type: stringToSubnetType(conv["type"].(string)),
		})
	}
	return subnets
}

func stringToSubnetType(s string) kopsapi.SubnetType {
	switch s {
	case "Public":
		return kopsapi.SubnetTypePublic
	case "Private":
		return kopsapi.SubnetTypePrivate
	case "Utility":
		return kopsapi.SubnetTypeUtility
	}
	return kopsapi.SubnetTypePublic
}

func expandNetworkingSpec(data []interface{}) *kopsapi.NetworkingSpec {
	spec := data[0].(map[string]interface{})

	switch spec["name"] {
	case "classic":
		return &kopsapi.NetworkingSpec{
			Classic: &kopsapi.ClassicNetworkingSpec{},
		}
	case "kubenet":
		return &kopsapi.NetworkingSpec{
			Kubenet: &kopsapi.KubenetNetworkingSpec{},
		}
	case "external":
		return &kopsapi.NetworkingSpec{
			External: &kopsapi.ExternalNetworkingSpec{},
		}
	case "cni":
		return &kopsapi.NetworkingSpec{
			CNI: &kopsapi.CNINetworkingSpec{},
		}
	case "kopeio":
		return &kopsapi.NetworkingSpec{
			Kopeio: &kopsapi.KopeioNetworkingSpec{},
		}
	case "weave":
		return &kopsapi.NetworkingSpec{
			Weave: &kopsapi.WeaveNetworkingSpec{},
		}
	case "flannel":
		return &kopsapi.NetworkingSpec{
			Flannel: &kopsapi.FlannelNetworkingSpec{},
		}
	case "calico":
		return &kopsapi.NetworkingSpec{
			Calico: &kopsapi.CalicoNetworkingSpec{},
		}
	case "canal":
		return &kopsapi.NetworkingSpec{
			Canal: &kopsapi.CanalNetworkingSpec{},
		}
	case "kuberouter":
		return &kopsapi.NetworkingSpec{
			Kuberouter: &kopsapi.KuberouterNetworkingSpec{},
		}
	case "romana":
		return &kopsapi.NetworkingSpec{
			Romana: &kopsapi.RomanaNetworkingSpec{},
		}
	case "amazonvpc":
		return &kopsapi.NetworkingSpec{
			AmazonVPC: &kopsapi.AmazonVPCNetworkingSpec{},
		}
	case "cilium":
		return &kopsapi.NetworkingSpec{
			Cilium: &kopsapi.CiliumNetworkingSpec{},
		}
	default:
	}
	return &kopsapi.NetworkingSpec{}
}

func expandEtcdClusterSpec(data []interface{}) []*kopsapi.EtcdClusterSpec {
	var spec []*kopsapi.EtcdClusterSpec

	for _, cluster := range data {
		top := cluster.(map[string]interface{})

		name := top["name"].(string)
		image := top["image"].(string)
		version := top["version"].(string)
		enableTLS := top["enable_etcd_tls"].(bool)
		enableTLSAuth := top["enable_tls_auth"].(bool)

		spec = append(spec, &kopsapi.EtcdClusterSpec{
			Name:          name,
			EnableEtcdTLS: enableTLS,
			EnableTLSAuth: enableTLSAuth,
			Image:         image,
			Version:       version,
			Members:       expandEtcdMemberSpec(top["etcd_member"].([]interface{})),
			Manager:       expandEtcdManagerSpec(top["manager"].([]interface{})),
			Backups:       expandEtcdBackupSpec(top["backups"].([]interface{})),
		})
	}

	return spec
}

func expandEtcdBackupSpec(data []interface{}) *kopsapi.EtcdBackupSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		backup := &kopsapi.EtcdBackupSpec{}
		backup.BackupStore = d["backup_store"].(string)
		backup.Image = d["image"].(string)
		return backup
	}
	return nil
}

func expandEtcdManagerSpec(data []interface{}) *kopsapi.EtcdManagerSpec {
	if len(data) > 0 {
		manager := &kopsapi.EtcdManagerSpec{}
		if len(data) > 0 {
			d := data[0].(map[string]interface{})
			manager.Image = d["image"].(string)
		}
		return manager
	}
	return nil
}

func expandEtcdMemberSpec(data []interface{}) []*kopsapi.EtcdMemberSpec {
	var spec []*kopsapi.EtcdMemberSpec

	for _, d := range data {
		member := d.(map[string]interface{})

		name := member["name"].(string)
		instanceGroup := member["instance_group"].(string)
		volumeType := member["volume_type"].(string)
		volumeIops := int32(member["volume_iops"].(int))
		volumeSize := int32(member["volume_size"].(int))
		kmsKeyID := member["kms_key_id"].(string)
		encryptedVolume := member["encrypted_volume"].(bool)

		spec = append(spec, &kopsapi.EtcdMemberSpec{
			Name:            name,
			InstanceGroup:   &instanceGroup,
			VolumeType:      &volumeType,
			VolumeIops:      &volumeIops,
			VolumeSize:      &volumeSize,
			KmsKeyId:        &kmsKeyID,
			EncryptedVolume: &encryptedVolume,
		})
	}

	return spec
}

func expandInstanceGroupSpec(data map[string]interface{}) kopsapi.InstanceGroupSpec {
	ig := kopsapi.InstanceGroupSpec{}
	ig.Role = expandInstanceGroupRole(data["role"].(string))
	ig.MachineType = data["machine_type"].(string)
	ig.Image = data["image"].(string)
	ig.Subnets = expandStringSlice(data["subnets"])
	ig.Zones = expandStringSlice(data["zones"])
	if rvs, ok := data["root_volume_size"]; ok {
		volumeSize := int32(rvs.(int))
		ig.RootVolumeSize = &volumeSize
	}
	if rvt, ok := data["root_volume_type"]; ok {
		volumeType := rvt.(string)
		ig.RootVolumeType = &volumeType
	}
	if rvi, ok := data["root_volume_iops"]; ok {
		volumeIOPS := int32(rvi.(int))
		ig.RootVolumeIops = &volumeIOPS
	}
	if rvo, ok := data["root_volume_optimization"]; ok {
		volumeOptimization := rvo.(bool)
		ig.RootVolumeOptimization = &volumeOptimization
	}
	if ms, ok := data["min_size"]; ok {
		minSize := int32(ms.(int))
		ig.MinSize = &minSize
	}
	if ms, ok := data["max_size"]; ok {
		maxSize := int32(ms.(int))
		ig.MaxSize = &maxSize
	}
	if cl, ok := data["cloud_labels"]; ok {
		ig.CloudLabels = expandStringMap(cl)
	}
	if nl, ok := data["node_labels"]; ok {
		ig.NodeLabels = expandStringMap(nl)
	}

	ig.AdditionalSecurityGroups = expandStringSlice(data["additional_security_groups"])
	ig.AdditionalUserData = expandAdditionalUserData(data["additional_user_data"].([]interface{}))
	ig.AssociatePublicIP = expandBool(data["associate_public_ip"])
	ig.DetailedInstanceMonitoring = expandBool(data["detailed_instance_monitoring"])
	ig.ExternalLoadBalancers = expandExternalLoadBalancers(data["external_load_balancer"].([]interface{}))
	ig.FileAssets = expandFileAssetSpec(data["file_asset"].([]interface{}))
	ig.Hooks = expandHookSpec(data["hook"].([]interface{}))
	ig.Kubelet = expandKubeletConfigSpec(data["kubelet"].([]interface{}))
	return ig
}

func expandKubeletConfigSpec(data []interface{}) *kopsapi.KubeletConfigSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})

		return &kopsapi.KubeletConfigSpec{
			APIServers:                         d["api_servers"].(string),
			AuthorizationMode:                  d["authorization_mode"].(string),
			AllowPrivileged:                    expandBool(d["allow_privileged"]),
			AnonymousAuth:                      expandBool(d["anonymous_auth"]),
			AuthenticationTokenWebhook:         expandBool(d["authentication_token_webhook"]),
			AuthenticationTokenWebhookCacheTTL: expandDuration(d["authentication_token_webhook_cache_ttl"]),
			BabysitDaemons:                     expandBool(d["babysit_daemons"]),
			BootstrapKubeconfig:                d["bootstrap_kubeconfig"].(string),
			CgroupRoot:                         d["cgroup_root"].(string),
			ClientCAFile:                       d["client_ca_file"].(string),
			CloudProvider:                      d["cloud_provider"].(string),
			ClusterDNS:                         d["cluster_dns"].(string),
			ClusterDomain:                      d["cluster_domain"].(string),
			ConfigureCBR0:                      expandBool(d["configure_cbr0"]),
			DockerDisableSharedPID:             expandBool(d["docker_disable_shared_pid"]),
			EnableCustomMetrics:                expandBool(d["enable_custom_metrics"]),
			EnableDebuggingHandlers:            expandBool(d["enable_debugging_handlers"]),
			EnforceNodeAllocatable:             d["enforce_node_allocatable"].(string),
			EvictionHard:                       expandString(d["eviction_hard"]),
			EvictionMaxPodGracePeriod:          int32(d["eviction_max_pod_grace_period"].(int)),
			EvictionMinimumReclaim:             d["eviction_minimum_reclaim"].(string),
			EvictionPressureTransitionPeriod:   expandDuration(d["eviction_pressure_transition_period"]),
			EvictionSoft:                       d["eviction_soft"].(string),
			EvictionSoftGracePeriod:            d["eviction_soft_grace_period"].(string),
			ExperimentalAllowedUnsafeSysctls:   expandStringSlice(d["experimental_allowed_unsafe_sysctls"]),
			FailSwapOn:                         expandBool(d["fail_swap_on"]),
			FeatureGates:                       expandStringMap(d["feature_gates"]),
			HairpinMode:                        d["hairpin_mode"].(string),
			HostnameOverride:                   d["hostname_override"].(string),
			ImageGCHighThresholdPercent:        expandInt32(d["image_gc_high_threshold_percent"]),
			ImageGCLowThresholdPercent:         expandInt32(d["image_gc_low_threshold_percent"]),
			ImagePullProgressDeadline:          expandDuration(d["image_pull_progress_deadline"]),
			KubeconfigPath:                     d["kubeconfig_path"].(string),
			KubeletCgroups:                     d["kubelet_cgroups"].(string),
			KubeReserved:                       expandStringMap(d["kube_reserved"]),
			KubeReservedCgroup:                 d["kube_reserved_cgroup"].(string),
			LogLevel:                           expandInt32(d["log_level"]),
			MaxPods:                            expandInt32(d["max_pods"]),
			NetworkPluginMTU:                   expandInt32(d["network_plugin_mtu"]),
			NetworkPluginName:                  d["network_plugin_name"].(string),
			NodeLabels:                         expandStringMap(d["node_labels"]),
			NodeStatusUpdateFrequency:          expandDuration(d["node_status_update_frequency"]),
			NonMasqueradeCIDR:                  d["non_masquerade_cidr"].(string),
			NvidiaGPUs:                         *expandInt32(d["nvidia_gpus"]),
			PodCIDR:                            d["pod_cidr"].(string),
			PodInfraContainerImage:             d["pod_infra_container_image"].(string),
			PodManifestPath:                    d["pod_manifest_path"].(string),
			ReadOnlyPort:                       expandInt32(d["read_only_port"]),
			ReconcileCIDR:                      expandBool(d["reconcile_cidr"]),
			RegisterNode:                       expandBool(d["register_node"]),
			RegisterSchedulable:                expandBool(d["register_schedulable"]),
			RequireKubeconfig:                  expandBool(d["require_kubeconfig"]),
			ResolverConfig:                     expandString(d["resolver_config"]),
			RootDir:                            d["root_dir"].(string),
			RuntimeRequestTimeout:              expandDuration(d["runtime_request_timeout"]),
			RuntimeCgroups:                     d["runtime_cgroups"].(string),
			SeccompProfileRoot:                 expandString(d["seccomp_profile_root"]),
			SerializeImagePulls:                expandBool(d["serialize_image_pulls"]),
			StreamingConnectionIdleTimeout:     expandDuration(d["streaming_connection_idle_timeout"]),
			SystemCgroups:                      d["system_cgroups"].(string),
			SystemReserved:                     expandStringMap(d["system_reserved"]),
			SystemReservedCgroup:               d["system_reserved_cgroup"].(string),
			Taints:                             expandStringSlice(d["taints"]),
			TLSCertFile:                        d["tls_cert_file"].(string),
			TLSPrivateKeyFile:                  d["tls_private_key_file"].(string),
			VolumePluginDirectory:              d["volume_plugin_directory"].(string),
			VolumeStatsAggPeriod:               expandDuration(d["volume_stats_agg_period"]),
		}
	}
	return nil
}

func expandInt32(data interface{}) *int32 {
	if data != nil {
		parsed := int32(data.(int))
		return &parsed
	}
	return nil
}

func expandString(data interface{}) *string {
	if data != nil {
		parsed := data.(string)
		return &parsed
	}
	return nil
}

func expandBool(data interface{}) *bool {
	if data != nil {
		parsed := data.(bool)
		return &parsed
	}
	return nil
}

func expandDuration(data interface{}) *v1.Duration {
	if data != nil {
		parsed, _ := time.ParseDuration(data.(string))
		return &v1.Duration{Duration: parsed}
	}
	return nil
}

func expandHookSpec(data []interface{}) []kopsapi.HookSpec {
	var hooks []kopsapi.HookSpec

	for _, d := range data {
		if d != nil {
			hook := d.(map[string]interface{})

			rolesString := expandStringSlice(hook["roles"])
			roles := make([]kopsapi.InstanceGroupRole, len(rolesString))

			for i, role := range rolesString {
				roles[i] = expandInstanceGroupRole(role)
			}

			hooks = append(hooks, kopsapi.HookSpec{
				Name:          hook["name"].(string),
				Disabled:      hook["disabled"].(bool),
				Manifest:      hook["manifest"].(string),
				Before:        expandStringSlice(hook["before"]),
				Requires:      expandStringSlice(hook["requires"]),
				Roles:         roles,
				ExecContainer: expandExecContainerAction(hook["exec_container"].([]interface{})),
			})
		}
	}

	return hooks
}

func expandExecContainerAction(data []interface{}) *kopsapi.ExecContainerAction {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		exec := &kopsapi.ExecContainerAction{
			Image:       d["image"].(string),
			Command:     expandStringSlice(d["command"]),
			Environment: expandStringMap(d["environment"]),
		}

		return exec
	}
	return nil
}

func expandFileAssetSpec(data []interface{}) []kopsapi.FileAssetSpec {
	var fileAssets []kopsapi.FileAssetSpec

	for _, d := range data {
		if d != nil {
			fas := d.(map[string]interface{})
			name := fas["name"].(string)
			path := fas["path"].(string)
			content := fas["content"].(string)
			isBase64 := fas["is_base64"].(bool)
			rolesString := expandStringSlice(fas["roles"])
			roles := make([]kopsapi.InstanceGroupRole, len(rolesString))

			for i, role := range rolesString {
				roles[i] = expandInstanceGroupRole(role)
			}

			fileAssets = append(fileAssets, kopsapi.FileAssetSpec{
				Name:     name,
				Path:     path,
				Content:  content,
				IsBase64: isBase64,
				Roles:    roles,
			})
		}
	}

	return fileAssets
}

func expandExternalLoadBalancers(data []interface{}) []kopsapi.LoadBalancer {
	var loadBalancers []kopsapi.LoadBalancer

	for _, d := range data {
		if d != nil {
			lb := d.(map[string]interface{})
			name := lb["load_balancer_name"].(string)
			target := lb["target_group_arn"].(string)

			loadBalancers = append(loadBalancers, kopsapi.LoadBalancer{
				LoadBalancerName: &name,
				TargetGroupARN:   &target,
			})
		}
	}

	return loadBalancers
}

func expandAdditionalUserData(data []interface{}) []kopsapi.UserData {
	var userData []kopsapi.UserData

	for _, d := range data {
		if d != nil {
			ud := d.(map[string]interface{})
			userData = append(userData, kopsapi.UserData{
				Name:    ud["name"].(string),
				Type:    ud["type"].(string),
				Content: ud["content"].(string),
			})
		}
	}

	return userData
}

func expandInstanceGroupRole(s string) kopsapi.InstanceGroupRole {
	switch s {
	case "Master":
		return kopsapi.InstanceGroupRoleMaster
	case "Node":
		return kopsapi.InstanceGroupRoleNode
	case "Bastion":
		return kopsapi.InstanceGroupRoleBastion
	}

	return kopsapi.InstanceGroupRoleNode
}
