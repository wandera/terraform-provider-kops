package kops

import (
	"encoding/json"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	kopsapi "k8s.io/kops/pkg/apis/kops"
	"log"
	"time"
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
		clusterspec.KubernetesAPIAccess = expandStringSlice(top.([]interface{}))
	}
	if top, ok := data["ssh_access"]; ok {
		clusterspec.SSHAccess = expandStringSlice(top.([]interface{}))
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
		clusterspec.AdditionalPolicies = expandStringMap(top.(map[string]interface{}))
	}

	spec, _ := json.Marshal(clusterspec)
	log.Printf("[DEBUG] Spec: %s", string(spec))

	return clusterspec
}

func expandStringMap(data map[string]interface{}) *map[string]string {
	s := make(map[string]string, len(data))
	for key, val := range data {
		s[key] = val.(string)
	}
	return &s
}

func expandStringSlice(data []interface{}) []string {
	s := make([]string, len(data))
	for i, val := range data {
		s[i] = val.(string)
	}
	return s
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
	ig.Subnets = expandStringSlice(data["subnets"].([]interface{}))
	ig.Zones = expandStringSlice(data["zones"].([]interface{}))
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
		ig.CloudLabels = *expandStringMap(cl.(map[string]interface{}))
	}
	if nl, ok := data["node_labels"]; ok {
		ig.NodeLabels = *expandStringMap(nl.(map[string]interface{}))
	}

	ig.AdditionalSecurityGroups = expandStringSlice(data["additional_security_groups"].([]interface{}))
	ig.AdditionalUserData = expandAdditionalUserData(data["additional_user_data"].([]interface{}))
	if api, ok := data["associate_public_ip"]; ok {
		associate := api.(bool)
		ig.AssociatePublicIP = &associate
	}
	if dim, ok := data["detailed_instance_monitoring"]; ok {
		detailed := dim.(bool)
		ig.DetailedInstanceMonitoring = &detailed
	}
	ig.ExternalLoadBalancers = expandExternalLoadBalancers(data["external_load_balancer"].([]interface{}))
	ig.FileAssets = expandFileAssetSpec(data["file_asset"].([]interface{}))
	ig.Hooks = expandHookSpec(data["hook"].([]interface{}))
	return ig
}

func expandHookSpec(data []interface{}) []kopsapi.HookSpec {
	var hooks []kopsapi.HookSpec

	for _, d := range data {
		if d != nil {
			hook := d.(map[string]interface{})

			rolesString := expandStringSlice(hook["roles"].([]interface{}))
			roles := make([]kopsapi.InstanceGroupRole, len(rolesString))

			for i, role := range rolesString {
				roles[i] = expandInstanceGroupRole(role)
			}

			hooks = append(hooks, kopsapi.HookSpec{
				Name:          hook["name"].(string),
				Disabled:      hook["disabled"].(bool),
				Manifest:      hook["manifest"].(string),
				Before:        expandStringSlice(hook["before"].([]interface{})),
				Requires:      expandStringSlice(hook["requires"].([]interface{})),
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
			Command:     expandStringSlice(d["command"].([]interface{})),
			Environment: *expandStringMap(d["environment"].(map[string]interface{})),
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
			rolesString := expandStringSlice(fas["roles"].([]interface{}))
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
