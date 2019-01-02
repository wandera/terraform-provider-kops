package kops

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	kopsapi "k8s.io/kops/pkg/apis/kops"
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
