package kops

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	kopsapi "k8s.io/kops/pkg/apis/kops"
	"time"
)

func clusterMetadataResourceData(data map[string]interface{}) v1.ObjectMeta {
	meta := v1.ObjectMeta{}
	meta.Name = data["name"].(string)
	timestamp, _ := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", data["creation_timestamp"].(string))
	meta.CreationTimestamp = v1.Time{Time: timestamp}
	return meta
}

func resourceDataClusterMetadata(cluster *kopsapi.Cluster) []map[string]interface{} {
	data := make(map[string]interface{})

	data["name"] = cluster.ObjectMeta.Name
	data["creation_timestamp"] = cluster.ObjectMeta.CreationTimestamp.String()

	return []map[string]interface{}{data}
}

func clusterSpecResourceData(data map[string]interface{}) kopsapi.ClusterSpec {
	clusterspec := kopsapi.ClusterSpec{}
	clusterspec.Channel = data["channel"].(string)
	clusterspec.CloudProvider = "aws"
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

	//clusterspec.SSHAccess = data["ssh_access"].([]string)
	clusterspec.Subnets = clusterSubnetSpecResourceData(data["subnet"].([]interface{}))
	//data["topology"] = resourceDataClusterTopology(clusterspec.Topology)
	//data["kubernetes_api_access"] = clusterspec.KubernetesAPIAccess
	//data["additional_policies"] = *clusterspec.AdditionalPolicies
	//data["etcd_cluster"] = resourceDataClusterEtcdCluster(clusterspec.EtcdClusters)

	return clusterspec
}

func resourceDataClusterSpec(cluster *kopsapi.Cluster) []map[string]interface{} {
	data := make(map[string]interface{})

	data["channel"] = cluster.Spec.Channel
	data["cloud_provider"] = cluster.Spec.CloudProvider
	data["cluster_dnsdomain"] = cluster.Spec.ClusterDNSDomain
	data["config_base"] = cluster.Spec.ConfigBase
	data["config_store"] = cluster.Spec.ConfigStore
	data["dnszone"] = cluster.Spec.DNSZone
	data["key_store"] = cluster.Spec.KeyStore
	data["kubernetes_version"] = cluster.Spec.KubernetesVersion
	data["master_internal_name"] = cluster.Spec.MasterInternalName
	data["master_public_name"] = cluster.Spec.MasterPublicName
	data["network_cidr"] = cluster.Spec.NetworkCIDR
	data["network_id"] = cluster.Spec.NetworkID
	data["non_masquerade_cidr"] = cluster.Spec.NonMasqueradeCIDR
	data["project"] = cluster.Spec.Project
	data["secret_store"] = cluster.Spec.SecretStore
	data["service_cluster_iprange"] = cluster.Spec.ServiceClusterIPRange
	data["sshkey_name"] = cluster.Spec.SSHKeyName
	data["networking"] = resourceDataClusterNetworking(cluster.Spec.Networking)
	data["subnet"] = resourceDataClusterSubnet(cluster.Spec.Subnets)
	data["topology"] = resourceDataClusterTopology(cluster.Spec.Topology)
	data["ssh_access"] = cluster.Spec.SSHAccess
	data["kubernetes_api_access"] = cluster.Spec.KubernetesAPIAccess
	data["additional_policies"] = *cluster.Spec.AdditionalPolicies
	data["etcd_cluster"] = resourceDataClusterEtcdCluster(cluster.Spec.EtcdClusters)

	return []map[string]interface{}{data}
}

func clusterSubnetSpecResourceData(data []interface{}) []kopsapi.ClusterSubnetSpec {
	subnets := make([]kopsapi.ClusterSubnetSpec, len(data))
	for _, s := range data {
		conv := s.(map[string]interface{})
		subnets = append(subnets, kopsapi.ClusterSubnetSpec{
			Name: conv["name"].(string),
			CIDR: conv["cidr"].(string),
			Zone: conv["zone"].(string),
			//Type: s["type"].(string),
		})
	}
	return subnets
}

func resourceDataClusterNetworking(spec interface{}) []map[string]interface{} {
	data := make(map[string]interface{})

	switch spec.(type) {
	case kopsapi.ClassicNetworkingSpec:
		data=""
	case kopsapi.KubenetNetworkingSpec:
		return nil
	case kopsapi.ExternalNetworkingSpec:
		return nil
	case kopsapi.CNINetworkingSpec:
		return nil
	case kopsapi.KopeioNetworkingSpec:
		return nil
	case kopsapi.WeaveNetworkingSpec:
		return nil
	case kopsapi.FlannelNetworkingSpec:
		return nil
	case kopsapi.CalicoNetworkingSpec:
		return nil
	case kopsapi.CanalNetworkingSpec:
		return nil
	case kopsapi.KuberouterNetworkingSpec:
		return nil
	case kopsapi.RomanaNetworkingSpec:
		return nil
	case kopsapi.AmazonVPCNetworkingSpec:
		return nil
	case kopsapi.CiliumNetworkingSpec:
		return nil

	}

	return []map[string]interface{}{data}
}

func resourceDataClusterSubnet(subnets []kopsapi.ClusterSubnetSpec) []map[string]interface{} {
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

func resourceDataClusterTopology(topology *kopsapi.TopologySpec) []map[string]interface{} {
	data := make(map[string]interface{})

	data["masters"] = topology.Masters
	data["nodes"] = topology.Nodes
	if topology.Bastion != nil {
		data["bastion"] = []map[string]interface{}{
			{
				"bastion_public_name":  topology.Bastion.BastionPublicName,
				"idle_timeout_seconds": topology.Bastion.IdleTimeoutSeconds,
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

func resourceDataClusterEtcdCluster(etcdClusters []*kopsapi.EtcdClusterSpec) []map[string]interface{} {
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
				mem["volume_iops"] = *member.VolumeIops
			}
			if member.VolumeSize != nil {
				mem["volume_size"] = *member.VolumeSize
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
