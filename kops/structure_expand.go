package kops

import (
	"encoding/json"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	kopsapi "k8s.io/kops/pkg/apis/kops"
	"log"
	"time"
)

func expandClusterMetadata(data map[string]interface{}) v1.ObjectMeta {
	meta := v1.ObjectMeta{}
	meta.Name = data["name"].(string)
	timestamp, _ := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", data["creation_timestamp"].(string))
	meta.CreationTimestamp = v1.Time{Time: timestamp}
	return meta
}

func expandClusterSpec(data map[string]interface{}) kopsapi.ClusterSpec {
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

	clusterspec.KubernetesAPIAccess = expandStringSlice(data["kubernetes_api_access"].([]interface{}))
	clusterspec.SSHAccess = expandStringSlice(data["ssh_access"].([]interface{}))
	clusterspec.Subnets = expandClusterSubnetSpec(data["subnet"].([]interface{}))
	clusterspec.Networking = expandNetworkingSpec(data["networking"].([]interface{}))
	clusterspec.EtcdClusters = expandEtcdClusterSpec(data["etcd_cluster"].([]interface{}))
	clusterspec.Topology = expandClusterTopology(data["topology"].([]interface{}))
	clusterspec.AdditionalPolicies = expandStringMap(data["additional_policies"].(map[string]interface{}))

	spec, _ := json.Marshal(clusterspec)
	log.Printf("[DEBUG] Object: %s", string(spec))

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
		topology.Bastion = expandBastionSpec(conv["bastion"].(map[string]interface{}))
		topology.DNS = expandDnsSpec(conv["dns"].(map[string]interface{}))
		return topology
	}
	return nil
}

func expandBastionSpec(data map[string]interface{}) *kopsapi.BastionSpec {
	if len(data) > 0 {
		bastion := &kopsapi.BastionSpec{}
		name := data["bastion_public_name"].(string)
		timeout := int64(data["idle_timeout_seconds"].(int))

		bastion.BastionPublicName = name
		bastion.IdleTimeoutSeconds = &timeout
		return bastion
	}
	return nil
}

func expandDnsSpec(data map[string]interface{}) *kopsapi.DNSSpec {
	if len(data) > 0 {
		dnsSpec := &kopsapi.DNSSpec{}
		switch data["type"].(string) {
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
		enableTls := top["enable_etcd_tls"].(bool)
		enableTlsAuth := top["enable_tls_auth"].(bool)

		spec = append(spec, &kopsapi.EtcdClusterSpec{
			Name:          name,
			EnableEtcdTLS: enableTls,
			EnableTLSAuth: enableTlsAuth,
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
	backup := &kopsapi.EtcdBackupSpec{}
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		backup.BackupStore = d["backup_store"].(string)
		backup.Image = d["image"].(string)
	}
	return backup
}

func expandEtcdManagerSpec(data []interface{}) *kopsapi.EtcdManagerSpec {
	manager := &kopsapi.EtcdManagerSpec{}
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		manager.Image = d["image"].(string)
	}
	return manager
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
		kmsKeyId := member["kms_key_id"].(string)
		encryptedVolume := member["encrypted_volume"].(bool)

		spec = append(spec, &kopsapi.EtcdMemberSpec{
			Name:            name,
			InstanceGroup:   &instanceGroup,
			VolumeType:      &volumeType,
			VolumeIops:      &volumeIops,
			VolumeSize:      &volumeSize,
			KmsKeyId:        &kmsKeyId,
			EncryptedVolume: &encryptedVolume,
		})
	}

	return spec
}