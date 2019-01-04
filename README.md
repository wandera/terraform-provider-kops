# terraform-provider-kops - WIP

[![Build Status](https://travis-ci.org/WanderaOrg/terraform-provider-kops.svg?branch=master)](https://travis-ci.org/WanderaOrg/terraform-provider-kops)
[![Go Report Card](https://goreportcard.com/badge/github.com/WanderaOrg/terraform-provider-kops)](https://goreportcard.com/report/github.com/WanderaOrg/terraform-provider-kops)
[![GitHub release](https://img.shields.io/github/release/WanderaOrg/terraform-provider-kops.svg)](https://github.com/WanderaOrg/terraform-provider-kops/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/WanderaOrg/terraform-provider-kops/blob/master/LICENSE)

# Road to 0.0.1-alpha
- [x] Implement kops/v1alpha2/Cluster flattening to TF state
- [x] Implement kops_cluster resource state sync
- [ ] Implement kops/v1alpha2/InstanceGroup flattening to TF state
- [x] Implement kops_instance_group resource state sync
- [ ] Cover flattening/expanding of state by UTs
- [x] Fill in spec defaults using `cloudup` package
- [ ] Deep validate spec using `cloudup` package
- [ ] Run create cluster cmd

# Roadmap
- [ ] Run rolling-update cluster cmd automatically
- [ ] Implement Cluster datasource
- [ ] Implement InstanceGroup datasource
- [ ] Implement Keystore datasource
- [ ] Implement Secretstore datasource
- [ ] Implement SSHSecretstore datasource
- [ ] Add e2e tests

# Usage

### Provider
```hcl
provider "kops" {
  state_store = "s3://cluster-example-state-storage"
}
```

### Cluster
```hcl
resource "kops_cluster" "cluster" {
  metadata {
    name = "cluster.example.com"
  }

  spec {
    cloud_provider      = "aws"
    kubernetes_version  = "1.10.11"

    network_cidr        = "10.0.0.0/16"
    non_masquerade_cidr = "10.0.0.0/16"

    topology {
      dns {
        type = "Public"
      }
    }

    networking {
      name = "kuberouter"
    }

    subnet {
      name = "eu-west-1a"
      cidr = "10.0.10.0/24"
      zone = "eu-west-1a"
      type = "Private"
    }

    subnet {
      name = "eu-west-1b"
      cidr = "10.0.11.0/24"
      zone = "eu-west-1b"
      type = "Private"
    }

    subnet {
      name = "eu-west-1c"
      cidr = "10.0.12.0/24"
      zone = "eu-west-1c"
      type = "Private"
    }

    etcd_cluster {
      name            = "main"
      enable_etcd_tls = "true"
      image           = "k8s.gcr.io/etcd:3.2.14"
      version         = "3.2.14"

      etcd_member {
        name             = "eu-west-1a"
        instance_group   = "master-eu-west-1a"
        encrypted_volume = "true"
      }

      etcd_member {
        name             = "eu-west-1b"
        instance_group   = "master-eu-west-1b"
        encrypted_volume = "true"
      }

      etcd_member {
        name             = "eu-west-1c"
        instance_group   = "master-eu-west-1c"
        encrypted_volume = "true"
      }
    }

    etcd_cluster {
      name            = "event"
      enable_etcd_tls = "true"
      image           = "k8s.gcr.io/etcd:3.2.14"
      version         = "3.2.14"

      etcd_member {
        name             = "eu-west-1a"
        instance_group   = "master-eu-west-1a"
        encrypted_volume = "true"
      }

      etcd_member {
        name             = "eu-west-1b"
        instance_group   = "master-eu-west-1b"
        encrypted_volume = "true"
      }

      etcd_member {
        name             = "eu-west-1c"
        instance_group   = "master-eu-west-1c"
        encrypted_volume = "true"
      }
    }
  }
}
```