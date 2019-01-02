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
				"machine_type":                 schemaStringOptional(),
				"image":                        schemaStringOptional(),
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
