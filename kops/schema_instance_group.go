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
				"role":                     schemaStringInSliceRequired([]string{"Master", "Node", "Bastion"}),
				"image":                    schemaStringOptional(),
				"min_size":                 schemaIntOptional(),
				"max_size":                 schemaIntOptional(),
				"machine_type":             schemaStringOptional(),
				"root_volume_size":         schemaIntOptional(),
				"root_volume_type":         schemaStringOptional(),
				"root_volume_iops":         schemaIntOptional(),
				"root_volume_optimization": schemaBoolOptional(),
				"subnets":                  schemaStringSliceRequired(),
				"zones":                    schemaStringSliceRequired(),
				"cloud_labels":             schemaStringMap(),
				"node_labels":              schemaStringMap(),
			},
		},
	}
}
