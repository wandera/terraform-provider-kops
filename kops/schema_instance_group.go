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
			},
		},
	}
}
