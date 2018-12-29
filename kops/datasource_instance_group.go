package kops

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceInstanceGroup() *schema.Resource {
	return &schema.Resource{
		Read: resourceInstanceGroupRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"metadata": schemaMetadata(),
		},
	}
}
