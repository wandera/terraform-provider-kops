package kops

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourceCluster() *schema.Resource {
	return &schema.Resource{
		Read: resourceClusterRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"metadata": schemaMetadata(),
			"spec":     schemaClusterSpec(),
		},
	}
}
