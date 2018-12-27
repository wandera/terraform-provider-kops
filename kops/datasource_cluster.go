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
			"state_store": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("KOPS_STATE_STORE", nil),
				Description: descriptions["state_store"],
			},
			"name": {
				Type:     schema.TypeString,
				Computed: true,
				Optional: true,
			},
			"content": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}
