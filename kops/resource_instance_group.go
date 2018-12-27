package kops

import (
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceInstanceGroup() *schema.Resource {
	return &schema.Resource{
		Create: resourceInstanceGroupCreate,
		Read:   resourceInstanceGroupRead,
		Update: resourceInstanceGroupUpdate,
		Delete: resourceInstanceGroupDelete,
		Exists: resourceInstanceGroupExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{},
	}
}

func resourceInstanceGroupCreate(d *schema.ResourceData, m interface{}) error {
	return nil
}

func resourceInstanceGroupRead(d *schema.ResourceData, m interface{}) error {
	return nil
}

func resourceInstanceGroupUpdate(d *schema.ResourceData, m interface{}) error {
	return nil
}

func resourceInstanceGroupDelete(d *schema.ResourceData, m interface{}) error {
	return nil
}

func resourceInstanceGroupExists(d *schema.ResourceData, m interface{}) (bool, error) {
	return false, nil
}
