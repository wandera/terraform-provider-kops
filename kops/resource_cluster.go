package kops

import (
	"github.com/hashicorp/terraform/helper/schema"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/kops/pkg/apis/kops"
)

func resourceCluster() *schema.Resource {
	return &schema.Resource{
		Create: resourceClusterCreate,
		Read:   resourceClusterRead,
		Update: resourceClusterUpdate,
		Delete: resourceClusterDelete,
		Exists: resourceClusterExists,
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
			"metadata": schemaMetadata(),
			"spec":     schemaClusterSpec(),
		},
	}
}

func resourceClusterCreate(d *schema.ResourceData, m interface{}) error {
	clientset, err := GetClientset(d.Get("state_store").(string))
	if err != nil {
		return err
	}

	cluster, err := clientset.CreateCluster(&kops.Cluster{
		ObjectMeta: clusterMetadataResourceData(sectionData(d, "metadata")),
		Spec:       clusterSpecResourceData(sectionData(d, "spec")),
	})

	if err != nil {
		return err
	}

	if err := d.Set("metadata", resourceDataClusterMetadata(cluster)); err != nil {
		return err
	}
	if err := d.Set("spec", resourceDataClusterSpec(cluster)); err != nil {
		return err
	}
	return nil
}

func sectionData(d *schema.ResourceData, section string) map[string]interface{} {
	return d.Get(section).([]interface{})[0].(map[string]interface{})
}

func resourceClusterRead(d *schema.ResourceData, m interface{}) error {
	return setResourceData(d, m)
}

func resourceClusterUpdate(d *schema.ResourceData, m interface{}) error {
	return nil
}

func resourceClusterDelete(d *schema.ResourceData, m interface{}) error {
	return nil
}

func resourceClusterExists(d *schema.ResourceData, m interface{}) (bool, error) {
	clientset, err := GetClientset(d.Get("state_store").(string))
	_, err = clientset.GetCluster(d.Get("metadata.name").(string))
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func setResourceData(d *schema.ResourceData, m interface{}) error {
	// get cluster
	clientset, err := GetClientset(d.Get("state_store").(string))
	cluster, err := clientset.GetCluster(d.Get("metadata.name").(string))
	if err != nil {
		return err
	}

	if err := d.Set("metadata", resourceDataClusterMetadata(cluster)); err != nil {
		return err
	}
	if err := d.Set("spec", resourceDataClusterSpec(cluster)); err != nil {
		return err
	}
	return nil
}
