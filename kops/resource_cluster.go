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
			"metadata": schemaMetadata(),
			"spec":     schemaClusterSpec(),
		},
	}
}

func resourceClusterCreate(d *schema.ResourceData, m interface{}) error {
	clientset := m.(*ProviderConfig).clientset

	cluster, err := clientset.CreateCluster(&kops.Cluster{
		ObjectMeta: expandClusterMetadata(sectionData(d, "metadata")),
		Spec:       expandClusterSpec(sectionData(d, "spec")),
	})
	if err != nil {
		return err
	}

	d.SetId(cluster.Name)

	return resourceClusterRead(d, m)
}

func resourceClusterRead(d *schema.ResourceData, m interface{}) error {
	cluster, err := getCluster(d, m)
	if err != nil {
		return err
	}
	if err := d.Set("metadata", flattenClusterMetadata(cluster)); err != nil {
		return err
	}
	if err := d.Set("spec", flattenClusterSpec(cluster)); err != nil {
		return err
	}
	return nil
}

func resourceClusterUpdate(d *schema.ResourceData, m interface{}) error {
	if ok, _ := resourceClusterExists(d, m); !ok {
		d.SetId("")
		return nil
	}

	clientset := m.(*ProviderConfig).clientset

	_, err := clientset.UpdateCluster(&kops.Cluster{
		ObjectMeta: expandClusterMetadata(sectionData(d, "metadata")),
		Spec:       expandClusterSpec(sectionData(d, "spec")),
	}, nil)

	if err != nil {
		return err
	}

	return resourceClusterRead(d, m)
}

func resourceClusterDelete(d *schema.ResourceData, m interface{}) error {
	clientset := m.(*ProviderConfig).clientset
	cluster, err := getCluster(d, m)
	if err != nil {
		return err
	}

	return clientset.DeleteCluster(cluster)
}

func resourceClusterExists(d *schema.ResourceData, m interface{}) (bool, error) {
	_, err := getCluster(d, m)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func getCluster(d *schema.ResourceData, m interface{}) (*kops.Cluster, error) {
	clientset := m.(*ProviderConfig).clientset
	cluster, err := clientset.GetCluster(d.Id())
	return cluster, err
}

func sectionData(d *schema.ResourceData, section string) map[string]interface{} {
	return d.Get(section).([]interface{})[0].(map[string]interface{})
}
