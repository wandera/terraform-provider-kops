package kops

import (
	"context"

	"github.com/hashicorp/terraform/helper/schema"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/assets"
	"k8s.io/kops/upup/pkg/fi/cloudup"
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

	cluster, err := clientset.CreateCluster(
		context.Background(),
		&kops.Cluster{
			ObjectMeta: expandObjectMeta(sectionData(d, "metadata")),
			Spec:       expandClusterSpec(sectionData(d, "spec")),
		})
	if err != nil {
		return err
	}

	cluster, err = clientset.GetCluster(context.Background(), cluster.Name)
	if err != nil {
		return err
	}

	assetBuilder := assets.NewAssetBuilder(cluster, "")
	fullCluster, err := cloudup.PopulateClusterSpec(clientset, cluster, assetBuilder)
	if err != nil {
		return err
	}

	_, err = clientset.UpdateCluster(context.Background(), fullCluster, nil)
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
	if err := d.Set("metadata", flattenObjectMeta(cluster.ObjectMeta)); err != nil {
		return err
	}
	if err := d.Set("spec", flattenClusterSpec(cluster.Spec)); err != nil {
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

	_, err := clientset.UpdateCluster(
		context.Background(),
		&kops.Cluster{
			ObjectMeta: expandObjectMeta(sectionData(d, "metadata")),
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

	return clientset.DeleteCluster(context.Background(), cluster)
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
	cluster, err := clientset.GetCluster(context.Background(), d.Id())
	return cluster, err
}

func sectionData(d *schema.ResourceData, section string) map[string]interface{} {
	return d.Get(section).([]interface{})[0].(map[string]interface{})
}
