package kops

import (
	"fmt"
	"github.com/hashicorp/terraform/helper/schema"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kops/pkg/apis/kops"
	"strings"
)

type InstanceGroupId struct {
	clusterName       string
	instanceGroupName string
}

func (i InstanceGroupId) String() string {
	return fmt.Sprintf("%s/%s", i.clusterName, i.instanceGroupName)
}

func ParseInstanceGroupId(id string) InstanceGroupId {
	split := strings.Split(id, "/")
	if len(split) == 2 {
		return InstanceGroupId{
			clusterName:       split[0],
			instanceGroupName: split[1],
		}
	}
	return InstanceGroupId{}
}

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
		Schema: map[string]*schema.Schema{
			"cluster_name": schemaStringRequired(),
			"metadata":     schemaMetadata(),
			"spec":         schemaInstanceGroupSpec(),
		},
	}
}

func resourceInstanceGroupCreate(d *schema.ResourceData, m interface{}) error {
	clusterName := d.Get("cluster_name").(string)
	clientset := m.(*ProviderConfig).clientset
	cluster, err := clientset.GetCluster(clusterName)
	if err != nil {
		return err
	}

	instanceGroup, err := clientset.InstanceGroupsFor(cluster).Create(&kops.InstanceGroup{
		ObjectMeta: expandObjectMeta(sectionData(d, "metadata")),
		Spec:       expandInstanceGroupSpec(sectionData(d, "spec")),
	})
	if err != nil {
		return err
	}

	d.SetId(InstanceGroupId{
		clusterName:       clusterName,
		instanceGroupName: instanceGroup.ObjectMeta.Name,
	}.String())

	return resourceInstanceGroupRead(d, m)
}

func resourceInstanceGroupRead(d *schema.ResourceData, m interface{}) error {
	instanceGroup, err := getInstanceGroup(d, m)
	if err != nil {
		return err
	}
	if err := d.Set("metadata", flattenObjectMeta(instanceGroup.ObjectMeta)); err != nil {
		return err
	}
	if err := d.Set("spec", flattenInstanceGroupSpec(instanceGroup.Spec)); err != nil {
		return err
	}
	return nil
}

func resourceInstanceGroupUpdate(d *schema.ResourceData, m interface{}) error {
	if ok, _ := resourceInstanceGroupExists(d, m); !ok {
		d.SetId("")
		return nil
	}

	return resourceInstanceGroupRead(d, m)
}

func resourceInstanceGroupDelete(d *schema.ResourceData, m interface{}) error {
	groupId := ParseInstanceGroupId(d.Id())
	clientset := m.(*ProviderConfig).clientset
	cluster, err := clientset.GetCluster(groupId.clusterName)
	if err != nil {
		return err
	}
	return clientset.InstanceGroupsFor(cluster).Delete(groupId.instanceGroupName, &v1.DeleteOptions{})
}

func resourceInstanceGroupExists(d *schema.ResourceData, m interface{}) (bool, error) {
	_, err := getInstanceGroup(d, m)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func getInstanceGroup(d *schema.ResourceData, m interface{}) (*kops.InstanceGroup, error) {
	groupId := ParseInstanceGroupId(d.Id())
	clientset := m.(*ProviderConfig).clientset
	cluster, err := clientset.GetCluster(groupId.clusterName)
	if err != nil {
		return nil, err
	}
	return clientset.InstanceGroupsFor(cluster).Get(groupId.instanceGroupName, v1.GetOptions{})
}
