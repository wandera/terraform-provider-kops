package kops

import (
	"fmt"
	"k8s.io/kops/pkg/client/simple"
	"k8s.io/kops/pkg/client/simple/vfsclientset"
	"k8s.io/kops/util/pkg/vfs"
	"k8s.io/kubernetes/staging/src/k8s.io/apimachinery/pkg/util/validation/field"
)

const (
	invalidStateError = `Unable to read state store s3 bucket.
Please use a valid s3 bucket uri on state_store attribute or KOPS_STATE_STORE env var.
A valid value follows the format s3://<bucket>.
Trailing slash will be trimmed.`
)

var clients = make(map[string]simple.Clientset)

func GetClientset(registryPath string) (simple.Clientset, error) {
	if client, ok := clients[registryPath]; ok {
		return client, nil
	}

	basePath, err := vfs.Context.BuildVfsPath(registryPath)
	if err != nil {
		return nil, fmt.Errorf("error building path for %q: %v", registryPath, err)
	}

	if !vfs.IsClusterReadable(basePath) {
		return nil, field.Invalid(field.NewPath("State Store"), registryPath, invalidStateError)
	}

	clientset := vfsclientset.NewVFSClientset(basePath, true)
	clients[registryPath] = clientset

	return clientset, nil
}
