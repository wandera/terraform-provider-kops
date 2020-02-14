package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/wandera/terraform-provider-kops/kops"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: kops.Provider})
}
