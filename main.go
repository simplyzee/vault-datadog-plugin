package main

import (
	"context"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"log"
	"os"
)

// backend implements the Backend for this plugin
type backend struct {
	*framework.Backend
	client clientInterface
}

var _ clientInterface = (*datadogClient)(nil)

const backendHelp = `
The Datadog secrets backend generates Datadog API and Application keys dynamically.

After configuring this backend, you can generate Datadog keys by:
1. Creating a role that defines the type of key (API or Application) and its permissions
2. Generating credentials using that role
`

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		//TLSProviderFunc: ,
	})

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()

	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}

	return b, nil
}

func Backend() *backend {
	b := &backend{}
	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				b.pathConfig(),
				b.pathRoles(),
				b.pathKeys(),
			},
		),
		Secrets: []*framework.Secret{
			b.datadogKeys(),
		},
	}
	return b
}
