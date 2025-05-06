package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type datadogRole struct {
	KeyType string   `json:"key_type"`
	Scopes  []string `json:"scopes,omitempty"`
	TTL     int      `json:"ttl"`
	MaxTTL  int      `json:"max_ttl"`
}

func (b *backend) pathRoles() *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"key_type": {
				Type:        framework.TypeString,
				Description: "Type of key to generate (api_key, app_key, both)",
				Required:    true,
				AllowedValues: []interface{}{
					"api_key",
					"app_key",
					"both",
				},
			},
			"scopes": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Scopes for application keys",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default TTL for generated credentials",
				Default:     3600,
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum TTL for generated credentials",
				Default:     86400,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathRoleRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRoleWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathRoleDelete,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathRoleList,
			},
		},
	}
}

func (b *backend) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: "Name of the role",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name for the generated keys",
				Default:     "vault-generated",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeysRead,
			},
		},
	}
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"key_type": role.KeyType,
			"scopes":   role.Scopes,
			"ttl":      role.TTL,
			"max_ttl":  role.MaxTTL,
		},
	}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role := &datadogRole{
		KeyType: data.Get("key_type").(string),
		Scopes:  data.Get("scopes").([]string),
		TTL:     data.Get("ttl").(int),
		MaxTTL:  data.Get("max_ttl").(int),
	}

	// Validate key type
	switch role.KeyType {
	case "api_key", "app_key", "both":
		// valid
	default:
		return logical.ErrorResponse("invalid key_type; must be 'api_key', 'app_key', or 'both'"), nil
	}

	// Validate TTL
	if role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	// Store the role
	entry, err := logical.StorageEntryJSON("role/"+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	if err := req.Storage.Delete(ctx, "role/"+name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*datadogRole, error) {
	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role datadogRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

// Add the key generation handler
func (b *backend) pathKeysRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role '%s' not found", roleName)), nil
	}

	// Ensure we have a client
	if b.client == nil {
		config, err := b.getConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return logical.ErrorResponse("datadog backend not configured"), nil
		}
		b.client = newDatadogClient(config.APIKey, config.AppKey)
	}

	keyName := data.Get("name").(string)
	if keyName == "" {
		keyName = fmt.Sprintf("vault-%s-%d", roleName, time.Now().Unix())
	}

	respData := make(map[string]interface{})
	var apiKey, appKey string

	if role.KeyType == "api_key" || role.KeyType == "both" {
		apiKey, err = b.client.createAPIKey(keyName)
		if err != nil {
			return nil, fmt.Errorf("error creating API key: %w", err)
		}
		respData["api_key"] = apiKey
	}

	if role.KeyType == "app_key" || role.KeyType == "both" {
		appKey, err = b.client.createAppKey(keyName, role.Scopes)
		if err != nil {
			return nil, fmt.Errorf("error creating Application key: %w", err)
		}
		respData["app_key"] = appKey
	}

	resp := &logical.Response{
		Data: respData,
	}

	// Set up the secret for revocation
	resp.Secret = &logical.Secret{
		InternalData: map[string]interface{}{
			"api_key":  apiKey,
			"app_key":  appKey,
			"key_type": role.KeyType,
		},
		LeaseOptions: logical.LeaseOptions{
			TTL:       time.Duration(role.TTL) * time.Second,
			MaxTTL:    time.Duration(role.MaxTTL) * time.Second,
			Renewable: true,
		},
	}

	return resp, nil
}

// Add the revocation handler
func (b *backend) secretKeysRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if b.client == nil {
		config, err := b.getConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil {
			return logical.ErrorResponse("datadog backend not configured"), nil
		}
		b.client = newDatadogClient(config.APIKey, config.AppKey)
	}

	keyType := req.Secret.InternalData["key_type"].(string)

	if keyType == "api_key" || keyType == "both" {
		if apiKey, ok := req.Secret.InternalData["api_key"].(string); ok && apiKey != "" {
			if err := b.client.deleteAPIKey(apiKey); err != nil {
				return nil, fmt.Errorf("error revoking API key: %w", err)
			}
		}
	}

	if keyType == "app_key" || keyType == "both" {
		if appKey, ok := req.Secret.InternalData["app_key"].(string); ok && appKey != "" {
			if err := b.client.deleteAppKey(appKey); err != nil {
				return nil, fmt.Errorf("error revoking Application key: %w", err)
			}
		}
	}

	return nil, nil
}

func (b *backend) datadogKeys() *framework.Secret {
	return &framework.Secret{
		Type: "datadog_keys",
		Fields: map[string]*framework.FieldSchema{
			"api_key": {
				Type:        framework.TypeString,
				Description: "Datadog API key",
			},
			"app_key": {
				Type:        framework.TypeString,
				Description: "Datadog Application key",
			},
		},
		Revoke: b.secretKeysRevoke,
	}
}
