package main

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

// mockStorage implements logical.Storage
type mockStorage struct {
	mock.Mock
	data map[string]*logical.StorageEntry
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		data: make(map[string]*logical.StorageEntry),
	}
}

func (m *mockStorage) List(ctx context.Context, path string) ([]string, error) {
	args := m.Called(ctx, path)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockStorage) Get(ctx context.Context, path string) (*logical.StorageEntry, error) {
	args := m.Called(ctx, path)
	if entry := args.Get(0); entry != nil {
		return entry.(*logical.StorageEntry), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *mockStorage) Delete(ctx context.Context, path string) error {
	args := m.Called(ctx, path)
	return args.Error(0)
}

// mockDatadogClient implements a mock version of our Datadog client
type mockDatadogClient struct {
	mock.Mock
}

func (m *mockDatadogClient) createAPIKey(name string) (string, error) {
	args := m.Called(name)
	return args.String(0), args.Error(1)
}

func (m *mockDatadogClient) createAppKey(name string, scopes []string) (string, error) {
	args := m.Called(name, scopes)
	return args.String(0), args.Error(1)
}

func (m *mockDatadogClient) deleteAPIKey(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *mockDatadogClient) deleteAppKey(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

// Test helper function to create a test backend with mocked storage
func testBackend(t *testing.T) (*backend, *mockStorage) {
	b := Backend()
	storage := newMockStorage()

	config := &logical.BackendConfig{
		StorageView: storage,
	}

	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	return b, storage
}

// Tests
func TestBackend_PathConfigCRUD(t *testing.T) {
	b, storage := testBackend(t)

	t.Run("config write and read", func(t *testing.T) {
		// Mock storage calls
		storage.On("Put", mock.Anything, mock.Anything).Return(nil)
		storage.On("Get", mock.Anything, "config").Return(&logical.StorageEntry{
			Key:   "config",
			Value: []byte(`{"api_key":"test-api-key","app_key":"test-app-key"}`),
		}, nil)

		// Write config
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "config",
			Storage:   storage,
			Data: map[string]interface{}{
				"api_key": "test-api-key",
				"app_key": "test-app-key",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.Nil(t, resp)

		// Read config
		req.Operation = logical.ReadOperation
		resp, err = b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "test-api-key", resp.Data["api_key"])
		assert.Equal(t, "test-app-key", resp.Data["app_key"])
	})
}

func TestBackend_PathRoleCRUD(t *testing.T) {
	b, storage := testBackend(t)

	t.Run("role create, read, and delete", func(t *testing.T) {
		// Mock storage calls
		storage.On("Put", mock.Anything, mock.Anything).Return(nil)
		storage.On("Get", mock.Anything, "role/test-role").Return(&logical.StorageEntry{
			Key:   "role/test-role",
			Value: []byte(`{"key_type":"both","scopes":["logs_read"],"ttl":3600,"max_ttl":86400}`),
		}, nil)
		storage.On("Delete", mock.Anything, "role/test-role").Return(nil)

		// Create role
		req := &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/test-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"key_type": "both",
				"scopes":   []string{"logs_read"},
				"ttl":      3600,
				"max_ttl":  86400,
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.Nil(t, resp)

		// Read role
		req.Operation = logical.ReadOperation
		resp, err = b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "both", resp.Data["key_type"])
		assert.Equal(t, []string{"logs_read"}, resp.Data["scopes"])

		// Delete role
		req.Operation = logical.DeleteOperation
		resp, err = b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.Nil(t, resp)
	})
}

func TestBackend_PathKeys(t *testing.T) {
	b, storage := testBackend(t)

	t.Run("generate keys", func(t *testing.T) {
		// Set up mock client
		mockClient := &mockDatadogClient{}
		b.client = mockClient

		// Mock storage calls
		storage.On("Get", mock.Anything, "role/test-role").Return(&logical.StorageEntry{
			Key:   "role/test-role",
			Value: []byte(`{"key_type":"both","scopes":["logs_read"],"ttl":3600,"max_ttl":86400}`),
		}, nil)

		// Mock client calls
		mockClient.On("createAPIKey", mock.Anything).Return("test-api-key", nil)
		mockClient.On("createAppKey", mock.Anything, []string{"logs_read"}).Return("test-app-key", nil)

		// Request keys
		req := &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "keys/test-role",
			Storage:   storage,
			Data: map[string]interface{}{
				"name": "test-keys",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "test-api-key", resp.Data["api_key"])
		assert.Equal(t, "test-app-key", resp.Data["app_key"])
	})
}

func TestBackend_KeyRevocation(t *testing.T) {
	b, storage := testBackend(t)

	t.Run("revoke keys", func(t *testing.T) {
		// Set up mock client
		mockClient := &mockDatadogClient{}
		b.client = mockClient

		// Mock storage for config
		storage.On("Get", mock.Anything, "config").Return(&logical.StorageEntry{
			Key:   "config",
			Value: []byte(`{"api_key":"admin-api-key","app_key":"admin-app-key"}`),
		}, nil)

		// Mock client calls
		mockClient.On("deleteAPIKey", "test-api-key").Return(nil)
		mockClient.On("deleteAppKey", "test-app-key").Return(nil)

		// Create revocation request
		req := &logical.Request{
			Operation: logical.RevokeOperation,
			Path:      "keys/test-role",
			Storage:   storage,
			Secret: &logical.Secret{
				InternalData: map[string]interface{}{
					"secret_type": "datadog_keys",
					"key_type":    "both",
					"api_key":     "test-api-key",
					"app_key":     "test-app-key",
				},
				LeaseOptions: logical.LeaseOptions{
					TTL:    3600,
					MaxTTL: 86400,
				},
			},
			Data: map[string]interface{}{
				"api_key": "test-api-key",
				"app_key": "test-app-key",
			},
		}

		resp, err := b.HandleRequest(context.Background(), req)
		assert.NoError(t, err)
		assert.Nil(t, resp)

		mockClient.AssertExpectations(t)
	})
}
