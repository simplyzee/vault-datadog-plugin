package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type clientInterface interface {
	createAPIKey(name string) (string, error)
	createAppKey(name string, scopes []string) (string, error)
	deleteAPIKey(key string) error
	deleteAppKey(key string) error
}

type datadogClient struct {
	apiKey  string
	appKey  string
	baseURL string
	client  *http.Client
}

func newDatadogClient(apiKey, appKey string) *datadogClient {
	return &datadogClient{
		apiKey:  apiKey,
		appKey:  appKey,
		baseURL: "https://api.datadoghq.com/api/v1",
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *datadogClient) createAPIKey(name string) (string, error) {
	payload := map[string]interface{}{
		"name": name,
	}

	resp, err := c.doRequest("POST", "/api_key", payload)
	if err != nil {
		return "", err
	}

	var result struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.APIKey, nil
}

func (c *datadogClient) createAppKey(name string, scopes []string) (string, error) {
	payload := map[string]interface{}{
		"name":   name,
		"scopes": scopes,
	}

	resp, err := c.doRequest("POST", "/application_key", payload)
	if err != nil {
		return "", err
	}

	var result struct {
		AppKey string `json:"application_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.AppKey, nil
}

func (c *datadogClient) deleteAPIKey(key string) error {
	_, err := c.doRequest("DELETE", fmt.Sprintf("/api_key/%s", key), nil)
	return err
}

func (c *datadogClient) deleteAppKey(key string) error {
	_, err := c.doRequest("DELETE", fmt.Sprintf("/application_key/%s", key), nil)
	return err
}

func (c *datadogClient) doRequest(method, path string, payload interface{}) (*http.Response, error) {
	var body bytes.Buffer
	if payload != nil {
		if err := json.NewEncoder(&body).Encode(payload); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, c.baseURL+path, &body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("datadog API request failed with status %d", resp.StatusCode)
	}

	return resp, nil
}
