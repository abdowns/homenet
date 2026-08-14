package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: 5 * time.Second}}
}

func (c *Client) Query(req QueryRequest) (*QueryResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Post(c.baseURL+"/api/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return &out, fmt.Errorf("query failed: %s", out.Error)
	}
	return &out, nil
}

func (c *Client) Status() (*StatusResponse, error) {
	resp, err := c.http.Get(c.baseURL + "/api/status")
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
