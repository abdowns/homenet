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
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) Query(req QueryRequest) (*QueryResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Post(c.baseURL+"/api/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	var out QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	if out.Error != "" {
		return &out, fmt.Errorf("%s", out.Error)
	}
	return &out, nil
}

func (c *Client) Up(req UpRequest) (*UpResponse, error) {
	var out UpResponse
	if err := c.postJSON("/api/up", req, &out); err != nil {
		return nil, err
	}
	if out.Error != "" {
		return &out, fmt.Errorf("%s", out.Error)
	}
	return &out, nil
}

func (c *Client) Down(req DownRequest) error {
	var out ErrorResponse
	if err := c.postJSON("/api/down", req, &out); err != nil {
		return err
	}
	if out.Error != "" {
		return fmt.Errorf("%s", out.Error)
	}
	return nil
}

func (c *Client) Expose(req ExposeRequest) (*ServiceInfo, error) {
	var out ServiceInfo
	if err := c.postJSON("/api/expose", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ListServices() (*ListServicesResponse, error) {
	resp, err := c.http.Get(c.baseURL + "/api/services")
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	var out ListServicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &out, nil
}

func (c *Client) postJSON(path string, req, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := c.http.Post(c.baseURL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c *Client) Status() (*StatusResponse, error) {
	resp, err := c.http.Get(c.baseURL + "/api/status")
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	var out StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &out, nil
}
