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

func (c *Client) ListServices() ([]ServiceInfo, error) {
	resp, err := c.http.Get(c.baseURL + "/api/services")
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	var out ListServicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return out.Services, nil
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

func (c *Client) PolicyCheck(src string) (*PolicyCheckResponse, error) {
	var out PolicyCheckResponse
	if err := c.postJSON("/api/policy/check", PolicySourceRequest{Source: src}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PolicyTest(src string) (*PolicyTestResponse, error) {
	var out PolicyTestResponse
	if err := c.postJSON("/api/policy/test", PolicySourceRequest{Source: src}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PolicyApply(src string) (*PolicyApplyResponse, error) {
	var out PolicyApplyResponse
	if err := c.postJSON("/api/policy/apply", PolicySourceRequest{Source: src}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PolicyStatus() (*PolicyStatusResponse, error) {
	resp, err := c.http.Get(c.baseURL + "/api/policy/status")
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	var out PolicyStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &out, nil
}

func (c *Client) Alerts() ([]Alert, error) {
	resp, err := c.http.Get(c.baseURL + "/api/alerts")
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	var out AlertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return out.Alerts, nil
}

func (c *Client) Devices() ([]DeviceInfo, error) {
	resp, err := c.http.Get(c.baseURL + "/api/devices")
	if err != nil {
		return nil, fmt.Errorf("labnetd unreachable at %s: %w", c.baseURL, err)
	}
	defer resp.Body.Close()
	var out DevicesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return out.Devices, nil
}

func (c *Client) PairCode(ttlSeconds int) (*PairCodeResponse, error) {
	var out PairCodeResponse
	if err := c.postJSON("/api/devices/pair-code", PairCodeRequest{TTLSeconds: ttlSeconds}, &out); err != nil {
		return nil, err
	}
	return &out, nil
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
