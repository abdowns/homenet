package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const apiVersion = "v1.41"

func NewSDKClient(socketPath string) *SDKClient {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	return &SDKClient{http: &http.Client{Transport: transport}}
}

type SDKClient struct {
	http *http.Client
}

func (c *SDKClient) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/"+apiVersion+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker: GET %s: %w (is the Docker daemon running and its socket reachable?)", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("docker: GET %s: %s: %s", path, resp.Status, msg)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("docker: decoding %s response: %w", path, err)
	}
	return nil
}

type dockerContainerJSON struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	State  string            `json:"State"`
	Ports  []struct {
		PublicPort int    `json:"PublicPort"`
		Type       string `json:"Type"`
	} `json:"Ports"`
}

func (c *SDKClient) ListContainers(ctx context.Context) ([]Container, error) {
	q := url.Values{}
	q.Set("all", "true")
	q.Set("filters", `{"label":["`+LabelHost+`"]}`)
	var raw []dockerContainerJSON
	if err := c.getJSON(ctx, "/containers/json?"+q.Encode(), &raw); err != nil {
		return nil, fmt.Errorf("docker: listing containers: %w", err)
	}
	return toContainers(raw), nil
}

func toContainers(raw []dockerContainerJSON) []Container {
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		name := r.ID
		if len(r.Names) > 0 {
			name = strings.TrimPrefix(r.Names[0], "/")
		}
		hostPort := ""
		for _, p := range r.Ports {
			if p.Type == "tcp" && p.PublicPort != 0 {
				hostPort = strconv.Itoa(p.PublicPort)
				break
			}
		}
		out = append(out, Container{
			ID: r.ID, Name: name, Image: r.Image, Labels: r.Labels,
			Running: r.State == "running", HostPort: hostPort,
		})
	}
	return out
}
