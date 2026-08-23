package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const apiVersion = "v1.41"

func NewSDKClient(socketPath string) *SDKClient {
	return &SDKClient{
		http: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

type SDKClient struct {
	http *http.Client
}

func (c *SDKClient) url(path string) string {
	return "http://unix/" + apiVersion + path
}

func (c *SDKClient) do(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker: %s %s: %w (is the Docker daemon running and its socket reachable?)", method, path, err)
	}
	return resp, nil
}

type dockerContainerJSON struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	State  string            `json:"State"`
	Ports  []struct {
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

func parseContainerList(data []byte) ([]Container, error) {
	var raw []dockerContainerJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding container list: %w", err)
	}
	out := make([]Container, 0, len(raw))
	for _, r := range raw {
		name := strings.TrimPrefix(firstOr(r.Names, r.ID), "/")
		wantPort := r.Labels[LabelPort]
		if wantPort == "" {
			wantPort = defaultPort
		}
		privatePort, _ := strconv.Atoi(wantPort)
		hostPort := ""
		for _, p := range r.Ports {
			if p.Type == "tcp" && p.PrivatePort == privatePort && p.PublicPort != 0 {
				hostPort = strconv.Itoa(p.PublicPort)
				break
			}
		}
		out = append(out, Container{
			ID: r.ID, Name: name, Image: r.Image, Labels: r.Labels,
			Running: r.State == "running", HostPort: hostPort,
		})
	}
	return out, nil
}

func firstOr(s []string, def string) string {
	if len(s) > 0 {
		return s[0]
	}
	return def
}

func (c *SDKClient) ListContainers(ctx context.Context) ([]Container, error) {
	filters := `{"label":["` + LabelHost + `"]}`
	resp, err := c.do(ctx, http.MethodGet, "/containers/json?all=true&filters="+url.QueryEscape(filters), nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("docker: reading container list response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker: listing containers: %s: %s", resp.Status, body)
	}
	return parseContainerList(body)
}

func (c *SDKClient) EnsureNetwork(ctx context.Context, name string) error {
	body, _ := json.Marshal(map[string]any{"Name": name, "Driver": "bridge"})
	resp, err := c.do(ctx, http.MethodPost, "/networks/create", bytes.NewReader(body), "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	msg, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(msg), "already exists") {
		return nil
	}
	return fmt.Errorf("docker: creating network %q: %s: %s", name, resp.Status, msg)
}

func (c *SDKClient) BuildImage(ctx context.Context, contextDir, tag string) error {
	tarball, err := tarDir(contextDir)
	if err != nil {
		return fmt.Errorf("docker: building tar context from %s: %w", contextDir, err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/build?t="+url.QueryEscape(tag), tarball, "application/x-tar")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	var lastStream string
	for {
		var line struct {
			Stream string `json:"stream"`
			Error  string `json:"error"`
		}
		if err := dec.Decode(&line); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("docker: reading build output: %w", err)
		}
		if line.Error != "" {
			return fmt.Errorf("docker: build failed: %s", line.Error)
		}
		if line.Stream != "" {
			lastStream = line.Stream
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker: build failed: %s: %s", resp.Status, lastStream)
	}
	return nil
}

func (c *SDKClient) RunContainer(ctx context.Context, spec RunSpec) (string, error) {
	port := spec.Labels[LabelPort]
	if port == "" {
		port = defaultPort
	}
	portKey := port + "/tcp"
	body, _ := json.Marshal(map[string]any{
		"Image":        spec.Image,
		"Labels":       spec.Labels,
		"ExposedPorts": map[string]any{portKey: map[string]any{}},
		"HostConfig": map[string]any{
			"PortBindings": map[string]any{
				portKey: []map[string]any{{"HostIp": "127.0.0.1", "HostPort": ""}},
			},
		},
		"NetworkingConfig": map[string]any{
			"EndpointsConfig": map[string]any{spec.Network: map[string]any{}},
		},
	})
	resp, err := c.do(ctx, http.MethodPost, "/containers/create?name="+url.QueryEscape(spec.Name), bytes.NewReader(body), "application/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("docker: creating container %q: %s: %s", spec.Name, resp.Status, respBody)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(respBody, &created); err != nil {
		return "", fmt.Errorf("docker: decoding create response: %w", err)
	}

	startResp, err := c.do(ctx, http.MethodPost, "/containers/"+created.ID+"/start", nil, "")
	if err != nil {
		return "", err
	}
	defer startResp.Body.Close()
	if startResp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(startResp.Body)
		return "", fmt.Errorf("docker: starting container %q: %s: %s", spec.Name, startResp.Status, msg)
	}
	return created.ID, nil
}

func (c *SDKClient) StopAndRemove(ctx context.Context, name string) error {
	stopResp, err := c.do(ctx, http.MethodPost, "/containers/"+url.QueryEscape(name)+"/stop", nil, "")
	if err != nil {
		return err
	}
	stopResp.Body.Close()
	if stopResp.StatusCode != http.StatusNoContent && stopResp.StatusCode != http.StatusNotModified {
		return fmt.Errorf("docker: stopping container %q: %s", name, stopResp.Status)
	}

	rmResp, err := c.do(ctx, http.MethodDelete, "/containers/"+url.QueryEscape(name), nil, "")
	if err != nil {
		return err
	}
	defer rmResp.Body.Close()
	if rmResp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(rmResp.Body)
		return fmt.Errorf("docker: removing container %q: %s: %s", name, rmResp.Status, msg)
	}
	return nil
}

func tarDir(dir string) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}
