package docker

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"labnet/internal/proxy"
)

const defaultPort = "80"

type Discovery struct {
	client   Client
	registry *proxy.Registry
	interval time.Duration

	known map[string]string
}

func NewDiscovery(client Client, registry *proxy.Registry, interval time.Duration) *Discovery {
	return &Discovery{client: client, registry: registry, interval: interval, known: map[string]string{}}
}

func (d *Discovery) PollOnce(ctx context.Context) (int, error) {
	containers, err := d.client.ListContainers(ctx)
	if err != nil {
		return 0, fmt.Errorf("docker: listing containers: %w", err)
	}

	seen := map[string]bool{}
	for _, c := range containers {
		host, ok := c.Labels[LabelHost]
		if !ok || !c.Running || c.HostPort == "" {
			continue
		}
		target, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%s", c.HostPort))
		if err != nil {
			log.Printf("docker: container %s has an unusable host port %q: %v", c.Name, c.HostPort, err)
			continue
		}
		d.registry.Register(c.Name, host, target)
		d.known[c.ID] = host
		seen[c.ID] = true
	}

	for id, host := range d.known {
		if !seen[id] {
			d.registry.Deregister(host)
			delete(d.known, id)
		}
	}
	return len(seen), nil
}

func (d *Discovery) Run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := d.PollOnce(ctx); err != nil {
				log.Printf("docker: discovery poll failed: %v", err)
			}
		}
	}
}
