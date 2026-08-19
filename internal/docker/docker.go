package docker

import "context"

const (
	LabelHost = "labnet.host"
	LabelPort = "labnet.port"
)

type Container struct {
	ID      string
	Name    string
	Labels  map[string]string
	Running bool
	IP      string
}

type Client interface {
	ListContainers(ctx context.Context) ([]Container, error)
}
