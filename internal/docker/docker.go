package docker

import "context"

const (
	LabelHost = "labnet.host"
	LabelPort = "labnet.port"
)

type Container struct {
	ID      string
	Name    string
	Image   string
	Labels  map[string]string
	Running bool
	// port on 127.0.0.1, not the container network ip, since docker desktop cant route to that
	HostPort string
}

type RunSpec struct {
	Name    string
	Image   string
	Network string
	Labels  map[string]string
}

type Client interface {
	ListContainers(ctx context.Context) ([]Container, error)
	EnsureNetwork(ctx context.Context, name string) error
	BuildImage(ctx context.Context, contextDir, tag string) error
	RunContainer(ctx context.Context, spec RunSpec) (id string, err error)
	StopAndRemove(ctx context.Context, name string) error
}
