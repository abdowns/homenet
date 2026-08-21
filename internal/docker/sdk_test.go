package docker

import "testing"

const containerListFixture = `[
  {
    "Id": "abc123",
    "Names": ["/myapp"],
    "Image": "labnet/myapp:latest",
    "Labels": {"labnet.host": "myapp.lab", "labnet.port": "3000"},
    "State": "running",
    "Ports": [
      {"PrivatePort": 3000, "PublicPort": 32768, "Type": "tcp"}
    ]
  },
  {
    "Id": "def456",
    "Names": ["/stopped-app"],
    "Image": "labnet/other:latest",
    "Labels": {"labnet.host": "other.lab"},
    "State": "exited",
    "Ports": []
  },
  {
    "Id": "ghi789",
    "Names": ["/no-network"],
    "Image": "labnet/orphan:latest",
    "Labels": {"labnet.host": "orphan.lab"},
    "State": "running",
    "Ports": []
  }
]`

func TestParseContainerList(t *testing.T) {
	cs, err := parseContainerList([]byte(containerListFixture))
	if err != nil {
		t.Fatalf("parseContainerList: %v", err)
	}
	if len(cs) != 3 {
		t.Fatalf("expected 3 containers, got %d", len(cs))
	}

	byName := map[string]Container{}
	for _, c := range cs {
		byName[c.Name] = c
	}

	app := byName["myapp"]
	if !app.Running {
		t.Error("myapp: expected Running=true")
	}
	if app.HostPort != "32768" {
		t.Errorf("myapp: HostPort = %q, want 32768", app.HostPort)
	}
	if app.Labels[LabelPort] != "3000" {
		t.Errorf("myapp: port label = %q, want 3000", app.Labels[LabelPort])
	}

	stopped := byName["stopped-app"]
	if stopped.Running {
		t.Error("stopped-app: expected Running=false")
	}
	if stopped.HostPort != "" {
		t.Errorf("stopped-app: HostPort = %q, want empty", stopped.HostPort)
	}

	orphan := byName["no-network"]
	if orphan.HostPort != "" {
		t.Errorf("no-network: HostPort = %q, want empty (nothing published)", orphan.HostPort)
	}
}

func TestParseContainerListEmpty(t *testing.T) {
	cs, err := parseContainerList([]byte(`[]`))
	if err != nil {
		t.Fatalf("parseContainerList: %v", err)
	}
	if len(cs) != 0 {
		t.Fatalf("expected 0 containers, got %d", len(cs))
	}
}

func TestParseContainerListInvalidJSON(t *testing.T) {
	if _, err := parseContainerList([]byte(`not json`)); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}
