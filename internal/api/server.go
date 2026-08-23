package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"labnet/internal/docker"
	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/proxy"
)

type Services struct {
	Registry      *proxy.Registry
	Docker        docker.Client
	Discovery     *docker.Discovery
	DockerNetwork string
}

type Server struct {
	zone    string
	started time.Time
	prog    *nql.Program
	rings   map[string]*journal.Ring
	svc     Services
}

// rings maps schema name to its journal; a schema with no ring isnt queryable
func NewServer(zone string, prog *nql.Program, rings map[string]*journal.Ring, svc Services) *Server {
	return &Server{zone: zone, started: time.Now(), prog: prog, rings: rings, svc: svc}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/query", s.handleQuery)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/up", s.handleUp)
	mux.HandleFunc("POST /api/down", s.handleDown)
	mux.HandleFunc("POST /api/expose", s.handleExpose)
	mux.HandleFunc("GET /api/services", s.handleListServices)
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, QueryResponse{Error: "bad request body: " + err.Error()})
		return
	}
	ring, ok := s.rings[req.Schema]
	if !ok {
		writeJSON(w, http.StatusNotFound, QueryResponse{Error: "no journal for schema " + req.Schema})
		return
	}
	rows, stats, err := ring.Query(req.Predicate, req.Limit)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, QueryResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, QueryResponse{
		Rows: rows, CompileMS: stats.CompileMS, ScanMS: stats.ScanMS,
		Scanned: stats.Scanned, Matched: stats.Matched,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := StatusResponse{
		Zone:    s.zone,
		Uptime:  time.Since(s.started).Round(time.Second).String(),
		Ringlen: map[string]int{},
		Schemas: map[string][]FieldInfo{},
	}
	for name, ring := range s.rings {
		resp.Ringlen[name] = ring.Len()
	}
	for _, sch := range s.prog.Schemas() {
		fields := make([]FieldInfo, len(sch.Fields))
		for i, f := range sch.Fields {
			fields[i] = FieldInfo{Name: f.Name, Type: f.Type.String()}
		}
		resp.Schemas[sch.Name] = fields
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUp(w http.ResponseWriter, r *http.Request) {
	var req UpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, UpResponse{Error: "bad request body: " + err.Error()})
		return
	}
	if req.Name == "" || req.Dir == "" {
		writeJSON(w, http.StatusBadRequest, UpResponse{Error: "name and dir are required"})
		return
	}
	port := req.Port
	if port == "" {
		port = "80"
	}
	ctx := r.Context()
	tag := "labnet/" + req.Name + ":latest"

	if err := s.svc.Docker.EnsureNetwork(ctx, s.svc.DockerNetwork); err != nil {
		writeJSON(w, http.StatusInternalServerError, UpResponse{Error: err.Error()})
		return
	}
	if err := s.svc.Docker.BuildImage(ctx, req.Dir, tag); err != nil {
		writeJSON(w, http.StatusInternalServerError, UpResponse{Error: err.Error()})
		return
	}
	host := req.Name + "." + s.zone
	labels := map[string]string{docker.LabelHost: host, docker.LabelPort: port}
	if _, err := s.svc.Docker.RunContainer(ctx, docker.RunSpec{
		Name: req.Name, Image: tag, Network: s.svc.DockerNetwork, Labels: labels,
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, UpResponse{Error: err.Error()})
		return
	}
	s.svc.Discovery.PollOnce(ctx) // pick it up now instead of waiting for the next tick
	writeJSON(w, http.StatusOK, UpResponse{Host: host})
}

func (s *Server) handleDown(w http.ResponseWriter, r *http.Request) {
	var req DownRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad request body: " + err.Error()})
		return
	}
	ctx := r.Context()
	if err := s.svc.Docker.StopAndRemove(ctx, req.Name); err == nil {
		s.svc.Discovery.PollOnce(ctx)
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	// not a running container by that name, try it as an exposed service
	if s.svc.Registry.DeregisterByName(req.Name) {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "no such service: " + req.Name})
}

func (s *Server) handleExpose(w http.ResponseWriter, r *http.Request) {
	var req ExposeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad request body: " + err.Error()})
		return
	}
	if req.Name == "" || req.Target == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "name and target are required"})
		return
	}
	target, err := url.Parse(req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: fmt.Sprintf("bad target %q: %v", req.Target, err)})
		return
	}
	host := req.Host
	if host == "" {
		host = req.Name + "." + s.zone
	}
	svc := s.svc.Registry.Register(req.Name, host, target)
	writeJSON(w, http.StatusOK, ServiceInfo{Name: svc.Name, Host: svc.Host, Target: svc.Target.String()})
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	svcs := s.svc.Registry.List()
	out := make([]ServiceInfo, len(svcs))
	for i, svc := range svcs {
		out[i] = ServiceInfo{Name: svc.Name, Host: svc.Host, Target: svc.Target.String()}
	}
	writeJSON(w, http.StatusOK, ListServicesResponse{Services: out})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
