package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"labnet/internal/auth"
	"labnet/internal/docker"
	"labnet/internal/journal"
	"labnet/internal/nql"
	"labnet/internal/policy"
	"labnet/internal/proxy"
)

type Services struct {
	Registry      *proxy.Registry
	Docker        docker.Client
	Discovery     *docker.Discovery
	DockerNetwork string
}

type PolicyDeps struct {
	Manager *policy.Manager
	Alerts  *policy.AlertLog
}

type AuthDeps struct {
	Store *auth.Store
}

type Server struct {
	zone    string
	started time.Time
	prog    *nql.Program
	rings   map[string]*journal.Ring
	svc     Services
	pol     PolicyDeps
	auth    AuthDeps
}

// rings maps schema name to its journal; a schema with no ring isnt queryable
func NewServer(zone string, prog *nql.Program, rings map[string]*journal.Ring, svc Services, pol PolicyDeps, ad AuthDeps) *Server {
	return &Server{zone: zone, started: time.Now(), prog: prog, rings: rings, svc: svc, pol: pol, auth: ad}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/query", s.handleQuery)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/up", s.handleUp)
	mux.HandleFunc("POST /api/down", s.handleDown)
	mux.HandleFunc("POST /api/expose", s.handleExpose)
	mux.HandleFunc("GET /api/services", s.handleListServices)
	mux.HandleFunc("POST /api/policy/check", s.handlePolicyCheck)
	mux.HandleFunc("POST /api/policy/test", s.handlePolicyTest)
	mux.HandleFunc("POST /api/policy/apply", s.handlePolicyApply)
	mux.HandleFunc("GET /api/policy/status", s.handlePolicyStatus)
	mux.HandleFunc("GET /api/alerts", s.handleAlerts)
	mux.HandleFunc("GET /api/devices", s.handleListDevices)
	mux.HandleFunc("POST /api/devices/pair-code", s.handlePairCode)
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
		Ringlen: map[string]RingCounts{},
		Schemas: map[string][]FieldInfo{},
	}
	for name, ring := range s.rings {
		resp.Ringlen[name] = RingCounts{Len: ring.Len(), Total: ring.Total()}
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
	var out []ServiceInfo
	if s.svc.Registry != nil {
		for _, svc := range s.svc.Registry.List() {
			out = append(out, ServiceInfo{Name: svc.Name, Host: svc.Host, Target: svc.Target.String()})
		}
	}
	writeJSON(w, http.StatusOK, ListServicesResponse{Services: out})
}

func (s *Server) handlePolicyCheck(w http.ResponseWriter, r *http.Request) {
	var req PolicySourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, PolicyCheckResponse{Error: "bad request body: " + err.Error()})
		return
	}
	p, err := policy.Compile(req.Source)
	if err != nil {
		writeJSON(w, http.StatusOK, PolicyCheckResponse{OK: false, Error: err.Error()})
		return
	}
	defer p.Close()
	writeJSON(w, http.StatusOK, PolicyCheckResponse{OK: true, Rules: p.RuleNames()})
}

func (s *Server) handlePolicyTest(w http.ResponseWriter, r *http.Request) {
	var req PolicySourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, PolicyTestResponse{Error: "bad request body: " + err.Error()})
		return
	}
	p, err := policy.Compile(req.Source)
	if err != nil {
		writeJSON(w, http.StatusOK, PolicyTestResponse{OK: false, Error: err.Error()})
		return
	}
	defer p.Close()

	resp := PolicyTestResponse{OK: true}
	if ring, ok := s.rings["HttpRequest"]; ok {
		res := p.TestHTTPRing(ring)
		resp.HTTP = PolicyRuleCounts{Total: res.HTTPTotal, Matched: res.HTTPDenied, ByRule: res.DeniedBy}
	}
	if ring, ok := s.rings["DnsQuery"]; ok {
		res := p.TestDNSRing(ring)
		resp.DNS = PolicyRuleCounts{Total: res.DNSTotal, Matched: res.DNSBlocked, ByRule: res.BlockedBy}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePolicyApply(w http.ResponseWriter, r *http.Request) {
	var req PolicySourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, PolicyApplyResponse{Error: "bad request body: " + err.Error()})
		return
	}
	if s.pol.Manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, PolicyApplyResponse{Error: "policy engine is not configured"})
		return
	}
	if err := s.pol.Manager.Apply(req.Source); err != nil {
		writeJSON(w, http.StatusOK, PolicyApplyResponse{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, PolicyApplyResponse{OK: true, Rules: s.pol.Manager.Current().RuleNames()})
}

func (s *Server) handlePolicyStatus(w http.ResponseWriter, r *http.Request) {
	if s.pol.Manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "policy engine is not configured"})
		return
	}
	writeJSON(w, http.StatusOK, PolicyStatusResponse{
		Source: s.pol.Manager.Source(),
		Rules:  s.pol.Manager.Current().RuleNames(),
	})
}

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if s.auth.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "device auth is not configured"})
		return
	}
	devices, err := s.auth.Store.ListDevices(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	out := make([]DeviceInfo, len(devices))
	for i, d := range devices {
		out[i] = DeviceInfo{ID: d.ID, Name: d.Name, PairedAt: d.PairedAt.Format(time.RFC3339)}
	}
	writeJSON(w, http.StatusOK, DevicesResponse{Devices: out})
}

func (s *Server) handlePairCode(w http.ResponseWriter, r *http.Request) {
	if s.auth.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "device auth is not configured"})
		return
	}
	var req PairCodeRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "bad request body: " + err.Error()})
			return
		}
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	code, err := s.auth.Store.CreatePairingCode(r.Context(), ttl)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, PairCodeResponse{Code: code, ExpiresAt: time.Now().Add(ttl).Format(time.RFC3339)})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	var alerts []Alert
	if s.pol.Alerts != nil {
		for _, a := range s.pol.Alerts.Recent(200) {
			alerts = append(alerts, Alert{TS: a.TS, Schema: a.Schema, Rule: a.Rule, Summary: a.Summary})
		}
	}
	writeJSON(w, http.StatusOK, AlertsResponse{Alerts: alerts})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
