package api

import (
	"encoding/json"
	"net/http"
	"time"

	"labnet/internal/journal"
	"labnet/internal/nql"
)

type Server struct {
	zone    string
	started time.Time
	prog    *nql.Program
	rings   map[string]*journal.Ring
}

// rings maps schema name to its journal; a schema with no ring isnt queryable
func NewServer(zone string, prog *nql.Program, rings map[string]*journal.Ring) *Server {
	return &Server{zone: zone, started: time.Now(), prog: prog, rings: rings}
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/query", s.handleQuery)
	mux.HandleFunc("/api/status", s.handleStatus)
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
