package api

import "labnet/internal/journal"

type QueryRequest struct {
	Schema    string `json:"schema"`
	Predicate string `json:"predicate"`
}

type QueryResponse struct {
	Rows   []journal.Row `json:"rows"`
	TookMS float64       `json:"took_ms"`
	Error  string        `json:"error,omitempty"`
}

type StatusResponse struct {
	Zone    string              `json:"zone"`
	Uptime  string              `json:"uptime"`
	Ringlen map[string]int      `json:"rings"`
	Schemas map[string][]string `json:"schemas"`
}
