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
	Zone    string                `json:"zone"`
	Uptime  string                `json:"uptime"`
	Ringlen map[string]RingCounts `json:"rings"`
	Schemas map[string][]string   `json:"schemas"`
}

type RingCounts struct {
	Len   int    `json:"len"`
	Total uint64 `json:"total"`
}

type UpRequest struct {
	Name string `json:"name"`
	Dir  string `json:"dir"`
	Port string `json:"port,omitempty"`
}

type UpResponse struct {
	Host  string `json:"host,omitempty"`
	Error string `json:"error,omitempty"`
}

type DownRequest struct {
	Name string `json:"name"`
}

type ExposeRequest struct {
	Name   string `json:"name"`
	Host   string `json:"host,omitempty"`
	Target string `json:"target"`
}

type ServiceInfo struct {
	Name   string `json:"name"`
	Host   string `json:"host"`
	Target string `json:"target"`
}

type ListServicesResponse struct {
	Services []ServiceInfo `json:"services"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
