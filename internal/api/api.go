package api

import "labnet/internal/journal"

type QueryRequest struct {
	Schema    string `json:"schema"`
	Predicate string `json:"predicate"`
	Limit     int    `json:"limit,omitempty"`
}

type QueryResponse struct {
	Rows      []journal.Row `json:"rows"`
	CompileMS float64       `json:"compile_ms"`
	ScanMS    float64       `json:"scan_ms"`
	Scanned   uint64        `json:"scanned"`
	Matched   uint64        `json:"matched"`
	Error     string        `json:"error,omitempty"`
}

type StatusResponse struct {
	Zone       string                `json:"zone"`
	Uptime     string                `json:"uptime"`
	Ringlen    map[string]RingCounts `json:"rings"`
	Schemas    map[string][]string   `json:"schemas"`
	AlertRules int                   `json:"alert_rules"`
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

// mirrors policy.Alert, redeclared so this package skips importing internal/policy
type Alert struct {
	TS      uint64 `json:"ts"`
	Rule    string `json:"rule"`
	Summary string `json:"summary"`
}

type AlertsResponse struct {
	Alerts []Alert `json:"alerts"`
}
