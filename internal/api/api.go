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
	Zone    string                 `json:"zone"`
	Uptime  string                 `json:"uptime"`
	Ringlen map[string]RingCounts  `json:"rings"`
	Schemas map[string][]FieldInfo `json:"schemas"`
}

type RingCounts struct {
	Len   int    `json:"len"`
	Total uint64 `json:"total"`
}

type FieldInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
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

type PolicySourceRequest struct {
	Source string `json:"source"`
}

type PolicyCheckResponse struct {
	OK    bool                `json:"ok"`
	Error string              `json:"error,omitempty"`
	Rules map[string][]string `json:"rules,omitempty"`
}

type PolicyRuleCounts struct {
	Total   int            `json:"total"`
	Matched int            `json:"matched"`
	ByRule  map[string]int `json:"by_rule"`
}

type PolicyTestResponse struct {
	OK    bool             `json:"ok"`
	Error string           `json:"error,omitempty"`
	HTTP  PolicyRuleCounts `json:"http,omitempty"`
	DNS   PolicyRuleCounts `json:"dns,omitempty"`
}

type PolicyApplyResponse struct {
	OK    bool                `json:"ok"`
	Error string              `json:"error,omitempty"`
	Rules map[string][]string `json:"rules,omitempty"`
}

type PolicyStatusResponse struct {
	Source string              `json:"source"`
	Rules  map[string][]string `json:"rules"`
}

type DeviceInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	PairedAt string `json:"paired_at"`
}

type DevicesResponse struct {
	Devices []DeviceInfo `json:"devices"`
}

type PairCodeRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"` // default 600 (10 minutes)
}

type PairCodeResponse struct {
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
}

// mirrors policy.Alert, redeclared so this package skips importing internal/policy
type Alert struct {
	TS      uint64 `json:"ts"`
	Schema  string `json:"schema"`
	Rule    string `json:"rule"`
	Summary string `json:"summary"`
}

type AlertsResponse struct {
	Alerts []Alert `json:"alerts"`
}
