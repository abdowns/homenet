package policy

import "sync"

// Alert is one alert_* rule match.
type Alert struct {
	TS      uint64 `json:"ts"`
	Schema  string `json:"schema"`
	Rule    string `json:"rule"`
	Summary string `json:"summary"`
}

type AlertLog struct {
	mu       sync.Mutex
	entries  []Alert
	capacity int
}

func NewAlertLog(capacity int) *AlertLog {
	return &AlertLog{capacity: capacity}
}

func (l *AlertLog) Add(a Alert) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, a)
	if len(l.entries) > l.capacity {
		l.entries = l.entries[len(l.entries)-l.capacity:]
	}
}

// n <= 0 returns everything held
func (l *AlertLog) Recent(n int) []Alert {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.entries) {
		n = len(l.entries)
	}
	out := make([]Alert, n)
	copy(out, l.entries[len(l.entries)-n:])
	return out
}
