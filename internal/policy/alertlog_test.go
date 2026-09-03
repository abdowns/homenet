package policy

import "testing"

func TestAlertLogEviction(t *testing.T) {
	l := NewAlertLog(3)
	for i := uint64(0); i < 5; i++ {
		l.Add(Alert{TS: i, Rule: "r"})
	}
	got := l.Recent(0)
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	for i, want := range []uint64{2, 3, 4} {
		if got[i].TS != want {
			t.Errorf("entry %d: ts = %d, want %d", i, got[i].TS, want)
		}
	}
}

func TestAlertLogRecentN(t *testing.T) {
	l := NewAlertLog(10)
	for i := uint64(0); i < 5; i++ {
		l.Add(Alert{TS: i})
	}
	got := l.Recent(2)
	if len(got) != 2 || got[0].TS != 3 || got[1].TS != 4 {
		t.Errorf("Recent(2) = %+v, want ts 3,4", got)
	}
}
