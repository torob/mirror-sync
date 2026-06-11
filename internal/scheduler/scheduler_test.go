package scheduler

import (
	"testing"
	"time"
)

func TestCronTraditionalDayOrSemantics(t *testing.T) {
	expr, err := parseCron("0 3 1 * 1")
	if err != nil {
		t.Fatal(err)
	}
	monday := time.Date(2026, 6, 8, 3, 0, 0, 0, time.UTC)
	if !expr.matches(monday) {
		t.Fatalf("restricted day-of-week should match")
	}
	firstOfMonth := time.Date(2026, 7, 1, 3, 0, 0, 0, time.UTC)
	if !expr.matches(firstOfMonth) {
		t.Fatalf("restricted day-of-month should match")
	}
	other := time.Date(2026, 7, 2, 3, 0, 0, 0, time.UTC)
	if expr.matches(other) {
		t.Fatalf("unexpected match")
	}
}

func TestCronStepAndSundaySeven(t *testing.T) {
	expr, err := parseCron("*/15 * * * 7")
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 6, 14, 10, 30, 0, 0, time.UTC)
	if !expr.matches(when) {
		t.Fatalf("expected Sunday 7 and */15 minute to match")
	}
}
