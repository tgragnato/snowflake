package sinkcluster

import (
	"strings"
	"testing"
	"time"
)

// TestCount verifies counting unique IPs in a SinkEntry file
func TestCount(t *testing.T) {
	t.Parallel()

	// Use dates that match the recordingStart/recordingEnd in the test data (UTC)
	counter := NewClusterCounter(time.Date(2026, 9, 6, 15, 38, 44, 0, time.UTC), time.Date(2026, 9, 6, 16, 0, 0, 0, time.UTC))

	// Valid gob-encoded hyperloglog data (generated from writer)
	input := `{"recordingStart":"2026-09-06T15:38:44Z","recordingEnd":"2026-09-06T15:39:48Z","recorded":"AwoAAAYGAP0EAAADBgASAwIAARJ/BAEBA3NldAH/gAABBgECAAAK/4AAAfwC2iSOAQMGAAADCgAAAwYAAA=="}
{"recordingStart":"2026-09-06T15:38:44Z","recordingEnd":"2026-09-06T15:39:48Z","recorded":"AwoAAAYGAP0EAAADBgASAwIAARJ/BAEBA3NldAH/gAABBgECAAAK/4AAAfwC2iSOAQMGAAADCgAAAwYAAA=="}
{"recordingStart":"2026-09-06T15:38:44Z","recordingEnd":"2026-09-06T15:39:48Z","recorded":"AwoAAAYGAP0EAAADBgASAwIAARJ/BAEBA3NldAH/gAABBgECAAAK/4AAAfwC2iSOAQMGAAADCgAAAwYAAA=="}`

	reader := strings.NewReader(input)
	result, err := counter.Count(reader)
	if err != nil {
		t.Fatalf("Count() returned error: %v", err)
	}

	if result.ChunkIncluded == 0 {
		t.Error("Expected at least 1 chunk included, got 0")
	}

	if result.Sum == 0 {
		t.Error("Expected positive count, got 0")
	}
}