package ipsetsink

import (
	"fmt"
	"math"
	"testing"

	"github.com/clarkduvall/hyperloglog"
)

// countSink dumps the sink and returns the cardinality the HyperLogLog
// structure estimates for it.
func countSink(t *testing.T, sink *IPSetSink) uint64 {
	t.Helper()
	data, err := sink.Dump()
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	structure, err := hyperloglog.NewPlus(18)
	if err != nil {
		t.Fatalf("NewPlus: %v", err)
	}
	if err := structure.GobDecode(data); err != nil {
		t.Fatalf("GobDecode: %v", err)
	}
	return structure.Count()
}

func TestSinkInit(t *testing.T) {
	t.Parallel()

	sink := NewIPSetSink([]byte("demo"))
	sink.AddIPToSet("test1")
	sink.AddIPToSet("test2")
	if count := countSink(t, sink); count < 1 || count > 3 {
		t.Errorf("count = %d, want between 1 and 3", count)
	}
}

func TestSinkCounting(t *testing.T) {
	t.Parallel()

	// The estimate is probabilistic, so allow a 1% relative error.
	const tolerance = 0.01
	for itemCount := 300; itemCount <= 10000; itemCount += 200 {
		sink := NewIPSetSink([]byte("demo"))
		// Add every item twice: the sink must count distinct IPs, so the
		// duplicates should not affect the estimate.
		for range 2 {
			for i := 0; i <= itemCount; i++ {
				sink.AddIPToSet(fmt.Sprintf("demo%v", i))
			}
		}
		count := countSink(t, sink)
		if relErr := math.Abs(float64(count)/float64(itemCount) - 1.0); relErr > tolerance {
			t.Errorf("itemCount %d: count = %d, relative error %v exceeds %v",
				itemCount, count, relErr, tolerance)
		}
	}
}
