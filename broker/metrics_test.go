package main

import (
	"sync"
	"sync/atomic"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFormatAndClearCountryStats(t *testing.T) {
	Convey("for country stats order", t, func() {
		stats := new(sync.Map)
		for cc, count := range map[string]uint64{
			"IT": 50,
			"FR": 200,
			"TZ": 100,
			"CN": 250,
			"RU": 150,
			"CA": 1,
			"BE": 1,
			"PH": 1,
		} {
			stats.LoadOrStore(cc, new(uint64))
			val, _ := stats.Load(cc)
			ptr := val.(*uint64)
			atomic.AddUint64(ptr, count)
		}
		So(formatAndClearCountryStats(stats, false), ShouldEqual, "CN=250,FR=200,RU=150,TZ=100,IT=50,BE=1,CA=1,PH=1")
		// The map should be cleared on return.
		stats.Range(func(_, _ any) bool { panic("map was not cleared") })
	})
}
