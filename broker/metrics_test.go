package main

import (
	"sync"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestFormatAndClearCountryStats(t *testing.T) {
	Convey("given a mapping of country stats", t, func() {
		stats := new(sync.Map)
		for _, record := range []struct {
			cc    string
			count uint64
		}{
			{"IT", 50},
			{"FR", 200},
			{"TZ", 100},
			{"CN", 250},
			{"RU", 150},
			{"CA", 1},
			{"BE", 1},
			{"PH", 1},
		} {
			stats.Store(record.cc, &record.count)
		}

		Convey("the order should be correct with binned=false", func() {
			So(formatAndClearCountryStats(stats, false), ShouldEqual, "CN=250,FR=200,RU=150,TZ=100,IT=50,BE=1,CA=1,PH=1")
		})

		// The map should be cleared on return.
		stats.Range(func(_, _ any) bool { panic("map was not cleared") })
	})
}
