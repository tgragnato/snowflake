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
			// The next 3 bin to the same value, 112. When not
			// binned, they should go in the order MY,ZA,AT (ordered
			// by count). When binned, they should go in the order
			// AT,MY,ZA (ordered by country code).
			{"AT", 105},
			{"MY", 112},
			{"ZA", 108},
		} {
			stats.Store(record.cc, &record.count)
		}

		Convey("the order should be correct with binned=false", func() {
			So(formatAndClearCountryStats(stats, false), ShouldEqual, "CN=250,FR=200,RU=150,MY=112,ZA=108,AT=105,TZ=100,IT=50,BE=1,CA=1,PH=1")
		})

		Convey("the order should be correct with binned=true", func() {
			So(formatAndClearCountryStats(stats, true), ShouldEqual, "CN=256,FR=200,RU=152,AT=112,MY=112,ZA=112,TZ=104,IT=56,BE=8,CA=8,PH=8")
		})

		// The map should be cleared on return.
		stats.Range(func(_, _ any) bool { panic("map was not cleared") })
	})
}
