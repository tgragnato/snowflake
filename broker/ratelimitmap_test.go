package main

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestRateLimitMap(t *testing.T) {
	Convey("Test RateLimitMap", t, func() {
		rlm := NewRateLimitMap()

		Convey("adds and stores ProxyPolls", func() {
			t := time.Now().Add(5 * time.Second)
			res, ok := rlm.CheckAndLimit("foo", 5*time.Second)
			So(res.After(t), ShouldBeTrue)
			So(ok, ShouldBeTrue)

			t = time.Now().Add(2 * time.Second)
			res, ok = rlm.CheckAndLimit("bar", 5*time.Second)
			So(res.After(t), ShouldBeTrue)
			So(ok, ShouldBeTrue)
		})
	})

	Convey("Snowflake proxy pool", t, func() {
		pool := NewSnowflakePool()
		pool.pollInterval = time.Second

		Convey("adds snowflakes to the rate limit map", func() {
			So(pool.rateLimitMap.inner.Len(), ShouldEqual, 0)
			_, ok := pool.CheckAndLimit("foo")
			So(ok, ShouldBeTrue)
			So(pool.rateLimitMap.inner.Len(), ShouldEqual, 1)
			_, ok = pool.CheckAndLimit("bar")
			So(ok, ShouldBeTrue)
			So(pool.rateLimitMap.inner.Len(), ShouldEqual, 2)

		})

		Convey("limits snowflake that polls too soon", func() {
			_, ok := pool.CheckAndLimit("foo")
			So(ok, ShouldBeTrue)
			noSoonerThan, ok := pool.CheckAndLimit("foo")
			So(ok, ShouldBeFalse)
			So(time.Now().After(noSoonerThan), ShouldBeFalse)
		})

		Convey("proxies can poll again when limit has expired", func() {
			_, ok := pool.CheckAndLimit("foo")
			So(ok, ShouldBeTrue)
			<-time.After(time.Second)
			noSoonerThan, ok := pool.CheckAndLimit("foo")
			So(ok, ShouldBeTrue)
			So(time.Now().After(noSoonerThan), ShouldBeFalse)
		})
	})
}
