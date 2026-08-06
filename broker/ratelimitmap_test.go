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
			t := time.Now().Add(time.Second)
			rlm.Add("foo", t)
			res, _ := rlm.Lookup("foo")
			So(res, ShouldEqual, t)

			t = time.Now().Add(2 * time.Second)
			rlm.Add("bar", t)
			res, _ = rlm.Lookup("bar")
			So(res, ShouldEqual, t)
		})
	})

	Convey("Snowflake proxy pool", t, func() {
		pool := NewSnowflakePool()

		Convey("adds snowflakes to the rate limit map", func() {
			snowflake := NewSnowflake("foo", "", "", 0)
			snowflake.addr = "foo"
			pool.Push(snowflake)

			So(pool.rateLimitMap.inner.Len(), ShouldEqual, 1)
			_, found := pool.rateLimitMap.Lookup("foo")
			So(found, ShouldBeTrue)

			pollInterval := pool.CheckAllowedPollTime("foo").Milliseconds()
			So(pollInterval > 0, ShouldBeTrue)

			snowflake = NewSnowflake("bar", "", "", 0)
			snowflake.addr = "bar"
			pool.Push(snowflake)

			So(pool.rateLimitMap.inner.Len(), ShouldEqual, 2)
			_, found = pool.rateLimitMap.Lookup("bar")
			So(found, ShouldBeTrue)

			pollInterval = pool.CheckAllowedPollTime("bar").Milliseconds()
			So(pollInterval > 0, ShouldBeTrue)

		})
	})
}
