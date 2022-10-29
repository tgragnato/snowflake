package snowflake_proxy

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestTokens(t *testing.T) {
	Convey("Tokens counter test", t, func() {
		tokens := newTokens()
		So(tokens.count(), ShouldEqual, 0)
		for i := 0; i < 20; i++ {
			tokens.get()
		}
		So(tokens.count(), ShouldEqual, 20)
		tokens.ret()
		So(tokens.count(), ShouldEqual, 19)
	})
}
