package namematcher

import (
	"testing"
)

func TestMatchMember(t *testing.T) {
	t.Parallel()

	testingVector := []struct {
		matcher string
		target  string
		expects bool
	}{
		{matcher: "", target: "", expects: true},
		{matcher: "^snowflake.torproject.net$", target: "snowflake.torproject.net", expects: true},
		{matcher: "^snowflake.torproject.net$", target: "faketorproject.net", expects: false},
		{matcher: "snowflake.torproject.net$", target: "faketorproject.net", expects: false},
		{matcher: "snowflake.torproject.net$", target: "snowflake.torproject.net", expects: true},
		{matcher: "snowflake.torproject.net$", target: "imaginary-01-snowflake.torproject.net", expects: true},
		{matcher: "snowflake.torproject.net$", target: "imaginary-aaa-snowflake.torproject.net", expects: true},
		{matcher: "snowflake.torproject.net$", target: "imaginary-aaa-snowflake.faketorproject.net", expects: false},
	}
	for _, v := range testingVector {
		t.Run(v.matcher+"<>"+v.target, func(t *testing.T) {
			matcher := NewNameMatcher(v.matcher)
			if got := matcher.IsMember(v.target); got != v.expects {
				t.Errorf("IsMember(%q) = %v, want %v", v.target, got, v.expects)
			}
		})
	}
}

func TestMatchSubset(t *testing.T) {
	t.Parallel()

	testingVector := []struct {
		matcher string
		target  string
		expects bool
	}{
		{matcher: "", target: "", expects: true},
		{matcher: "^snowflake.torproject.net$", target: "^snowflake.torproject.net$", expects: true},
		{matcher: "snowflake.torproject.net$", target: "^snowflake.torproject.net$", expects: true},
		{matcher: "snowflake.torproject.net$", target: "snowflake.torproject.net$", expects: true},
		{matcher: "snowflake.torproject.net$", target: "testing-snowflake.torproject.net$", expects: true},
		{matcher: "snowflake.torproject.net$", target: "^testing-snowflake.torproject.net$", expects: true},
		{matcher: "snowflake.torproject.net$", target: "", expects: false},
	}
	for _, v := range testingVector {
		t.Run(v.matcher+"<>"+v.target, func(t *testing.T) {
			matcher := NewNameMatcher(v.matcher)
			target := NewNameMatcher(v.target)
			if got := matcher.IsSupersetOf(target); got != v.expects {
				t.Errorf("IsSupersetOf(%q) = %v, want %v", v.target, got, v.expects)
			}
		})
	}
}
