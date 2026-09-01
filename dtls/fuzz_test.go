// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package dtls

import (
	"os"
	"testing"
)

func FuzzUnmarshalBinary(f *testing.F) {
	// The seed corpus is a head start, not a requirement: when it is absent
	// the target still runs against the cached corpus and generated inputs.
	for _, seed := range []string{
		"testdata/seed/TestResumeClient.raw",
		"testdata/seed/TestResumeServer.raw",
	} {
		if data, err := os.ReadFile(seed); err == nil {
			f.Add(data)
		}
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		deserialized := &State{}
		_ = deserialized.UnmarshalBinary(data)
	})
}
