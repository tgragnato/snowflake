// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package protocol

import (
	"errors"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func TestDecodeCompressionMethods(t *testing.T) {
	testCases := []struct {
		buf    []byte
		result []*CompressionMethod
		err    error
	}{
		{[]byte{}, nil, dtlserrors.ErrBufferTooSmall},
	}

	for _, testCase := range testCases {
		_, err := DecodeCompressionMethods(testCase.buf)
		if !errors.Is(err, testCase.err) {
			t.Fatal("Unexpected error", err)
		}
	}
}
