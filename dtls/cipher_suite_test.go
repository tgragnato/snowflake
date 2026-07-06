// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
)

func TestCipherSuiteName(t *testing.T) {
	testCases := []struct {
		suite    CipherSuiteID
		expected string
	}{
		{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
		{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
		{TLS_PSK_WITH_CHACHA20_POLY1305_SHA256, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"},
		{CipherSuiteID(0x0000), "0x0000"},
	}

	for _, testCase := range testCases {
		res := CipherSuiteName(testCase.suite)
		if res != testCase.expected {
			t.Fatalf("Expected: %s, got %s", testCase.expected, res)
		}
	}
}

func TestAllCipherSuites(t *testing.T) {
	actual := len(allCipherSuites())
	if actual == 0 {
		t.Fatal()
	}
}

func TestInsecureCipherSuites(t *testing.T) {
	if len(InsecureCipherSuites()) != 0 {
		t.Errorf("Expected no insecure ciphersuites")
	}
}

func TestCipherSuites(t *testing.T) {
	ours := allCipherSuites()
	theirs := CipherSuites()
	if len(ours) != len(theirs) {
		t.Fatalf("expected %d cipher suites, got %d", len(ours), len(theirs))
	}

	for i, s := range ours {
		t.Run(s.String(), func(t *testing.T) {
			cipher := theirs[i]
			if cipher.ID != uint16(s.ID()) {
				t.Errorf("expected ID %d, got %d", uint16(s.ID()), cipher.ID)
			}
			if cipher.Name != s.String() {
				t.Errorf("expected name %s, got %s", s.String(), cipher.Name)
			}
			if !reflect.DeepEqual(cipherSuiteSupportedVersionIDs(s.ID()), cipher.SupportedVersions) {
				t.Errorf("expected supported versions %v, got %v", cipherSuiteSupportedVersionIDs(s.ID()), cipher.SupportedVersions)
			}
			if cipher.Insecure {
				t.Error("expected Insecure to be false")
			}
		})
	}
}

func TestCipherSuiteSupportedVersions(t *testing.T) {
	testCases := []struct {
		name     string
		suite    CipherSuiteID
		expected []protocol.Version
	}{
		{
			name:     "TLS 1.3",
			suite:    TLS_CHACHA20_POLY1305_SHA256,
			expected: []protocol.Version{protocol.Version1_3},
		},
		{
			name:     "DTLS 1.2",
			suite:    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			expected: []protocol.Version{protocol.Version1_2},
		},
		{
			name:     "custom suites default to DTLS 1.2",
			suite:    0xffff,
			expected: []protocol.Version{protocol.Version1_2},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if !reflect.DeepEqual(testCase.expected, cipherSuiteSupportedVersions(testCase.suite)) {
				t.Errorf("expected %v, got %v", testCase.expected, cipherSuiteSupportedVersions(testCase.suite))
			}
		})
	}
}

func TestParseCipherSuitesForVersions(t *testing.T) {
	t.Run("default DTLS 1.2", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			nil,
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(suites) == 0 {
			t.Fatal("expected non-empty suites")
		}

		for _, suite := range suites {
			if !cipherSuiteIDSupportsVersion(suite.ID(), protocol.Version1_2) {
				t.Errorf("expected suite %v to support DTLS 1.2", suite.ID())
			}
			if cipherSuiteIDSupportsVersion(suite.ID(), protocol.Version1_3) {
				t.Errorf("expected suite %v not to support DTLS 1.3", suite.ID())
			}
		}
	})

	t.Run("default DTLS 1.3", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			nil,
			nil,
			true,
			false,
			protocol.Version1_3,
			protocol.Version1_3,
		)
		if err != nil {
			t.Fatal(err)
		}
		want := []uint16{uint16(TLS_CHACHA20_POLY1305_SHA256)}
		if !reflect.DeepEqual(want, configCipherSuiteIDs(suites)) {
			t.Fatalf("expected %v, got %v", want, configCipherSuiteIDs(suites))
		}
	})

	t.Run("default dual stack", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			nil,
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_3,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(suites) <= len(defaultCipherSuites13()) {
			t.Fatalf("expected more than %d suites, got %d", len(defaultCipherSuites13()), len(suites))
		}
		ids := configCipherSuiteIDs(suites)
		found := false
		for _, id := range ids {
			if id == uint16(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected suites to contain TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
		}
	})

	t.Run("selected suites are filtered by version", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			},
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		if err != nil {
			t.Fatal(err)
		}
		want := []uint16{uint16(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)}
		if !reflect.DeepEqual(want, configCipherSuiteIDs(suites)) {
			t.Fatalf("expected %v, got %v", want, configCipherSuiteIDs(suites))
		}
	})

	t.Run("selected suite must match version", func(t *testing.T) {
		_, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{},
			nil,
			true,
			false,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		if !errors.Is(err, dtlserrors.ErrNoAvailableCertificateCipherSuite) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNoAvailableCertificateCipherSuite, err)
		}
	})

	t.Run("TLS 1.3 suites are authentication neutral", func(t *testing.T) {
		suites, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{},
			nil,
			false,
			true,
			protocol.Version1_3,
			protocol.Version1_3,
		)
		if err != nil {
			t.Fatal(err)
		}
		want := []uint16{uint16(TLS_CHACHA20_POLY1305_SHA256)}
		if !reflect.DeepEqual(want, configCipherSuiteIDs(suites)) {
			t.Fatalf("expected %v, got %v", want, configCipherSuiteIDs(suites))
		}
	})

	t.Run("custom anonymous suites do not satisfy PSK configs", func(t *testing.T) {
		_, err := parseCipherSuitesForVersions(
			[]CipherSuiteID{},
			func() []CipherSuite {
				return []CipherSuite{&testCustomCipherSuite{authenticationType: CipherSuiteAuthenticationTypeAnonymous}}
			},
			false,
			true,
			protocol.Version1_2,
			protocol.Version1_2,
		)
		if !errors.Is(err, dtlserrors.ErrNoAvailablePSKCipherSuite) {
			t.Fatalf("expected %v, got %v", dtlserrors.ErrNoAvailablePSKCipherSuite, err)
		}
	})
}

// CustomCipher that is just used to assert Custom IDs work.
type testCustomCipherSuite struct {
	ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384
	authenticationType CipherSuiteAuthenticationType
}

func (t *testCustomCipherSuite) ID() CipherSuiteID {
	return 0xFFFF
}

func (t *testCustomCipherSuite) AuthenticationType() CipherSuiteAuthenticationType {
	return t.authenticationType
}

// Assert that two connections that pass in a CipherSuite with a CustomID works.
func TestCustomCipherSuite(t *testing.T) {
	type result struct {
		c   *Conn
		err error
	}

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	runTest := func(cipherFactory func() []CipherSuite) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		resultCh := make(chan result)

		go func() {
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), []ClientOption{
				WithCustomCipherSuites(cipherFactory),
			}, true)
			resultCh <- result{client, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), []ServerOption{
			WithCustomCipherSuites(cipherFactory),
		}, true)

		clientResult := <-resultCh

		if err != nil {
			t.Error(err)
		} else {
			_ = server.Close()
		}

		if clientResult.err != nil {
			t.Error(clientResult.err)
		} else {
			_ = clientResult.c.Close()
		}
	}

	t.Run("Custom ID", func(*testing.T) {
		runTest(func() []CipherSuite {
			return []CipherSuite{&testCustomCipherSuite{authenticationType: CipherSuiteAuthenticationTypeCertificate}}
		})
	})

	t.Run("Anonymous Cipher", func(*testing.T) {
		runTest(func() []CipherSuite {
			return []CipherSuite{&testCustomCipherSuite{authenticationType: CipherSuiteAuthenticationTypeAnonymous}}
		})
	})
}
