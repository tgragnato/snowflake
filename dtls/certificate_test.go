// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/tls"
	"testing"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func TestGetCertificate(t *testing.T) {
	certificateWildcard, err := selfsign.GenerateSelfSignedWithDNS("*.test.test")
	if err != nil {
		t.Fatal(err)
	}

	certificateTest, err := selfsign.GenerateSelfSignedWithDNS("test.test", "www.test.test", "pop.test.test")
	if err != nil {
		t.Fatal(err)
	}

	certificateRandom, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		localCertificates   []tls.Certificate
		desc                string
		serverName          string
		expectedCertificate tls.Certificate
		getCertificate      func(info *ClientHelloInfo) (*tls.Certificate, error)
	}{
		{
			desc: "Simple match in CN",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "test.test",
			expectedCertificate: certificateTest,
		},
		{
			desc: "Simple match in SANs",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "www.test.test",
			expectedCertificate: certificateTest,
		},

		{
			desc: "Wildcard match",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "foo.test.test",
			expectedCertificate: certificateWildcard,
		},
		{
			desc: "No match return first",
			localCertificates: []tls.Certificate{
				certificateRandom,
				certificateTest,
				certificateWildcard,
			},
			serverName:          "foo.bar",
			expectedCertificate: certificateRandom,
		},
		{
			desc: "Get certificate from callback",
			getCertificate: func(*ClientHelloInfo) (*tls.Certificate, error) {
				return &certificateTest, nil
			},
			expectedCertificate: certificateTest,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			getCertificate := func(info *dtlsconfig.ClientHelloInfo) (*tls.Certificate, error) {
				return test.getCertificate(&ClientHelloInfo{
					ServerName:   info.ServerName,
					CipherSuites: info.CipherSuites,
					RandomBytes:  info.RandomBytes,
				})
			}
			if test.getCertificate == nil {
				getCertificate = nil
			}

			cfg := &handshakeConfig{
				LocalCertificates:   test.localCertificates,
				LocalGetCertificate: getCertificate,
			}
			cert, err := cfg.GetCertificate(&dtlsconfig.ClientHelloInfo{ServerName: test.serverName})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.expectedCertificate.Leaf != cert.Leaf {
				t.Errorf("Certificate Leaf should match expected: got %v, want %v", cert.Leaf, test.expectedCertificate.Leaf)
			}
		})
	}
}
