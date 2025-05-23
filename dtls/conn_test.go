// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/pion/transport/v3/dpipe"
	"github.com/pion/transport/v3/test"
)

var (
	errTestPSKInvalidIdentity = errors.New("TestPSK: Server got invalid identity")
	errPSKRejected            = errors.New("PSK Rejected")
	errNotExpectedChain       = errors.New("not expected chain")
	errExpecedChain           = errors.New("expected chain")
	errWrongCert              = errors.New("wrong cert")
)

func TestStressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	// Run the test
	stressDuplex(t)
}

func stressDuplex(t *testing.T) {
	t.Helper()

	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = ca.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = cb.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 100,
	}

	err = test.StressDuplex(ca, cb, opt)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRoutineLeakOnClose(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ca.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if err := cb.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ca.Close(); err != nil {
		t.Fatal(err)
	}
	// Packet is sent, but not read.
	// inboundLoop routine should not be leaked.
}

func TestReadWriteDeadline(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	var netErr net.Error

	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	if err := ca.SetDeadline(time.Unix(0, 1)); err != nil {
		t.Fatal(err)
	}
	_, werr := ca.Write(make([]byte, 100))
	if errors.As(werr, &netErr) {
		if !netErr.Timeout() {
			t.Error("Deadline exceeded Write must return Timeout error")
		}
		if !netErr.Temporary() {
			t.Error("Deadline exceeded Write must return Temporary error")
		}
	} else {
		t.Error("Write must return net.Error error")
	}
	_, rerr := ca.Read(make([]byte, 100))
	if errors.As(rerr, &netErr) {
		if !netErr.Timeout() {
			t.Error("Deadline exceeded Read must return Timeout error")
		}
		if !netErr.Temporary() {
			t.Error("Deadline exceeded Read must return Temporary error")
		}
	} else {
		t.Error("Read must return net.Error error")
	}
	if err := ca.SetDeadline(time.Time{}); err != nil {
		t.Error(err)
	}

	if err := ca.Close(); err != nil {
		t.Error(err)
	}
	if err := cb.Close(); err != nil {
		t.Error(err)
	}

	if _, err := ca.Write(make([]byte, 100)); !errors.Is(err, ErrConnClosed) {
		t.Errorf("Write must return %v after close, got %v", ErrConnClosed, err)
	}
	if _, err := ca.Read(make([]byte, 100)); !errors.Is(err, io.EOF) {
		t.Errorf("Read must return %v after close, got %v", io.EOF, err)
	}
}

func TestSequenceNumberOverflow(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("ApplicationData", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		if err != nil {
			t.Fatal(err)
		}

		atomic.StoreUint64(&ca.state.localSequenceNumber[1], recordlayer.MaxSequenceNumber)
		if _, werr := ca.Write(make([]byte, 100)); werr != nil {
			t.Errorf("Write must send message with maximum sequence number, but errord: %v", werr)
		}
		if _, werr := ca.Write(make([]byte, 100)); !errors.Is(werr, errSequenceNumberOverflow) {
			t.Errorf("Write must abandonsend message with maximum sequence number, but errord: %v", werr)
		}

		if err := ca.Close(); err != nil {
			t.Error(err)
		}
		if err := cb.Close(); err != nil {
			t.Error(err)
		}
	})
	t.Run("Handshake", func(t *testing.T) {
		ca, cb, err := pipeMemory()
		if err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		atomic.StoreUint64(&ca.state.localSequenceNumber[0], recordlayer.MaxSequenceNumber+1)

		// Try to send handshake packet.
		if werr := ca.writePackets(ctx, []*packet{
			{
				record: &recordlayer.RecordLayer{
					Header: recordlayer.Header{
						Version: protocol.Version1_2,
					},
					Content: &handshake.Handshake{
						Message: &handshake.MessageClientHello{
							Version:            protocol.Version1_2,
							Cookie:             make([]byte, 64),
							CipherSuiteIDs:     cipherSuiteIDs(defaultCipherSuites()),
							CompressionMethods: defaultCompressionMethods(),
						},
					},
				},
			},
		}); !errors.Is(werr, errSequenceNumberOverflow) {
			t.Errorf("Connection must fail on handshake packet reaches maximum sequence number")
		}

		if err := ca.Close(); err != nil {
			t.Error(err)
		}
		if err := cb.Close(); err != nil {
			t.Error(err)
		}
	})
}

func pipeMemory() (*Conn, *Conn, error) {
	// In memory pipe
	ca, cb := dpipe.Pipe()

	return pipeConn(ca, cb)
}

func pipeConn(ca, cb net.Conn) (*Conn, *Conn, error) {
	type result struct {
		c   *Conn
		err error
	}

	resultCh := make(chan result)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup client
	go func() {
		client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
			SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
		}, true)
		resultCh <- result{client, err}
	}()

	// Setup server
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
	}, true)
	if err != nil {
		return nil, nil, err
	}

	// Receive client
	res := <-resultCh
	if res.err != nil {
		_ = server.Close()

		return nil, nil, res.err
	}

	return res.c, server, nil
}

func testClient(
	ctx context.Context,
	pktConn net.PacketConn,
	rAddr net.Addr,
	cfg *Config,
	generateCertificate bool,
) (*Conn, error) {
	if generateCertificate {
		clientCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{clientCert}
	}
	cfg.InsecureSkipVerify = true
	conn, err := Client(pktConn, rAddr, cfg)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func testServer(
	ctx context.Context,
	c net.PacketConn,
	rAddr net.Addr,
	cfg *Config,
	generateCertificate bool,
) (*Conn, error) {
	if generateCertificate {
		serverCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{serverCert}
	}
	conn, err := Server(c, rAddr, cfg)
	if err != nil {
		return nil, err
	}

	return conn, conn.HandshakeContext(ctx)
}

func sendClientHello(cookie []byte, ca net.Conn, sequenceNumber uint64, extensions []extension.Extension) error {
	packet, err := (&recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Version:        protocol.Version1_2,
			SequenceNumber: sequenceNumber,
		},
		Content: &handshake.Handshake{
			Header: handshake.Header{
				MessageSequence: uint16(sequenceNumber),
			},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				Cookie:             cookie,
				CipherSuiteIDs:     cipherSuiteIDs(defaultCipherSuites()),
				CompressionMethods: defaultCompressionMethods(),
				Extensions:         extensions,
			},
		},
	}).Marshal()
	if err != nil {
		return err
	}

	if _, err = ca.Write(packet); err != nil {
		return err
	}

	return nil
}

func TestHandshakeWithInvalidRecord(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		c   *Conn
		err error
	}
	clientErr := make(chan result, 1)
	ca, cb := dpipe.Pipe()
	caWithInvalidRecord := &connWithCallback{Conn: ca}

	var msgSeq atomic.Int32
	// Send invalid record after first message
	caWithInvalidRecord.onWrite = func([]byte) {
		if msgSeq.Add(1) == 2 {
			if _, err := ca.Write([]byte{0x01, 0x02}); err != nil {
				t.Fatal(err)
			}
		}
	}
	go func() {
		client, err := testClient(ctx, dtlsnet.PacketConnFromConn(caWithInvalidRecord), caWithInvalidRecord.RemoteAddr(), &Config{
			CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		}, true)
		clientErr <- result{client, err}
	}()

	server, errServer := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
	}, true)

	errClient := <-clientErr

	defer func() {
		if server != nil {
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
		}

		if errClient.c != nil {
			if err := errClient.c.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}()

	if errServer != nil {
		t.Fatalf("Server failed(%v)", errServer)
	}

	if errClient.err != nil {
		t.Fatalf("Client failed(%v)", errClient.err)
	}
}

func TestExportKeyingMaterial(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	var rand [28]byte
	exportLabel := "EXTRACTOR-dtls_srtp"

	expectedServerKey := []byte{0x30, 0xef, 0x2b, 0x2d, 0x4f, 0x72, 0xe2, 0x3d, 0x2a, 0x13}
	expectedClientKey := []byte{0xc7, 0xf9, 0x75, 0x03, 0x6b, 0x44, 0x10, 0x42, 0x34, 0xcf}

	conn := &Conn{
		state: State{
			localRandom:         handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand},
			remoteRandom:        handshake.Random{GMTUnixTime: time.Unix(1000, 0), RandomBytes: rand},
			localSequenceNumber: []uint64{0, 0},
			cipherSuite:         &ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{},
		},
	}
	conn.setLocalEpoch(0)
	conn.setRemoteEpoch(0)

	state, ok := conn.ConnectionState()
	if !ok {
		t.Fatal("ConnectionState failed")
	}
	_, err := state.ExportKeyingMaterial(exportLabel, nil, 0)
	if !errors.Is(err, errHandshakeInProgress) {
		t.Errorf("ExportKeyingMaterial when epoch == 0: expected '%s' actual '%s'", errHandshakeInProgress, err)
	}

	conn.setLocalEpoch(1)
	state, ok = conn.ConnectionState()
	if !ok {
		t.Fatal("ConnectionState failed")
	}
	_, err = state.ExportKeyingMaterial(exportLabel, []byte{0x00}, 0)
	if !errors.Is(err, errContextUnsupported) {
		t.Errorf("ExportKeyingMaterial with context: expected '%s' actual '%s'", errContextUnsupported, err)
	}

	for k := range invalidKeyingLabels() {
		state, ok = conn.ConnectionState()
		if !ok {
			t.Fatal("ConnectionState failed")
		}
		_, err = state.ExportKeyingMaterial(k, nil, 0)
		if !errors.Is(err, errReservedExportKeyingMaterial) {
			t.Errorf("ExportKeyingMaterial reserved label: expected '%s' actual '%s'", errReservedExportKeyingMaterial, err)
		}
	}

	state, ok = conn.ConnectionState()
	if !ok {
		t.Fatal("ConnectionState failed")
	}
	keyingMaterial, err := state.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedServerKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedServerKey, keyingMaterial)
	}

	conn.state.isClient = true
	state, ok = conn.ConnectionState()
	if !ok {
		t.Fatal("ConnectionState failed")
	}
	keyingMaterial, err = state.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedClientKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedClientKey, keyingMaterial)
	}
}

func TestPSK(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                   string
		ClientIdentity         []byte
		ServerIdentity         []byte
		CipherSuites           []CipherSuiteID
		ClientVerifyConnection func(*State) error
		ServerVerifyConnection func(*State) error
		WantFail               bool
		ExpectedServerErr      string
		ExpectedClientErr      string
	}{
		{
			Name:           "Server identity specified",
			ServerIdentity: []byte("Test Identity"),
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
		},
		{
			Name:           "Server identity specified - Server verify connection fails",
			ServerIdentity: []byte("Test Identity"),
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
			ServerVerifyConnection: func(*State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: errExample.Error(),
			ExpectedClientErr: alert.BadCertificate.String(),
		},
		{
			Name:           "Server identity specified - Client verify connection fails",
			ServerIdentity: []byte("Test Identity"),
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
			ClientVerifyConnection: func(*State) error {
				return errExample
			},
			WantFail:          true,
			ExpectedServerErr: alert.BadCertificate.String(),
			ExpectedClientErr: errExample.Error(),
		},
		{
			Name:           "Server identity nil",
			ServerIdentity: nil,
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
		},
		{
			Name:           "TLS_PSK_WITH_AES_128_GCM_SHA256",
			ServerIdentity: nil,
			ClientIdentity: []byte("Client Identity"),
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
		},
		{
			Name:           "Client identity empty",
			ServerIdentity: nil,
			ClientIdentity: []byte{},
			CipherSuites:   []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			type result struct {
				c   *Conn
				err error
			}
			clientRes := make(chan result, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					PSK: func(hint []byte) ([]byte, error) {
						if !bytes.Equal(test.ServerIdentity, hint) {
							return nil, fmt.Errorf("TestPSK: Client got invalid identity expected(% 02x) actual(% 02x)", test.ServerIdentity, hint)
						}

						return []byte{0xAB, 0xC1, 0x23}, nil
					},
					PSKIdentityHint:  test.ClientIdentity,
					CipherSuites:     test.CipherSuites,
					VerifyConnection: test.ClientVerifyConnection,
				}

				c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
				clientRes <- result{c, err}
			}()

			config := &Config{
				PSK: func(hint []byte) ([]byte, error) {
					fmt.Println(hint)
					if !bytes.Equal(test.ClientIdentity, hint) {
						return nil, fmt.Errorf("%w: expected(% 02x) actual(% 02x)", errTestPSKInvalidIdentity, test.ClientIdentity, hint)
					}

					return []byte{0xAB, 0xC1, 0x23}, nil
				},
				PSKIdentityHint:  test.ServerIdentity,
				CipherSuites:     test.CipherSuites,
				VerifyConnection: test.ServerVerifyConnection,
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, false)
			if test.WantFail {
				res := <-clientRes
				if err == nil || !strings.Contains(err.Error(), test.ExpectedServerErr) {
					t.Fatalf("TestPSK: Server expected(%v) actual(%v)", test.ExpectedServerErr, err)
				}
				if res.err == nil || !strings.Contains(res.err.Error(), test.ExpectedClientErr) {
					t.Fatalf("TestPSK: Client expected(%v) actual(%v)", test.ExpectedClientErr, res.err)
				}

				return
			}
			if err != nil {
				t.Fatalf("TestPSK: Server failed(%v)", err)
			}

			state, ok := server.ConnectionState()
			if !ok {
				t.Fatalf("TestPSK: Server ConnectionState failed")
			}
			actualPSKIdentityHint := state.IdentityHint
			if !bytes.Equal(actualPSKIdentityHint, test.ClientIdentity) {
				t.Errorf(
					"TestPSK: Server ClientPSKIdentity Mismatch '%s': expected(%v) actual(%v)",
					test.Name, test.ClientIdentity, actualPSKIdentityHint,
				)
			}

			defer func() {
				_ = server.Close()
			}()

			res := <-clientRes
			if res.err != nil {
				t.Fatal(res.err)
			}
			_ = res.c.Close()
		})
	}
}

func TestPSKHintFail(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	serverAlertError := &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InternalError}}
	pskRejected := errPSKRejected

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, cb := dpipe.Pipe()
	go func() {
		conf := &Config{
			PSK: func([]byte) ([]byte, error) {
				return nil, pskRejected
			},
			PSKIdentityHint: []byte{},
			CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
		}

		_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
		clientErr <- err
	}()

	config := &Config{
		PSK: func([]byte) ([]byte, error) {
			return nil, pskRejected
		},
		PSKIdentityHint: []byte{},
		CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
	}

	if _, err := testServer(
		ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, false,
	); !errors.Is(err, serverAlertError) {
		t.Fatalf("TestPSK: Server error exp(%v) failed(%v)", serverAlertError, err)
	}

	if err := <-clientErr; !errors.Is(err, pskRejected) {
		t.Fatalf("TestPSK: Client error exp(%v) failed(%v)", pskRejected, err)
	}
}

// Assert that ServerKeyExchange is only sent if Identity is set on server side.
func TestPSKServerKeyExchange(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name        string
		SetIdentity bool
	}{
		{
			Name:        "Server Identity Set",
			SetIdentity: true,
		},
		{
			Name:        "Server Not Identity Set",
			SetIdentity: false,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			gotServerKeyExchange := false

			clientErr := make(chan error, 1)
			ca, cb := dpipe.Pipe()
			cbAnalyzer := &connWithCallback{Conn: cb}
			cbAnalyzer.onWrite = func(in []byte) {
				messages, err := recordlayer.UnpackDatagram(in)
				if err != nil {
					t.Fatal(err)
				}

				for i := range messages {
					h := &handshake.Handshake{}
					_ = h.Unmarshal(messages[i][recordlayer.FixedHeaderSize:])

					if h.Header.Type == handshake.TypeServerKeyExchange {
						gotServerKeyExchange = true
					}
				}
			}

			go func() {
				conf := &Config{
					PSK: func([]byte) ([]byte, error) {
						return []byte{0xAB, 0xC1, 0x23}, nil
					},
					PSKIdentityHint: []byte{0xAB, 0xC1, 0x23},
					CipherSuites:    []CipherSuiteID{ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256},
				}

				if client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false); err != nil {
					clientErr <- err
				} else {
					clientErr <- client.Close()
				}
			}()

			config := &Config{
				PSK: func([]byte) ([]byte, error) {
					return []byte{0xAB, 0xC1, 0x23}, nil
				},
				CipherSuites: []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256},
			}
			if test.SetIdentity {
				config.PSKIdentityHint = []byte{0xAB, 0xC1, 0x23}
			}

			if server, err := testServer(
				ctx, dtlsnet.PacketConnFromConn(cbAnalyzer), cbAnalyzer.RemoteAddr(), config, false,
			); err != nil {
				t.Fatalf("TestPSK: Server error %v", err)
			} else {
				if err = server.Close(); err != nil {
					t.Fatal(err)
				}
			}

			if err := <-clientErr; err != nil {
				t.Fatalf("TestPSK: Client error %v", err)
			}

			if gotServerKeyExchange != test.SetIdentity {
				t.Fatalf(
					"Mismatch between setting Identity and getting a ServerKeyExchange exp(%t) actual(%t)",
					test.SetIdentity, gotServerKeyExchange,
				)
			}
		})
	}
}

func TestClientTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	clientErr := make(chan error, 1)

	ca, _ := dpipe.Pipe()
	go func() {
		conf := &Config{}

		c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, true)
		if err == nil {
			_ = c.Close()
		}
		clientErr <- err
	}()

	// no server!
	err := <-clientErr
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Client error exp(Temporary network error) failed(%v)", err)
	}
}

func TestSRTPConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                          string
		ClientSRTP                    []SRTPProtectionProfile
		ServerSRTP                    []SRTPProtectionProfile
		ClientSRTPMasterKeyIdentifier []byte
		ServerSRTPMasterKeyIdentifier []byte
		ExpectedProfile               SRTPProtectionProfile
		WantClientError               error
		WantServerError               error
	}{
		{
			Name:            "No SRTP in use",
			ClientSRTP:      nil,
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:                          "SRTP both ends",
			ClientSRTP:                    []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:                    []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile:               SRTP_AES128_CM_HMAC_SHA1_80,
			ClientSRTPMasterKeyIdentifier: []byte("ClientSRTPMKI"),
			ServerSRTPMasterKeyIdentifier: []byte("ServerSRTPMKI"),
			WantClientError:               nil,
			WantServerError:               nil,
		},
		{
			Name:            "SRTP client only",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			WantServerError: errServerNoMatchingSRTPProfile,
		},
		{
			Name:            "SRTP server only",
			ClientSRTP:      nil,
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "Multiple Suites",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "Multiple Suites, Client Chooses",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AES128_CM_HMAC_SHA1_32},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_32, SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
				SRTPProtectionProfiles: test.ClientSRTP, SRTPMasterKeyIdentifier: test.ServerSRTPMasterKeyIdentifier,
			}, true)
			resultCh <- result{client, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			SRTPProtectionProfiles: test.ServerSRTP, SRTPMasterKeyIdentifier: test.ClientSRTPMasterKeyIdentifier,
		}, true)
		if !errors.Is(err, test.WantServerError) {
			t.Errorf(
				"TestSRTPConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)",
				test.Name, test.WantServerError, err,
			)
		}
		if err == nil {
			defer func() {
				_ = server.Close()
			}()
		}

		res := <-resultCh
		if res.err == nil {
			defer func() {
				_ = res.c.Close()
			}()
		}
		if !errors.Is(res.err, test.WantClientError) {
			t.Fatalf(
				"TestSRTPConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)",
				test.Name, test.WantClientError, res.err,
			)
		}
		if res.c == nil {
			return
		}

		actualClientSRTP, _ := res.c.SelectedSRTPProtectionProfile()
		if actualClientSRTP != test.ExpectedProfile {
			t.Errorf(
				"TestSRTPConfiguration: Client SRTPProtectionProfile Mismatch '%s': expected(%v) actual(%v)",
				test.Name, test.ExpectedProfile, actualClientSRTP,
			)
		}

		actualServerSRTP, _ := server.SelectedSRTPProtectionProfile()
		if actualServerSRTP != test.ExpectedProfile {
			t.Errorf(
				"TestSRTPConfiguration: Server SRTPProtectionProfile Mismatch '%s': expected(%v) actual(%v)",
				test.Name, test.ExpectedProfile, actualServerSRTP,
			)
		}

		actualServerMKI, _ := server.RemoteSRTPMasterKeyIdentifier()
		if !bytes.Equal(actualServerMKI, test.ServerSRTPMasterKeyIdentifier) {
			t.Errorf(
				"TestSRTPConfiguration: Server SRTPMKI Mismatch '%s': expected(%v) actual(%v)",
				test.Name, test.ServerSRTPMasterKeyIdentifier, actualServerMKI,
			)
		}

		actualClientMKI, _ := res.c.RemoteSRTPMasterKeyIdentifier()
		if !bytes.Equal(actualClientMKI, test.ClientSRTPMasterKeyIdentifier) {
			t.Errorf(
				"TestSRTPConfiguration: Client SRTPMKI Mismatch '%s': expected(%v) actual(%v)",
				test.Name, test.ClientSRTPMasterKeyIdentifier, actualClientMKI,
			)
		}
	}
}

func TestClientCertificate(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	srvCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	srvCAPool := x509.NewCertPool()
	srvCertificate, err := x509.ParseCertificate(srvCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	srvCAPool.AddCert(srvCertificate)

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientCfg *Config
			serverCfg *Config
			wantErr   bool
		}{
			"NoClientCert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
				},
			},
			"NoClientCert_ServerVerifyConnectionFails": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
					VerifyConnection: func(*State) error {
						return errExample
					},
				},
				wantErr: true,
			},
			"NoClientCert_ClientVerifyConnectionFails": {
				clientCfg: &Config{RootCAs: srvCAPool, VerifyConnection: func(*State) error {
					return errExample
				}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   NoClientCert,
					ClientCAs:    caPool,
				},
				wantErr: true,
			},
			"NoClientCert_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
			},
			"RequestClientCert_cert_sigscheme": { // specify signature algorithm
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP521AndSHA512},
					Certificates:     []tls.Certificate{srvCert},
					ClientAuth:       RequestClientCert,
				},
			},
			"RequestClientCert_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequestClientCert,
				},
			},
			"RequestClientCert_no_cert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequestClientCert,
					ClientCAs:    caPool,
				},
			},
			"RequireAnyClientCert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
			},
			"RequireAnyClientCert_error": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAnyClientCert,
				},
				wantErr: true,
			},
			"VerifyClientCertIfGiven_no_cert": {
				clientCfg: &Config{RootCAs: srvCAPool},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
					ClientCAs:    caPool,
				},
			},
			"VerifyClientCertIfGiven_cert": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
					ClientCAs:    caPool,
				},
			},
			"VerifyClientCertIfGiven_error": {
				clientCfg: &Config{RootCAs: srvCAPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   VerifyClientCertIfGiven,
				},
				wantErr: true,
			},
			"RequireAndVerifyClientCert": {
				clientCfg: &Config{
					RootCAs:      srvCAPool,
					Certificates: []tls.Certificate{cert},
					VerifyConnection: func(s *State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], srvCertificate.Raw); !ok {
							return errExample
						}

						return nil
					},
				},
				serverCfg: &Config{
					Certificates: []tls.Certificate{srvCert},
					ClientAuth:   RequireAndVerifyClientCert,
					ClientCAs:    caPool,
					VerifyConnection: func(s *State) error {
						if ok := bytes.Equal(s.PeerCertificates[0], certificate.Raw); !ok {
							return errExample
						}

						return nil
					},
				},
			},
			"RequireAndVerifyClientCert_callbacks": {
				clientCfg: &Config{
					RootCAs: srvCAPool,
					// Certificates:   []tls.Certificate{cert},
					GetClientCertificate: func(*CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
				},
				serverCfg: &Config{
					GetCertificate: func(*ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil },
					// Certificates:   []tls.Certificate{srvCert},
					ClientAuth: RequireAndVerifyClientCert,
					ClientCAs:  caPool,
				},
			},
		}
		for name, tt := range tests {
			tt := tt
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				type result struct {
					c          *Conn
					err, hserr error
				}
				c := make(chan result)

				go func() {
					client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg)
					c <- result{client, err, client.Handshake()}
				}()

				server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg)
				hserr := server.Handshake()
				res := <-c
				defer func() {
					if err == nil {
						_ = server.Close()
					}
					if res.err == nil {
						_ = res.c.Close()
					}
				}()

				if tt.wantErr {
					if err != nil || hserr != nil {
						// Error expected, test succeeded
						return
					}
					t.Error("Error expected")
				}
				if err != nil {
					t.Errorf("Server failed(%v)", err)
				}

				if res.err != nil {
					t.Errorf("Client failed(%v)", res.err)
				}

				state, ok := server.ConnectionState()
				if !ok {
					t.Error("Server connection state not available")
				}
				actualClientCert := state.PeerCertificates
				if tt.serverCfg.ClientAuth == RequireAnyClientCert ||
					tt.serverCfg.ClientAuth == RequireAndVerifyClientCert {
					if actualClientCert == nil {
						t.Errorf("Client did not provide a certificate")
					}

					var cfgCert [][]byte
					if len(tt.clientCfg.Certificates) > 0 {
						cfgCert = tt.clientCfg.Certificates[0].Certificate
					}
					if tt.clientCfg.GetClientCertificate != nil {
						crt, err := tt.clientCfg.GetClientCertificate(&CertificateRequestInfo{})
						if err != nil {
							t.Errorf("Server configuration did not provide a certificate")
						}
						cfgCert = crt.Certificate
					}
					if len(cfgCert) == 0 || !bytes.Equal(cfgCert[0], actualClientCert[0]) {
						t.Errorf("Client certificate was not communicated correctly")
					}
				}
				if tt.serverCfg.ClientAuth == NoClientCert {
					if actualClientCert != nil {
						t.Errorf("Client certificate wasn't expected")
					}
				}

				clientState, ok := res.c.ConnectionState()
				if !ok {
					t.Error("Client connection state not available")
				}
				actualServerCert := clientState.PeerCertificates
				if actualServerCert == nil {
					t.Errorf("Server did not provide a certificate")
				}
				var cfgCert [][]byte
				if len(tt.serverCfg.Certificates) > 0 {
					cfgCert = tt.serverCfg.Certificates[0].Certificate
				}
				if tt.serverCfg.GetCertificate != nil {
					crt, err := tt.serverCfg.GetCertificate(&ClientHelloInfo{})
					if err != nil {
						t.Errorf("Server configuration did not provide a certificate")
					}
					cfgCert = crt.Certificate
				}
				if len(cfgCert) == 0 || !bytes.Equal(cfgCert[0], actualServerCert[0]) {
					t.Errorf("Server certificate was not communicated correctly")
				}
			})
		}
	})
}

func TestConnectionID(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	clientCID := []byte{5, 77, 33, 24, 93, 27, 45, 81}
	serverCID := []byte{64, 24, 73, 2, 17, 96, 38, 59}
	cidEcho := func(echo []byte) func() []byte {
		return func() []byte {
			return echo
		}
	}
	tests := map[string]struct {
		clientCfg          *Config
		serverCfg          *Config
		clientConnectionID []byte
		serverConnectionID []byte
	}{
		"BidirectionalConnectionIDs": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(clientCID),
			},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(serverCID),
			},
			clientConnectionID: clientCID,
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyClientSends": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(nil),
			},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(serverCID),
			},
			serverConnectionID: serverCID,
		},
		"BothSupportOnlyServerSends": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(clientCID),
			},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(nil),
			},
			clientConnectionID: clientCID,
		},
		"ClientDoesNotSupport": {
			clientCfg: &Config{},
			serverCfg: &Config{
				ConnectionIDGenerator: cidEcho(serverCID),
			},
		},
		"ServerDoesNotSupport": {
			clientCfg: &Config{
				ConnectionIDGenerator: cidEcho(clientCID),
			},
			serverCfg: &Config{},
		},
		"NeitherSupport": {
			clientCfg: &Config{},
			serverCfg: &Config{},
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg, true)
			if err != nil {
				t.Fatalf("Unexpected server error: %v", err)
			}
			res := <-c
			if res.err != nil {
				t.Fatalf("Unexpected client error: %v", res.err)
			}
			defer func() {
				if err == nil {
					_ = server.Close()
				}
				if res.err == nil {
					_ = res.c.Close()
				}
			}()

			if !bytes.Equal(res.c.state.getLocalConnectionID(), tt.clientConnectionID) {
				t.Errorf(
					"Unexpected client local connection ID\nwant: %v\ngot:%v",
					tt.clientConnectionID, res.c.state.localConnectionID,
				)
			}
			if !bytes.Equal(res.c.state.remoteConnectionID, tt.serverConnectionID) {
				t.Errorf(
					"Unexpected client remote connection ID\nwant: %v\ngot:%v",
					tt.serverConnectionID, res.c.state.remoteConnectionID,
				)
			}
			if !bytes.Equal(server.state.getLocalConnectionID(), tt.serverConnectionID) {
				t.Errorf(
					"Unexpected server local connection ID\nwant: %v\ngot:%v",
					tt.serverConnectionID, server.state.localConnectionID,
				)
			}
			if !bytes.Equal(server.state.remoteConnectionID, tt.clientConnectionID) {
				t.Errorf(
					"Unexpected server remote connection ID\nwant: %v\ngot:%v",
					tt.clientConnectionID, server.state.remoteConnectionID,
				)
			}
		})
	}
}

func TestExtendedMasterSecret(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	tests := map[string]struct {
		clientCfg         *Config
		serverCfg         *Config
		expectedClientErr error
		expectedServerErr error
	}{
		"Request_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Request_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Require_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: errClientRequiredButNoServerEMS,
			expectedServerErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
		},
		"Disable_Request_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequestExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
		"Disable_Require_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: RequireExtendedMasterSecret,
			},
			expectedClientErr: &alertError{&alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}},
			expectedServerErr: errServerRequiredButNoClientEMS,
		},
		"Disable_Disable_ExtendedMasterSecret": {
			clientCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			serverCfg: &Config{
				ExtendedMasterSecret: DisableExtendedMasterSecret,
			},
			expectedClientErr: nil,
			expectedServerErr: nil,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			c := make(chan result)

			go func() {
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg, true)
				c <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg, true)
			res := <-c
			defer func() {
				if err == nil {
					_ = server.Close()
				}
				if res.err == nil {
					_ = res.c.Close()
				}
			}()

			if !errors.Is(res.err, tt.expectedClientErr) {
				t.Errorf("Client error expected: \"%v\" but got \"%v\"", tt.expectedClientErr, res.err)
			}

			if !errors.Is(err, tt.expectedServerErr) {
				t.Errorf("Server error expected: \"%v\" but got \"%v\"", tt.expectedServerErr, err)
			}
		})
	}
}

func TestServerCertificate(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(certificate)

	t.Run("parallel", func(t *testing.T) { // sync routines to check routine leak
		tests := map[string]struct {
			clientCfg *Config
			serverCfg *Config
			wantErr   bool
		}{
			"no_ca": {
				clientCfg: &Config{},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
			"good_ca": {
				clientCfg: &Config{RootCAs: caPool},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"no_ca_skip_verify": {
				clientCfg: &Config{InsecureSkipVerify: true},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"good_ca_skip_verify_custom_verify_peer": {
				clientCfg: &Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					Certificates: []tls.Certificate{cert},
					ClientAuth:   RequireAnyClientCert,
					VerifyPeerCertificate: func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) != 0 {
							return errNotExpectedChain
						}

						return nil
					},
				},
			},
			"good_ca_verify_custom_verify_peer": {
				clientCfg: &Config{RootCAs: caPool, Certificates: []tls.Certificate{cert}},
				serverCfg: &Config{
					ClientCAs:    caPool,
					Certificates: []tls.Certificate{cert},
					ClientAuth:   RequireAndVerifyClientCert,
					VerifyPeerCertificate: func(_ [][]byte, chain [][]*x509.Certificate) error {
						if len(chain) == 0 {
							return errExpecedChain
						}

						return nil
					},
				},
			},
			"good_ca_custom_verify_peer": {
				clientCfg: &Config{
					RootCAs: caPool,
					VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
						return errWrongCert
					},
				},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
			"server_name": {
				clientCfg: &Config{RootCAs: caPool, ServerName: certificate.Subject.CommonName},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
			},
			"server_name_error": {
				clientCfg: &Config{RootCAs: caPool, ServerName: "barfoo"},
				serverCfg: &Config{Certificates: []tls.Certificate{cert}, ClientAuth: NoClientCert},
				wantErr:   true,
			},
		}
		for name, tt := range tests {
			tt := tt
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()

				type result struct {
					c          *Conn
					err, hserr error
				}
				srvCh := make(chan result)
				go func() {
					s, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), tt.serverCfg)
					srvCh <- result{s, err, s.Handshake()}
				}()

				cli, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), tt.clientCfg)
				hserr := cli.Handshake()
				if err == nil {
					_ = cli.Close()
				}
				if !tt.wantErr && (err != nil || hserr != nil) {
					t.Errorf("Client failed(%v, %v)", err, hserr)
				}
				if tt.wantErr && err == nil && hserr == nil {
					t.Fatal("Error expected")
				}

				srv := <-srvCh
				if srv.err == nil {
					_ = srv.c.Close()
				}
			})
		}
	})
}

func TestCipherSuiteConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                    string
		ClientCipherSuites      []CipherSuiteID
		ServerCipherSuites      []CipherSuiteID
		WantClientError         error
		WantServerError         error
		WantSelectedCipherSuite CipherSuiteID
	}{
		{
			Name:               "No CipherSuites specified",
			ClientCipherSuites: nil,
			ServerCipherSuites: nil,
			WantClientError:    nil,
			WantServerError:    nil,
		},
		{
			Name:               "Invalid CipherSuite",
			ClientCipherSuites: []CipherSuiteID{0x00},
			ServerCipherSuites: []CipherSuiteID{0x00},
			WantClientError:    &invalidCipherSuiteError{0x00},
			WantServerError:    &invalidCipherSuiteError{0x00},
		},
		{
			Name:                    "Valid CipherSuites specified",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		{
			Name:                    "Server supports subset of client suites",
			ClientCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_PSK_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites:      []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
			WantClientError:         nil,
			WantServerError:         nil,
			WantSelectedCipherSuite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			resultCh := make(chan result)

			go func() {
				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
					CipherSuites: test.ClientCipherSuites,
				}, true)
				resultCh <- result{client, err}
			}()

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
				CipherSuites: test.ServerCipherSuites,
			}, true)
			if err == nil {
				defer func() {
					_ = server.Close()
				}()
			}
			if !errors.Is(err, test.WantServerError) {
				t.Errorf(
					"TestCipherSuiteConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)",
					test.Name, test.WantServerError, err,
				)
			}

			res := <-resultCh
			if res.err == nil {
				_ = server.Close()
				_ = res.c.Close()
			}
			if !errors.Is(res.err, test.WantClientError) {
				t.Errorf(
					"TestSRTPConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)",
					test.Name, test.WantClientError, res.err,
				)
			}
			if test.WantSelectedCipherSuite != 0x00 && res.c.state.cipherSuite.ID() != test.WantSelectedCipherSuite {
				t.Errorf(
					"TestCipherSuiteConfiguration: Server Selected Bad Cipher Suite '%s': expected(%v) actual(%v)",
					test.Name, test.WantSelectedCipherSuite, res.c.state.cipherSuite.ID(),
				)
			}
		})
	}
}

func TestCertificateAndPSKServer(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name      string
		ClientPSK bool
	}{
		{
			Name:      "Client uses PKI",
			ClientPSK: false,
		},
		{
			Name:      "Client uses PSK",
			ClientPSK: true,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			type result struct {
				c   *Conn
				err error
			}
			resultCh := make(chan result)

			go func() {
				config := &Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}}
				if test.ClientPSK {
					config.PSK = func([]byte) ([]byte, error) {
						return []byte{0x00, 0x01, 0x02}, nil
					}
					config.PSKIdentityHint = []byte{0x00}
					config.CipherSuites = []CipherSuiteID{TLS_PSK_WITH_AES_128_GCM_SHA256}
				}

				client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
				resultCh <- result{client, err}
			}()

			config := &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_PSK_WITH_AES_128_GCM_SHA256},
				PSK: func([]byte) ([]byte, error) {
					return []byte{0x00, 0x01, 0x02}, nil
				},
			}

			server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
			if err == nil {
				defer func() {
					_ = server.Close()
				}()
			} else {
				t.Errorf("TestCertificateAndPSKServer: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, nil, err)
			}

			res := <-resultCh
			if res.err == nil {
				_ = server.Close()
				_ = res.c.Close()
			} else {
				t.Errorf(
					"TestCertificateAndPSKServer: Client Error Mismatch '%s': expected(%v) actual(%v)",
					test.Name, nil, res.err,
				)
			}
		})
	}
}

func TestPSKConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                 string
		ClientHasCertificate bool
		ServerHasCertificate bool
		ClientPSK            PSKCallback
		ServerPSK            PSKCallback
		ClientPSKIdentity    []byte
		ServerPSKIdentity    []byte
		WantClientError      error
		WantServerError      error
	}{
		{
			Name:                 "PSK and no certificate specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errNoAvailablePSKCipherSuite,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "PSK and certificate specified",
			ClientHasCertificate: true,
			ServerHasCertificate: true,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errNoAvailablePSKCipherSuite,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "PSK and no identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    nil,
			ServerPSKIdentity:    nil,
			WantClientError:      errPSKAndIdentityMustBeSetForClient,
			WantServerError:      errNoAvailablePSKCipherSuite,
		},
		{
			Name:                 "No PSK and identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            nil,
			ServerPSK:            nil,
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errIdentityNoPSK,
			WantServerError:      errIdentityNoPSK,
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			client, err := testClient(
				ctx,
				dtlsnet.PacketConnFromConn(ca),
				ca.RemoteAddr(),
				&Config{PSK: test.ClientPSK, PSKIdentityHint: test.ClientPSKIdentity},
				test.ClientHasCertificate,
			)
			resultCh <- result{client, err}
		}()

		_, err := testServer(
			ctx,
			dtlsnet.PacketConnFromConn(cb),
			cb.RemoteAddr(),
			&Config{PSK: test.ServerPSK, PSKIdentityHint: test.ServerPSKIdentity},
			test.ServerHasCertificate,
		)
		if err != nil || test.WantServerError != nil {
			if !(err != nil && test.WantServerError != nil && err.Error() == test.WantServerError.Error()) {
				t.Fatalf(
					"TestPSKConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)",
					test.Name, test.WantServerError, err,
				)
			}
		}

		res := <-resultCh
		if res.err != nil || test.WantClientError != nil {
			if !(res.err != nil && test.WantClientError != nil && res.err.Error() == test.WantClientError.Error()) {
				t.Fatalf(
					"TestPSKConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)",
					test.Name,
					test.WantClientError,
					res.err,
				)
			}
		}
	}
}

func TestServerTimeout(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookie := make([]byte, 20)
	_, err := rand.Read(cookie)
	if err != nil {
		t.Fatal(err)
	}

	var rand [28]byte
	random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

	cipherSuites := []CipherSuite{
		&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{},
	}

	extensions := []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: []signaturehash.Algorithm{
				{Hash: hash.SHA256, Signature: signature.ECDSA},
				{Hash: hash.SHA384, Signature: signature.ECDSA},
				{Hash: hash.SHA512, Signature: signature.ECDSA},
			},
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P384},
		},
		&extension.SupportedPointFormats{
			PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
		},
	}

	record := &recordlayer.RecordLayer{
		Header: recordlayer.Header{
			SequenceNumber: 0,
			Version:        protocol.Version1_2,
		},
		Content: &handshake.Handshake{
			// sequenceNumber and messageSequence line up, may need to be re-evaluated
			Header: handshake.Header{
				MessageSequence: 0,
			},
			Message: &handshake.MessageClientHello{
				Version:            protocol.Version1_2,
				Cookie:             cookie,
				Random:             random,
				CipherSuiteIDs:     cipherSuiteIDs(cipherSuites),
				CompressionMethods: defaultCompressionMethods(),
				Extensions:         extensions,
			},
		},
	}

	packet, err := record.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	ca, cb := dpipe.Pipe()
	defer func() {
		err := ca.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Client reader
	caReadChan := make(chan []byte, 1000)
	go func() {
		for {
			data := make([]byte, 8192)
			n, err := ca.Read(data)
			if err != nil {
				return
			}

			caReadChan <- data[:n]
		}
	}()

	// Start sending ClientHello packets until server responds with first packet
	go func() {
		for {
			select {
			case <-time.After(10 * time.Millisecond):
				_, err := ca.Write(packet)
				if err != nil {
					return
				}
			case <-caReadChan:
				// Once we receive the first reply from the server, stop
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		FlightInterval: 100 * time.Millisecond,
	}

	_, serverErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
	var netErr net.Error
	if !errors.As(serverErr, &netErr) || !netErr.Timeout() {
		t.Fatalf("Client error exp(Temporary network error) failed(%v)", serverErr)
	}

	// Wait a little longer to ensure no additional messages have been sent by the server
	time.Sleep(300 * time.Millisecond)
	select {
	case msg := <-caReadChan:
		t.Fatalf("Expected no additional messages from server, got: %+v", msg)
	default:
	}
}

func TestProtocolVersionValidation(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookie := make([]byte, 20)
	if _, err := rand.Read(cookie); err != nil {
		t.Fatal(err)
	}

	var rand [28]byte
	random := handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: rand}

	config := &Config{
		CipherSuites:   []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		FlightInterval: 100 * time.Millisecond,
	}

	t.Run("Server", func(t *testing.T) {
		serverCases := map[string]struct {
			records []*recordlayer.RecordLayer
		}{
			"ClientHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
				},
			},
			"SecondsClientHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version1_2,
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
					{
						Header: recordlayer.Header{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageClientHello{
								Version:            protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Cookie:             cookie,
								Random:             random,
								CipherSuiteIDs:     []uint16{uint16((&ciphersuite.TLSEcdheEcdsaWithAes256GcmSha384{}).ID())},
								CompressionMethods: defaultCompressionMethods(),
							},
						},
					},
				},
			},
		}
		for name, serverCase := range serverCases {
			serverCase := serverCase
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				defer func() {
					err := ca.Close()
					if err != nil {
						t.Error(err)
					}
				}()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				var wg sync.WaitGroup
				wg.Add(1)
				defer wg.Wait()
				go func() {
					defer wg.Done()
					if _, err := testServer(
						ctx,
						dtlsnet.PacketConnFromConn(cb),
						cb.RemoteAddr(),
						config,
						true,
					); !errors.Is(err, errUnsupportedProtocolVersion) {
						t.Errorf("Client error exp(%v) failed(%v)", errUnsupportedProtocolVersion, err)
					}
				}()

				time.Sleep(50 * time.Millisecond)

				resp := make([]byte, 1024)
				for _, record := range serverCase.records {
					packet, err := record.Marshal()
					if err != nil {
						t.Fatal(err)
					}
					if _, werr := ca.Write(packet); werr != nil {
						t.Fatal(werr)
					}
					n, rerr := ca.Read(resp[:cap(resp)])
					if rerr != nil {
						t.Fatal(rerr)
					}
					resp = resp[:n]
				}

				h := &recordlayer.Header{}
				if err := h.Unmarshal(resp); err != nil {
					t.Fatal("Failed to unmarshal response")
				}
				if h.ContentType != protocol.ContentTypeAlert {
					t.Errorf("Peer must return alert to unsupported protocol version")
				}
			})
		}
	})

	t.Run("Client", func(t *testing.T) {
		clientCases := map[string]struct {
			records []*recordlayer.RecordLayer
		}{
			"ServerHelloVersion": {
				records: []*recordlayer.RecordLayer{
					{
						Header: recordlayer.Header{
							Version: protocol.Version1_2,
						},
						Content: &handshake.Handshake{
							Message: &handshake.MessageHelloVerifyRequest{
								Version: protocol.Version1_2,
								Cookie:  cookie,
							},
						},
					},
					{
						Header: recordlayer.Header{
							Version:        protocol.Version1_2,
							SequenceNumber: 1,
						},
						Content: &handshake.Handshake{
							Header: handshake.Header{
								MessageSequence: 1,
							},
							Message: &handshake.MessageServerHello{
								Version:           protocol.Version{Major: 0xfe, Minor: 0xff}, // try to downgrade
								Random:            random,
								CipherSuiteID:     func() *uint16 { id := uint16(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384); return &id }(),
								CompressionMethod: defaultCompressionMethods()[0],
							},
						},
					},
				},
			},
		}
		for name, clientCase := range clientCases {
			clientCase := clientCase
			t.Run(name, func(t *testing.T) {
				ca, cb := dpipe.Pipe()
				defer func() {
					err := ca.Close()
					if err != nil {
						t.Error(err)
					}
				}()

				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				var wg sync.WaitGroup
				wg.Add(1)
				defer wg.Wait()
				go func() {
					defer wg.Done()
					if _, err := testClient(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true); !errors.Is(
						err, errUnsupportedProtocolVersion,
					) {
						t.Errorf("Server error exp(%v) failed(%v)", errUnsupportedProtocolVersion, err)
					}
				}()

				time.Sleep(50 * time.Millisecond)

				for _, record := range clientCase.records {
					if _, err := ca.Read(make([]byte, 1024)); err != nil {
						t.Fatal(err)
					}

					packet, err := record.Marshal()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := ca.Write(packet); err != nil {
						t.Fatal(err)
					}
				}
				resp := make([]byte, 1024)
				n, err := ca.Read(resp)
				if err != nil {
					t.Fatal(err)
				}
				resp = resp[:n]

				h := &recordlayer.Header{}
				if err := h.Unmarshal(resp); err != nil {
					t.Fatal("Failed to unmarshal response")
				}
				if h.ContentType != protocol.ContentTypeAlert {
					t.Errorf("Peer must return alert to unsupported protocol version")
				}
			})
		}
	})
}

func TestMultipleHelloVerifyRequest(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	cookies := [][]byte{
		// first clientHello contains an empty cookie
		{},
	}
	var packets [][]byte
	for i := 0; i < 2; i++ {
		cookie := make([]byte, 20)
		if _, err := rand.Read(cookie); err != nil {
			t.Fatal(err)
		}
		cookies = append(cookies, cookie)

		record := &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				SequenceNumber: uint64(i),
				Version:        protocol.Version1_2,
			},
			Content: &handshake.Handshake{
				Header: handshake.Header{
					MessageSequence: uint16(i),
				},
				Message: &handshake.MessageHelloVerifyRequest{
					Version: protocol.Version1_2,
					Cookie:  cookie,
				},
			},
		}
		packet, err := record.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
	}

	ca, cb := dpipe.Pipe()
	defer func() {
		err := ca.Close()
		if err != nil {
			t.Error(err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{}, false)
	}()

	for i, cookie := range cookies {
		// read client hello
		resp := make([]byte, 1024)
		n, err := cb.Read(resp)
		if err != nil {
			t.Fatal(err)
		}
		record := &recordlayer.RecordLayer{}
		if err := record.Unmarshal(resp[:n]); err != nil {
			t.Fatal(err)
		}
		clientHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageClientHello)
		if !ok {
			t.Fatal("Failed to cast MessageClientHello")
		}

		if !bytes.Equal(clientHello.Cookie, cookie) {
			t.Fatalf("Wrong cookie, expected: %x, got: %x", clientHello.Cookie, cookie)
		}
		if len(packets) <= i {
			break
		}
		// write hello verify request
		if _, err := cb.Write(packets[i]); err != nil {
			t.Fatal(err)
		}
	}
	cancel()
}

// Assert that a DTLS Server always responds with RenegotiationInfo if
// a ClientHello contained that extension or not.
func TestRenegotationInfo(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	resp := make([]byte, 1024)

	for _, testCase := range []struct {
		Name                  string
		SendRenegotiationInfo bool
	}{
		{
			"Include RenegotiationInfo",
			true,
		},
		{
			"No RenegotiationInfo",
			false,
		},
	} {
		test := testCase
		t.Run(test.Name, func(t *testing.T) {
			ca, cb := dpipe.Pipe()
			defer func() {
				if err := ca.Close(); err != nil {
					t.Error(err)
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			go func() {
				if _, err := testServer(
					ctx,
					dtlsnet.PacketConnFromConn(cb),
					cb.RemoteAddr(),
					&Config{},
					true,
				); !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
			}()

			time.Sleep(50 * time.Millisecond)

			extensions := []extension.Extension{}
			if test.SendRenegotiationInfo {
				extensions = append(extensions, &extension.RenegotiationInfo{
					RenegotiatedConnection: 0,
				})
			}
			err := sendClientHello([]byte{}, ca, 0, extensions)
			if err != nil {
				t.Fatal(err)
			}
			n, err := ca.Read(resp)
			if err != nil {
				t.Fatal(err)
			}
			record := &recordlayer.RecordLayer{}
			if err = record.Unmarshal(resp[:n]); err != nil {
				t.Fatal(err)
			}

			helloVerifyRequest, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageHelloVerifyRequest)
			if !ok {
				t.Fatal("Failed to cast MessageHelloVerifyRequest")
			}

			err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
			if err != nil {
				t.Fatal(err)
			}
			if n, err = ca.Read(resp); err != nil {
				t.Fatal(err)
			}

			messages, err := recordlayer.UnpackDatagram(resp[:n])
			if err != nil {
				t.Fatal(err)
			}

			if err := record.Unmarshal(messages[0]); err != nil {
				t.Fatal(err)
			}

			serverHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
			if !ok {
				t.Fatal("Failed to cast MessageServerHello")
			}

			gotNegotationInfo := false
			for _, v := range serverHello.Extensions {
				if _, ok := v.(*extension.RenegotiationInfo); ok {
					gotNegotationInfo = true
				}
			}

			if !gotNegotationInfo {
				t.Fatalf("Received ServerHello without RenegotiationInfo")
			}
		})
	}
}

func TestServerNameIndicationExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name       string
		ServerName string
		Expected   []byte
		IncludeSNI bool
	}{
		{
			Name:       "Server name is a valid hostname",
			ServerName: "example.com",
			Expected:   []byte("example.com"),
			IncludeSNI: true,
		},
		{
			Name:       "Server name is an IP literal",
			ServerName: "1.2.3.4",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
		{
			Name:       "Server name is empty",
			ServerName: "",
			Expected:   []byte(""),
			IncludeSNI: false,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					ServerName: test.ServerName,
				}

				_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			if err != nil {
				t.Fatal(err)
			}
			r := &recordlayer.RecordLayer{}
			if err = r.Unmarshal(resp[:n]); err != nil {
				t.Fatal(err)
			}

			clientHello, ok := r.Content.(*handshake.Handshake).Message.(*handshake.MessageClientHello)
			if !ok {
				t.Fatal("Failed to cast MessageClientHello")
			}

			gotSNI := false
			var actualServerName string
			for _, v := range clientHello.Extensions {
				if _, ok := v.(*extension.ServerName); ok {
					gotSNI = true
					extensionServerName, ok := v.(*extension.ServerName)
					if !ok {
						t.Fatal("Failed to cast extension.ServerName")
					}

					actualServerName = extensionServerName.ServerName
				}
			}

			if gotSNI != test.IncludeSNI {
				t.Errorf("TestSNI: unexpected SNI inclusion '%s': expected(%v) actual(%v)", test.Name, test.IncludeSNI, gotSNI)
			}

			if !bytes.Equal([]byte(actualServerName), test.Expected) {
				t.Errorf("TestSNI: server name mismatch '%s': expected(%v) actual(%v)", test.Name, test.Expected, actualServerName)
			}
		})
	}
}

func TestALPNExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name                   string
		ClientProtocolNameList []string
		ServerProtocolNameList []string
		ExpectedProtocol       string
		ExpectAlertFromClient  bool
		ExpectAlertFromServer  bool
		Alert                  alert.Description
	}{
		{
			Name:                   "Negotiate a protocol",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{"spd/1"},
			ExpectedProtocol:       "spd/1",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Server doesn't support any",
			ClientProtocolNameList: []string{"http/1.1", "spd/1"},
			ServerProtocolNameList: []string{},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Negotiate with higher server precedence",
			ClientProtocolNameList: []string{"http/1.1", "spd/1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "http/3", "spd/1"},
			ExpectedProtocol:       "http/3",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  false,
			Alert:                  0,
		},
		{
			Name:                   "Empty intersection",
			ClientProtocolNameList: []string{"http/1.1", "http/3"},
			ServerProtocolNameList: []string{"ssh/2", "spd/1"},
			ExpectedProtocol:       "",
			ExpectAlertFromClient:  false,
			ExpectAlertFromServer:  true,
			Alert:                  alert.NoApplicationProtocol,
		},
		{
			Name:                   "Multiple protocols in ServerHello",
			ClientProtocolNameList: []string{"http/1.1"},
			ServerProtocolNameList: []string{"http/1.1"},
			ExpectedProtocol:       "http/1.1",
			ExpectAlertFromClient:  true,
			ExpectAlertFromServer:  false,
			Alert:                  alert.InternalError,
		},
	} {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ca, cb := dpipe.Pipe()
			go func() {
				conf := &Config{
					SupportedProtocols: test.ClientProtocolNameList,
				}
				_, _ = testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), conf, false)
			}()

			// Receive ClientHello
			resp := make([]byte, 1024)
			n, err := cb.Read(resp)
			if err != nil {
				t.Fatal(err)
			}

			ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel2()

			ca2, cb2 := dpipe.Pipe()
			go func() {
				conf := &Config{
					SupportedProtocols: test.ServerProtocolNameList,
				}
				if _, err2 := testServer(ctx2, dtlsnet.PacketConnFromConn(cb2), cb2.RemoteAddr(), conf, true); !errors.Is(
					err2, context.Canceled,
				) {
					if test.ExpectAlertFromServer {
						// Assert the error type?
					} else {
						t.Error(err2)
					}
				}
			}()

			time.Sleep(50 * time.Millisecond)

			// Forward ClientHello
			if _, err = ca2.Write(resp[:n]); err != nil {
				t.Fatal(err)
			}

			// Receive HelloVerify
			resp2 := make([]byte, 1024)
			n, err = ca2.Read(resp2)
			if err != nil {
				t.Fatal(err)
			}

			// Forward HelloVerify
			if _, err = cb.Write(resp2[:n]); err != nil {
				t.Fatal(err)
			}

			// Receive ClientHello
			resp3 := make([]byte, 1024)
			n, err = cb.Read(resp3)
			if err != nil {
				t.Fatal(err)
			}

			// Forward ClientHello
			if _, err = ca2.Write(resp3[:n]); err != nil {
				t.Fatal(err)
			}

			// Receive ServerHello
			resp4 := make([]byte, 1024)
			n, err = ca2.Read(resp4)
			if err != nil {
				t.Fatal(err)
			}

			messages, err := recordlayer.UnpackDatagram(resp4[:n])
			if err != nil {
				t.Fatal(err)
			}

			record := &recordlayer.RecordLayer{}
			if err := record.Unmarshal(messages[0]); err != nil {
				t.Fatal(err)
			}

			if test.ExpectAlertFromServer {
				a, ok := record.Content.(*alert.Alert)
				if !ok {
					t.Fatal("Failed to cast alert.Alert")
				}

				if a.Description != test.Alert {
					t.Errorf("ALPN %v: expected(%v) actual(%v)", test.Name, test.Alert, a.Description)
				}
			} else {
				serverHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
				if !ok {
					t.Fatal("Failed to cast handshake.MessageServerHello")
				}

				var negotiatedProtocol string
				for _, v := range serverHello.Extensions {
					if _, ok := v.(*extension.ALPN); ok {
						e, ok := v.(*extension.ALPN)
						if !ok {
							t.Fatal("Failed to cast extension.ALPN")
						}

						negotiatedProtocol = e.ProtocolNameList[0]

						// Manipulate ServerHello
						if test.ExpectAlertFromClient {
							e.ProtocolNameList = append(e.ProtocolNameList, "oops")
						}
					}
				}

				if negotiatedProtocol != test.ExpectedProtocol {
					t.Errorf("ALPN %v: expected(%v) actual(%v)", test.Name, test.ExpectedProtocol, negotiatedProtocol)
				}

				s, err := record.Marshal()
				if err != nil {
					t.Fatal(err)
				}

				// Forward ServerHello
				if _, err = cb.Write(s); err != nil {
					t.Fatal(err)
				}

				if test.ExpectAlertFromClient {
					resp5 := make([]byte, 1024)
					n, err = cb.Read(resp5)
					if err != nil {
						t.Fatal(err)
					}

					r2 := &recordlayer.RecordLayer{}
					if err := r2.Unmarshal(resp5[:n]); err != nil {
						t.Fatal(err)
					}

					a, ok := r2.Content.(*alert.Alert)
					if !ok {
						t.Fatal("Failed to cast alert.Alert")
					}

					if a.Description != test.Alert {
						t.Errorf("ALPN %v: expected(%v) actual(%v)", test.Name, test.Alert, a.Description)
					}
				}
			}

			time.Sleep(50 * time.Millisecond) // Give some time for returned errors
		})
	}
}

// Make sure the supported_groups extension is not included in the ServerHello.
func TestSupportedGroupsExtension(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("ServerHello Supported Groups", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		go func() {
			if _, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{}, true); !errors.Is(
				err, context.Canceled,
			) {
				t.Error(err)
			}
		}()
		extensions := []extension.Extension{
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.P384},
			},
			&extension.SupportedPointFormats{
				PointFormats: []elliptic.CurvePointFormat{elliptic.CurvePointFormatUncompressed},
			},
		}

		time.Sleep(50 * time.Millisecond)

		resp := make([]byte, 1024)
		err := sendClientHello([]byte{}, ca, 0, extensions)
		if err != nil {
			t.Fatal(err)
		}

		// Receive ServerHello
		n, err := ca.Read(resp)
		if err != nil {
			t.Fatal(err)
		}
		record := &recordlayer.RecordLayer{}
		if err = record.Unmarshal(resp[:n]); err != nil {
			t.Fatal(err)
		}

		helloVerifyRequest, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageHelloVerifyRequest)
		if !ok {
			t.Fatal("Failed to cast MessageHelloVerifyRequest")
		}

		err = sendClientHello(helloVerifyRequest.Cookie, ca, 1, extensions)
		if err != nil {
			t.Fatal(err)
		}
		if n, err = ca.Read(resp); err != nil {
			t.Fatal(err)
		}

		messages, err := recordlayer.UnpackDatagram(resp[:n])
		if err != nil {
			t.Fatal(err)
		}

		if err := record.Unmarshal(messages[0]); err != nil {
			t.Fatal(err)
		}

		serverHello, ok := record.Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello)
		if !ok {
			t.Fatal("Failed to cast MessageServerHello")
		}

		gotGroups := false
		for _, v := range serverHello.Extensions {
			if _, ok := v.(*extension.SupportedEllipticCurves); ok {
				gotGroups = true
			}
		}

		if gotGroups {
			t.Errorf("TestSupportedGroups: supported_groups extension was sent in ServerHello")
		}
	})
}

func TestSessionResume(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("resumed", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *Conn
			err error
		}
		clientRes := make(chan result, 1)

		ss := &memSessStore{}

		id, _ := hex.DecodeString("9b9fc92255634d9fb109febed42166717bb8ded8c738ba71bc7f2a0d9dae0306")
		secret, _ := hex.DecodeString(
			"2e942a37aca5241deb2295b5fcedac221c7078d2503d2b62aeb48c880d7da73c001238b708559686b9da6e829c05ead7",
		)

		s := Session{ID: id, Secret: secret}

		ca, cb := dpipe.Pipe()

		_ = ss.Set(id, s)
		_ = ss.Set([]byte(ca.RemoteAddr().String()+"_example.com"), s)

		go func() {
			config := &Config{
				CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
				ServerName:   "example.com",
				SessionStore: ss,
				MTU:          100,
			}
			c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
			clientRes <- result{c, err}
		}()

		config := &Config{
			CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
			ServerName:   "example.com",
			SessionStore: ss,
			MTU:          100,
		}
		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
		if err != nil {
			t.Fatalf("TestSessionResume: Server failed(%v)", err)
		}

		state, ok := server.ConnectionState()
		if !ok {
			t.Fatal("TestSessionResume: ConnectionState failed")
		}
		actualSessionID := state.SessionID
		actualMasterSecret := state.masterSecret
		if !bytes.Equal(actualSessionID, id) {
			t.Errorf("TestSessionResumetion: SessionID Mismatch: expected(%v) actual(%v)", id, actualSessionID)
		}
		if !bytes.Equal(actualMasterSecret, secret) {
			t.Errorf("TestSessionResumetion: masterSecret Mismatch: expected(%v) actual(%v)", secret, actualMasterSecret)
		}

		defer func() {
			_ = server.Close()
		}()

		res := <-clientRes
		if res.err != nil {
			t.Fatal(res.err)
		}
		_ = res.c.Close()
	})

	t.Run("new session", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		type result struct {
			c   *Conn
			err error
		}
		clientRes := make(chan result, 1)

		s1 := &memSessStore{}
		s2 := &memSessStore{}

		ca, cb := dpipe.Pipe()
		go func() {
			config := &Config{
				ServerName:   "example.com",
				SessionStore: s1,
			}
			c, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), config, false)
			clientRes <- result{c, err}
		}()

		config := &Config{
			SessionStore: s2,
		}
		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), config, true)
		if err != nil {
			t.Fatalf("TestSessionResumetion: Server failed(%v)", err)
		}

		state, ok := server.ConnectionState()
		if !ok {
			t.Fatal("TestSessionResumetion: ConnectionState failed")
		}
		actualSessionID := state.SessionID
		actualMasterSecret := state.masterSecret
		ss, _ := s2.Get(actualSessionID)
		if !bytes.Equal(actualMasterSecret, ss.Secret) {
			t.Errorf("TestSessionResumetion: masterSecret Mismatch: expected(%v) actual(%v)", ss.Secret, actualMasterSecret)
		}

		defer func() {
			_ = server.Close()
		}()

		res := <-clientRes
		if res.err != nil {
			t.Fatal(res.err)
		}
		cs, _ := s1.Get([]byte(ca.RemoteAddr().String() + "_example.com"))
		if !bytes.Equal(actualMasterSecret, cs.Secret) {
			t.Errorf("TestSessionResumetion: masterSecret Mismatch: expected(%v) actual(%v)", ss.Secret, actualMasterSecret)
		}
		_ = res.c.Close()
	})
}

type memSessStore struct {
	sync.Map
}

func (ms *memSessStore) Set(key []byte, s Session) error {
	k := hex.EncodeToString(key)
	ms.Store(k, s)

	return nil
}

func (ms *memSessStore) Get(key []byte) (Session, error) {
	k := hex.EncodeToString(key)

	v, ok := ms.Load(k)
	if !ok {
		return Session{}, nil
	}

	s, ok := v.(Session)
	if !ok {
		return Session{}, nil
	}

	return s, nil
}

func (ms *memSessStore) Del(key []byte) error {
	k := hex.EncodeToString(key)
	ms.Delete(k)

	return nil
}

// Test that we return the proper certificate if we are serving multiple ServerNames on a single Server.
func TestMultipleServerCertificates(t *testing.T) {
	fooCert, err := selfsign.GenerateSelfSignedWithDNS("foo")
	if err != nil {
		t.Fatal(err)
	}

	barCert, err := selfsign.GenerateSelfSignedWithDNS("bar")
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	for _, cert := range []tls.Certificate{fooCert, barCert} {
		certificate, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		caPool.AddCert(certificate)
	}

	for _, test := range []struct {
		RequestServerName string
		ExpectedDNSName   string
	}{
		{
			"foo",
			"foo",
		},
		{
			"bar",
			"bar",
		},
		{
			"invalid",
			"foo",
		},
	} {
		test := test
		t.Run(test.RequestServerName, func(t *testing.T) {
			clientErr := make(chan error, 2)
			client := make(chan *Conn, 1)

			ca, cb := dpipe.Pipe()
			go func() {
				clientConn, err := testClient(context.TODO(), dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
					RootCAs:    caPool,
					ServerName: test.RequestServerName,
					VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
						certificate, err := x509.ParseCertificate(rawCerts[0])
						if err != nil {
							return err
						}

						if certificate.DNSNames[0] != test.ExpectedDNSName {
							return errWrongCert
						}

						return nil
					},
				}, false)
				clientErr <- err
				client <- clientConn
			}()

			if s, err := testServer(context.TODO(), dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
				Certificates: []tls.Certificate{fooCert, barCert},
			}, false); err != nil {
				t.Fatal(err)
			} else if err = s.Close(); err != nil {
				t.Fatal(err)
			}

			if c, err := <-client, <-clientErr; err != nil {
				t.Fatal(err)
			} else if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEllipticCurveConfiguration(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	for _, test := range []struct {
		Name            string
		ConfigCurves    []elliptic.Curve
		HandshakeCurves []elliptic.Curve
	}{
		{
			Name:            "Curve defaulting",
			ConfigCurves:    nil,
			HandshakeCurves: defaultCurves,
		},
		{
			Name:            "Single curve",
			ConfigCurves:    []elliptic.Curve{elliptic.X25519},
			HandshakeCurves: []elliptic.Curve{elliptic.X25519},
		},
		{
			Name:            "Multiple curves",
			ConfigCurves:    []elliptic.Curve{elliptic.P384, elliptic.X25519},
			HandshakeCurves: []elliptic.Curve{elliptic.P384, elliptic.X25519},
		},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		resultCh := make(chan result)

		go func() {
			client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}, EllipticCurves: test.ConfigCurves}, true)
			resultCh <- result{client, err}
		}()

		server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{CipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}, EllipticCurves: test.ConfigCurves}, true)
		if err != nil {
			t.Fatalf("Server error: %v", err)
		}

		if len(test.ConfigCurves) == 0 && len(test.HandshakeCurves) != len(server.fsm.cfg.ellipticCurves) {
			t.Fatalf(
				"Failed to default Elliptic curves, expected %d, got: %d",
				len(test.HandshakeCurves),
				len(server.fsm.cfg.ellipticCurves),
			)
		}

		if len(test.ConfigCurves) != 0 {
			if len(test.HandshakeCurves) != len(server.fsm.cfg.ellipticCurves) {
				t.Fatalf(
					"Failed to configure Elliptic curves, expect %d, got %d",
					len(test.HandshakeCurves),
					len(server.fsm.cfg.ellipticCurves),
				)
			}
			for i, c := range test.ConfigCurves {
				if c != server.fsm.cfg.ellipticCurves[i] {
					t.Fatalf("Failed to maintain Elliptic curve order, expected %s, got %s", c, server.fsm.cfg.ellipticCurves[i])
				}
			}
		}

		res := <-resultCh
		if res.err != nil {
			t.Fatalf("Client error; %v", err)
		}

		defer func() {
			err = server.Close()
			if err != nil {
				t.Fatal(err)
			}
			err = res.c.Close()
			if err != nil {
				t.Fatal(err)
			}
		}()
	}
}

func TestSkipHelloVerify(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	gotHello := make(chan struct{})

	go func() {
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			Certificates:            []tls.Certificate{certificate},
			LoggerFactory:           logging.NewDefaultLoggerFactory(),
			InsecureSkipVerifyHello: true,
		}, false)
		if sErr != nil {
			t.Error(sErr)

			return
		}
		buf := make([]byte, 1024)
		if _, sErr = server.Read(buf); sErr != nil {
			t.Error(sErr)
		}
		gotHello <- struct{}{}
		if sErr = server.Close(); sErr != nil {
			t.Error(sErr)
		}
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		LoggerFactory:      logging.NewDefaultLoggerFactory(),
		InsecureSkipVerify: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("hello")); err != nil {
		t.Error(err)
	}
	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		t.Error("timeout")
	}

	if err = client.Close(); err != nil {
		t.Error(err)
	}
}

type connWithCallback struct {
	net.Conn
	onWrite func([]byte)
}

func (c *connWithCallback) Write(b []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite(b)
	}

	return c.Conn.Write(b)
}

func TestApplicationDataQueueLimited(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	defer ca.Close()
	defer cb.Close()

	done := make(chan struct{})
	go func() {
		serverCert, err := selfsign.GenerateSelfSigned()
		if err != nil {
			t.Error(err)

			return
		}
		cfg := &Config{}
		cfg.Certificates = []tls.Certificate{serverCert}

		dconn, err := createConn(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), cfg, false, nil)
		if err != nil {
			t.Error(err)

			return
		}
		go func() {
			for i := 0; i < 5; i++ {
				dconn.lock.RLock()
				qlen := len(dconn.encryptedPackets)
				dconn.lock.RUnlock()
				if qlen > maxAppDataPacketQueueSize {
					t.Error("too many encrypted packets enqueued", len(dconn.encryptedPackets))
				}
				time.Sleep(1 * time.Second)
			}
		}()
		if err := dconn.HandshakeContext(ctx); err == nil {
			t.Error("expected handshake to fail")
		}
		close(done)
	}()
	extensions := []extension.Extension{}

	time.Sleep(50 * time.Millisecond)

	err := sendClientHello([]byte{}, ca, 0, extensions)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)

	for i := 0; i < 1000; i++ {
		// Send an application data packet
		packet, err := (&recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version:        protocol.Version1_2,
				SequenceNumber: uint64(3),
				Epoch:          1, // use an epoch greater than 0
			},
			Content: &protocol.ApplicationData{
				Data: []byte{1, 2, 3, 4},
			},
		}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		ca.Write(packet)
		if i%100 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	time.Sleep(1 * time.Second)
	ca.Close()
	<-done
}

func TestHelloRandom(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ca, cb := dpipe.Pipe()
	certificate, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	gotHello := make(chan struct{})

	chRandom := [handshake.RandomBytesLength]byte{}
	_, err = rand.Read(chRandom[:])
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		server, sErr := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			GetCertificate: func(chi *ClientHelloInfo) (*tls.Certificate, error) {
				if len(chi.CipherSuites) == 0 {
					return &certificate, nil
				}

				if !bytes.Equal(chi.RandomBytes[:], chRandom[:]) {
					t.Error("client hello random differs")
				}

				return &certificate, nil
			},
			LoggerFactory: logging.NewDefaultLoggerFactory(),
		}, false)
		if sErr != nil {
			t.Error(sErr)

			return
		}
		buf := make([]byte, 1024)
		if _, sErr = server.Read(buf); sErr != nil {
			t.Error(sErr)
		}
		gotHello <- struct{}{}
		if sErr = server.Close(); sErr != nil {
			t.Error(sErr)
		}
	}()

	client, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		HelloRandomBytesGenerator: func() [handshake.RandomBytesLength]byte {
			return chRandom
		},
		InsecureSkipVerify: true,
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write([]byte("hello")); err != nil {
		t.Error(err)
	}
	select {
	case <-gotHello:
		// OK
	case <-time.After(time.Second * 5):
		t.Error("timeout")
	}

	if err = client.Close(); err != nil {
		t.Error(err)
	}
}

func TestOnConnectionAttempt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*20)
	defer cancel()

	var clientOnConnectionAttempt, serverOnConnectionAttempt atomic.Int32

	ca, cb := dpipe.Pipe()
	clientErr := make(chan error, 1)
	go func() {
		_, err := testClient(ctx, dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
			OnConnectionAttempt: func(in net.Addr) error {
				clientOnConnectionAttempt.Store(1)
				if in == nil {
					t.Fatal("net.Addr is nil")
				}

				return nil
			},
		}, true)
		clientErr <- err
	}()

	expectedErr := &FatalError{}
	if _, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		OnConnectionAttempt: func(in net.Addr) error {
			serverOnConnectionAttempt.Store(1)
			if in == nil {
				t.Fatal("net.Addr is nil")
			}

			return expectedErr
		},
	}, true); !errors.Is(err, expectedErr) {
		t.Fatal(err)
	}

	if err := <-clientErr; err == nil {
		t.Fatal(err)
	}

	if v := serverOnConnectionAttempt.Load(); v != 1 {
		t.Fatal("OnConnectionAttempt did not fire for server")
	}

	if v := clientOnConnectionAttempt.Load(); v != 0 {
		t.Fatal("OnConnectionAttempt fired for client")
	}
}

func TestFragmentBuffer_Retransmission(t *testing.T) {
	fragmentBuffer := newFragmentBuffer()
	frag := []byte{
		0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, 0x03, 0x00,
		0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01,
	}

	if _, isRetransmission, err := fragmentBuffer.push(frag); err != nil {
		t.Fatal(err)
	} else if isRetransmission {
		t.Fatal("fragment should not be retransmission")
	}

	if v, _ := fragmentBuffer.pop(); v == nil {
		t.Fatal("Failed to pop fragment")
	}

	if _, isRetransmission, err := fragmentBuffer.push(frag); err != nil {
		t.Fatal(err)
	} else if !isRetransmission {
		t.Fatal("fragment should be retransmission")
	}
}

func TestConnectionState(t *testing.T) {
	ca, cb := dpipe.Pipe()

	// Setup client
	clientCfg := &Config{}
	clientCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.Certificates = []tls.Certificate{clientCert}
	clientCfg.InsecureSkipVerify = true
	client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = client.Close()
	}()

	_, ok := client.ConnectionState()
	if ok {
		t.Fatal("ConnectionState should be nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorChannel := make(chan error)
	go func() {
		errC := client.HandshakeContext(ctx)
		errorChannel <- errC
	}()

	// Setup server
	server, err := testServer(ctx, dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = server.Close()
	}()

	err = <-errorChannel
	if err != nil {
		t.Fatal(err)
	}

	_, ok = client.ConnectionState()
	if !ok {
		t.Fatal("ConnectionState should not be nil")
	}
}

func TestMultiHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	ca, cb := dpipe.Pipe()
	serverCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		Certificates: []tls.Certificate{serverCert},
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = server.Handshake()
	}()

	clientCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	client, err := Client(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), &Config{
		Certificates: []tls.Certificate{clientCert},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err = client.Handshake(); err == nil {
		t.Fatal(err)
	}

	if err = client.Handshake(); err == nil {
		t.Fatal(err)
	}

	if err = server.Close(); err != nil {
		t.Fatal(err)
	}

	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseDuringHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		_, cb := dpipe.Pipe()
		server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
			Certificates: []tls.Certificate{serverCert},
		})
		if err != nil {
			t.Fatal(err)
		}

		waitChan := make(chan struct{})
		go func() {
			close(waitChan)
			_ = server.Handshake()
		}()

		<-waitChan
		if err = server.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCloseWithoutHandshake(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 10).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	_, cb := dpipe.Pipe()
	server, err := Server(dtlsnet.PacketConnFromConn(cb), cb.RemoteAddr(), &Config{
		Certificates: []tls.Certificate{serverCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
}
