// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func TestCanonicalHandshake13(t *testing.T) {
	const bodyLen = 3

	body := []byte{0xaa, 0xbb, 0xcc}
	raw := makeRawHandshake13(t, handshake.Header{
		Type:            handshake.TypeClientHello,
		Length:          bodyLen,
		MessageSequence: 7,
		FragmentLength:  bodyLen,
	}, body)

	canonical, err := canonicalHandshake13(raw)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(canonical, []byte{
		byte(handshake.TypeClientHello), 0x00, 0x00, 0x03,
		0xaa, 0xbb, 0xcc,
	}) {
		t.Errorf("expected %v, got %v", []byte{
			byte(handshake.TypeClientHello), 0x00, 0x00, 0x03,
			0xaa, 0xbb, 0xcc,
		}, canonical)
	}
}

func TestCanonicalHandshake13RejectsInvalidMessages(t *testing.T) {
	const bodyLen = 2

	body := []byte{0xaa, 0xbb}

	for _, test := range []struct {
		name string
		raw  []byte
		err  error
	}{
		{
			name: "too small",
			raw:  []byte{byte(handshake.TypeClientHello)},
			err:  dtlserrors.ErrBufferTooSmall,
		},
		{
			name: "fragment offset",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen,
				MessageSequence: 1,
				FragmentOffset:  1,
				FragmentLength:  bodyLen,
			}, body),
			err: dtlserrors.ErrInvalidHandshakeTranscriptMessage,
		},
		{
			name: "fragment length",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen,
				MessageSequence: 1,
				FragmentLength:  bodyLen - 1,
			}, body),
			err: dtlserrors.ErrInvalidHandshakeTranscriptMessage,
		},
		{
			name: "body length",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen + 1,
				MessageSequence: 1,
				FragmentLength:  bodyLen + 1,
			}, body),
			err: dtlserrors.ErrInvalidHandshakeTranscriptMessage,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicalHandshake13(test.raw)
			if !errors.Is(err, test.err) {
				t.Errorf("expected error %v, got %v", test.err, err)
			}
		})
	}
}

func TestHandshakeTranscript13DeferredHashSelection(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01, 0x02})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x03, 0x04})
	expectedClientHello := append([]byte(nil), clientHello...)

	transcript := newHandshakeTranscript13()
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
	}
	clientHello[len(clientHello)-1] = 0xff
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
	}

	if transcript.selectHash(sha256.New) != nil {
		t.Error(transcript.selectHash(sha256.New))
	}

	_, err := transcript.sum()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(hashTranscript13(expectedClientHello), serverHello) {
		t.Errorf("expected %v, got %v", hashTranscript13(expectedClientHello), serverHello)
	}
}

func TestHandshakeTranscript13RejectsSumBeforeHashSelection(t *testing.T) {
	transcript := newHandshakeTranscript13()

	_, err := transcript.sum()
	if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptHashNotSelected) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptHashNotSelected, err)
	}
}

func TestHandshakeTranscript13RejectsHashReselection(t *testing.T) {
	transcript := newHandshakeTranscript13()
	if transcript.selectHash(sha256.New) != nil {
		t.Error(transcript.selectHash(sha256.New))
	}

	err := transcript.selectHash(sha256.New)
	if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptHashAlreadySelected) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptHashAlreadySelected, err)
	}
}

func TestHandshakeTranscript13DuplicateHandling(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	changedClientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x02})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x03})

	transcript := newHandshakeTranscript13()
	if transcript.selectHash(sha256.New) != nil {
		t.Error(transcript.selectHash(sha256.New))
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
	}

	err := transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, changedClientHello)
	if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptMessageChanged) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptMessageChanged, err)
	}

	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
	}

	sum, err := transcript.sum()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(hashTranscript13(clientHello, serverHello), sum) {
		t.Errorf("expected %v, got %v", hashTranscript13(clientHello, serverHello), sum)
	}
}

func TestHandshakeTranscript13RejectsInvalidCanonicalMessage(t *testing.T) {
	transcript := newHandshakeTranscript13()

	err := transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, []byte{
		byte(handshake.TypeClientHello), 0x00, 0x00, 0x02, 0x01,
	})
	if !errors.Is(err, dtlserrors.ErrInvalidHandshakeTranscriptMessage) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidHandshakeTranscriptMessage, err)
	}
}

func TestHandshakeTranscript13HelloRetryRequest(t *testing.T) {
	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	clientHello2 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x03})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x04})

	transcript := newHandshakeTranscript13()
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello1) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello1))
	}
	if transcript.selectHash(sha256.New) != nil {
		t.Error(transcript.selectHash(sha256.New))
	}
	if transcript.applyHelloRetryRequest() != nil {
		t.Error(transcript.applyHelloRetryRequest())
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, helloRetryRequest) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, helloRetryRequest))
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13, seq: 1}, clientHello2) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13, seq: 1}, clientHello2))
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13, seq: 1}, serverHello) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13, seq: 1}, serverHello))
	}

	clientHello1Hash := hashTranscript13(clientHello1)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expected := hashTranscript13(messageHash, helloRetryRequest, clientHello2, serverHello)

	sum, err := transcript.sum()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(expected, sum) {
		t.Errorf("expected %v, got %v", expected, sum)
	}
	if "MessageHash" != handshake.TypeMessageHash.String() {
		t.Errorf("expected %v, got %v", "MessageHash", handshake.TypeMessageHash.String())
	}
}

func TestHandshakeTranscript13HelloRetryRequestBinderFork(t *testing.T) {
	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	placeholderBinder := make([]byte, sha256.Size)
	_, truncatedClientHello2 := pskClientHelloTranscript13(t, placeholderBinder)

	transcript := newHandshakeTranscript13()
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello1) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello1))
	}
	if transcript.selectHash(sha256.New) != nil {
		t.Error(transcript.selectHash(sha256.New))
	}
	if transcript.applyHelloRetryRequest() != nil {
		t.Error(transcript.applyHelloRetryRequest())
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, helloRetryRequest) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, helloRetryRequest))
	}

	mainSumBefore, err := transcript.sum()
	if err != nil {
		t.Error(err)
	}
	if !errors.Is(validateCanonicalHandshake13(truncatedClientHello2), dtlserrors.ErrInvalidHandshakeTranscriptMessage) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrInvalidHandshakeTranscriptMessage, validateCanonicalHandshake13(truncatedClientHello2))
	}

	binderTranscriptHash, err := transcript.sumWithSuffix(truncatedClientHello2)
	if err != nil {
		t.Error(err)
	}

	clientHello1Hash := hashTranscript13(clientHello1)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedBinderTranscriptHash := hashTranscript13(messageHash, helloRetryRequest, truncatedClientHello2)
	if !reflect.DeepEqual(expectedBinderTranscriptHash, binderTranscriptHash) {
		t.Errorf("expected %v, got %v", expectedBinderTranscriptHash, binderTranscriptHash)
	}

	binderKey := []byte("binder key")
	binder := hmacSHA25613(binderKey, binderTranscriptHash)
	expectedBinder := hmacSHA25613(binderKey, expectedBinderTranscriptHash)
	if !reflect.DeepEqual(expectedBinder, binder) {
		t.Errorf("expected %v, got %v", expectedBinder, binder)
	}

	mainSumAfter, err := transcript.sum()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(mainSumBefore, mainSumAfter) {
		t.Errorf("expected %v, got %v", mainSumBefore, mainSumAfter)
	}

	clientHello2, truncatedClientHello2WithBinder := pskClientHelloTranscript13(t, binder)
	if !reflect.DeepEqual(truncatedClientHello2, truncatedClientHello2WithBinder) {
		t.Errorf("expected %v, got %v", truncatedClientHello2, truncatedClientHello2WithBinder)
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13, seq: 1}, clientHello2) != nil {
		t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13, seq: 1}, clientHello2))
	}

	sum, err := transcript.sum()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(hashTranscript13(messageHash, helloRetryRequest, clientHello2), sum) {
		t.Errorf("expected %v, got %v", hashTranscript13(messageHash, helloRetryRequest, clientHello2), sum)
	}
}

func TestHandshakeTranscript13HelloRetryRequestErrors(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})

	t.Run("hash not selected", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
			t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
		}

		err := transcript.applyHelloRetryRequest()
		if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptHashNotSelected) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptHashNotSelected, err)
		}
	})

	t.Run("not first client hello only", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
			t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
		}
		if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello) != nil {
			t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
		}
		if transcript.selectHash(sha256.New) != nil {
			t.Error(transcript.selectHash(sha256.New))
		}

		err := transcript.applyHelloRetryRequest()
		if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid, err)
		}
	})

	t.Run("server message", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello) != nil {
			t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
		}
		if transcript.selectHash(sha256.New) != nil {
			t.Error(transcript.selectHash(sha256.New))
		}

		err := transcript.applyHelloRetryRequest()
		if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid, err)
		}
	})

	t.Run("already applied", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
			t.Error(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
		}
		if transcript.selectHash(sha256.New) != nil {
			t.Error(transcript.selectHash(sha256.New))
		}
		if transcript.applyHelloRetryRequest() != nil {
			t.Error(transcript.applyHelloRetryRequest())
		}

		err := transcript.applyHelloRetryRequest()
		if !errors.Is(err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid, err)
		}
	})
}

func TestDeriveHandshakeTrafficSecrets13NoHRRAndHRR(t *testing.T) {
	preMasterSecret := bytes.Repeat([]byte{0x42}, sha256.Size)

	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	noHRRTranscriptHash := hashTranscript13(clientHello, serverHello)

	noHRRSecrets, err := deriveHandshakeTrafficSecrets13(sha256.New, preMasterSecret, noHRRTranscriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(noHRRSecrets.Client) != sha256.Size {
		t.Fatalf("wrong length: got %d, want %d", len(noHRRSecrets.Client), sha256.Size)
	}
	if len(noHRRSecrets.Server) != sha256.Size {
		t.Fatalf("wrong length: got %d, want %d", len(noHRRSecrets.Server), sha256.Size)
	}
	if reflect.DeepEqual(noHRRSecrets.Client, noHRRSecrets.Server) {
		t.Errorf("should not equal %v", noHRRSecrets.Client)
	}

	again, err := deriveHandshakeTrafficSecrets13(sha256.New, preMasterSecret, noHRRTranscriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(noHRRSecrets, again) {
		t.Errorf("expected %v, got %v", noHRRSecrets, again)
	}

	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x03})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x04})
	clientHello2 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x05})
	serverHello2 := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x06})
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, hashTranscript13(clientHello1))
	hrrTranscriptHash := hashTranscript13(messageHash, helloRetryRequest, clientHello2, serverHello2)

	hrrSecrets, err := deriveHandshakeTrafficSecrets13(sha256.New, preMasterSecret, hrrTranscriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(noHRRSecrets.Client, hrrSecrets.Client) {
		t.Errorf("should not equal %v", noHRRSecrets.Client)
	}
	if reflect.DeepEqual(noHRRSecrets.Server, hrrSecrets.Server) {
		t.Errorf("should not equal %v", noHRRSecrets.Server)
	}

	changedSecret := append([]byte(nil), preMasterSecret...)
	changedSecret[0] ^= 0xff
	changedSecrets, err := deriveHandshakeTrafficSecrets13(sha256.New, changedSecret, noHRRTranscriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(noHRRSecrets.Client, changedSecrets.Client) {
		t.Errorf("should not equal %v", noHRRSecrets.Client)
	}
	if reflect.DeepEqual(noHRRSecrets.Server, changedSecrets.Server) {
		t.Errorf("should not equal %v", noHRRSecrets.Server)
	}
}

func TestDeriveAndStoreHandshakeTrafficSecrets13FromTranscript(t *testing.T) {
	cipherSuite := cipherSuiteForID(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256)
	state := &dtlsstate.State{
		CipherSuite:     cipherSuite,
		PreMasterSecret: bytes.Repeat([]byte{0x11}, sha256.Size),
	}

	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	transcript := newHandshakeTranscript13()
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
		t.Fatal(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello) != nil {
		t.Fatal(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
	}

	if deriveAndStoreHandshakeTrafficSecrets13(state, transcript) != nil {
		t.Fatal(deriveAndStoreHandshakeTrafficSecrets13(state, transcript))
	}

	transcriptHash, err := transcript.sum()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := deriveHandshakeTrafficSecrets13(cipherSuite.HashFunc(), state.PreMasterSecret, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, state.HandshakeTrafficSecrets13) {
		t.Errorf("expected %v, got %v", expected, state.HandshakeTrafficSecrets13)
	}
	if len(state.HandshakeTrafficSecrets13.Client) == 0 {
		t.Errorf("expected non-empty")
	}
	if len(state.HandshakeTrafficSecrets13.Server) == 0 {
		t.Errorf("expected non-empty")
	}
}

func TestCertificateVerifyInput13ServerAndClient(t *testing.T) {
	transcriptHash := bytes.Repeat([]byte{0xa5}, sha256.Size)

	serverInput := certificateVerifyInput13(false, transcriptHash)
	clientInput := certificateVerifyInput13(true, transcriptHash)

	if len(serverInput) != certificateVerifyPaddingLen13+len(serverCertificateVerifyContext13)+sha256.Size {
		t.Fatalf("wrong length: got %d, want %d", len(serverInput), certificateVerifyPaddingLen13+len(serverCertificateVerifyContext13))
	}
	if !reflect.DeepEqual(bytes.Repeat([]byte{0x20}, certificateVerifyPaddingLen13), serverInput[:certificateVerifyPaddingLen13]) {
		t.Errorf("expected %v, got %v", bytes.Repeat([]byte{0x20}, certificateVerifyPaddingLen13), serverInput[:certificateVerifyPaddingLen13])
	}
	serverContextEnd := certificateVerifyPaddingLen13 + len(serverCertificateVerifyContext13)
	serverContext := serverInput[certificateVerifyPaddingLen13:serverContextEnd]
	if serverCertificateVerifyContext13 != string(serverContext) {
		t.Errorf("expected %v, got %v", serverCertificateVerifyContext13, string(serverContext))
	}
	if !reflect.DeepEqual(transcriptHash, serverInput[len(serverInput)-sha256.Size:]) {
		t.Errorf("expected %v, got %v", transcriptHash, serverInput[len(serverInput)-sha256.Size:])
	}

	if len(clientInput) != certificateVerifyPaddingLen13+len(clientCertificateVerifyContext13)+sha256.Size {
		t.Fatalf("wrong length: got %d, want %d", len(clientInput), certificateVerifyPaddingLen13+len(clientCertificateVerifyContext13)+sha256.Size)
	}
	clientContextEnd := certificateVerifyPaddingLen13 + len(clientCertificateVerifyContext13)
	clientContext := clientInput[certificateVerifyPaddingLen13:clientContextEnd]
	if clientCertificateVerifyContext13 != string(clientContext) {
		t.Errorf("expected %v, got %v", clientCertificateVerifyContext13, string(clientContext))
	}
	if !reflect.DeepEqual(transcriptHash, clientInput[len(clientInput)-sha256.Size:]) {
		t.Errorf("expected %v, got %v", transcriptHash, clientInput[len(clientInput)-sha256.Size:])
	}
	if reflect.DeepEqual(serverInput, clientInput) {
		t.Errorf("should not equal %v", serverInput)
	}
}

func TestFinishedVerifyData13(t *testing.T) {
	baseKey := bytes.Repeat([]byte{0x11}, sha256.Size)
	transcriptHash := bytes.Repeat([]byte{0x22}, sha256.Size)

	finishedKey, err := finishedKey13(sha256.New, baseKey)
	if err != nil {
		t.Fatal(err)
	}

	verifyData, err := finishedVerifyData13(sha256.New, baseKey, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifyData) != sha256.Size {
		t.Fatalf("wrong length: got %d, want %d", len(verifyData), sha256.Size)
	}

	expectedMAC := hmac.New(sha256.New, finishedKey)
	_, err = expectedMAC.Write(transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedMAC.Sum(nil), verifyData) {
		t.Errorf("expected %v, got %v", expectedMAC.Sum(nil), verifyData)
	}
	if verifyFinishedData13(sha256.New, baseKey, transcriptHash, verifyData) != nil {
		t.Error(verifyFinishedData13(sha256.New, baseKey, transcriptHash, verifyData))
	}

	changedTranscript := append([]byte(nil), transcriptHash...)
	changedTranscript[0] ^= 0xff
	changedVerifyData, err := finishedVerifyData13(sha256.New, baseKey, changedTranscript)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(verifyData, changedVerifyData) {
		t.Errorf("should not equal %v", verifyData)
	}

	changedKey := append([]byte(nil), baseKey...)
	changedKey[0] ^= 0xff
	changedKeyVerifyData, err := finishedVerifyData13(sha256.New, changedKey, transcriptHash)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verifyData, changedKeyVerifyData) {
		t.Errorf("should not equal %v", verifyData)
	}

	badVerifyData := append([]byte(nil), verifyData...)
	badVerifyData[0] ^= 0xff
	if !errors.Is(verifyFinishedData13(sha256.New, baseKey, transcriptHash, badVerifyData), dtlserrors.ErrVerifyDataMismatch) {
		t.Errorf("expected error %v, got %v", dtlserrors.ErrVerifyDataMismatch, verifyFinishedData13(sha256.New, baseKey, transcriptHash, badVerifyData))
	}
}

func TestDTLS13TranscriptAuthenticatedHandshakeInputs(t *testing.T) {
	cipherSuite := cipherSuiteForID(TLS_PSK_WITH_CHACHA20_POLY1305_SHA256)
	state := &dtlsstate.State{
		CipherSuite:     cipherSuite,
		PreMasterSecret: bytes.Repeat([]byte{0x77}, sha256.Size),
	}
	transcript := newHandshakeTranscript13()

	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello) != nil {
		t.Fatal(transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
	}
	if transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello) != nil {
		t.Fatal(transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
	}

	if deriveAndStoreHandshakeTrafficSecrets13(state, transcript) != nil {
		t.Fatal(deriveAndStoreHandshakeTrafficSecrets13(state, transcript))
	}
	if len(state.HandshakeTrafficSecrets13.Client) == 0 {
		t.Fatalf("expected non-empty")
	}
	if len(state.HandshakeTrafficSecrets13.Server) == 0 {
		t.Fatalf("expected non-empty")
	}

	certificate := canonicalTranscriptHandshake13(handshake.TypeCertificate, []byte{0x03})
	if transcript.appendCanonical(transcriptMessageID13{
		sender: transcriptServer13,
		seq:    1,
	}, certificate) != nil {
		t.Fatal(transcript.appendCanonical(transcriptMessageID13{
			sender: transcriptServer13,
			seq:    1,
		}, certificate))
	}

	certVerifyInput, err := certificateVerifyInputFromTranscript13(false, transcript)
	if err != nil {
		t.Fatal(err)
	}
	certVerifyTranscriptHash, err := transcript.sum()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(certVerifyTranscriptHash, certVerifyInput[len(certVerifyInput)-sha256.Size:]) {
		t.Errorf("expected %v, got %v", certVerifyTranscriptHash, certVerifyInput[len(certVerifyInput)-sha256.Size:])
	}

	certVerify := canonicalTranscriptHandshake13(handshake.TypeCertificateVerify, []byte{0x04})
	if transcript.appendCanonical(transcriptMessageID13{
		sender: transcriptServer13,
		seq:    2,
	}, certVerify) != nil {
		t.Fatal(transcript.appendCanonical(transcriptMessageID13{
			sender: transcriptServer13,
			seq:    2,
		}, certVerify))
	}

	verifyData, err := finishedVerifyDataFromTranscript13(
		sha256.New,
		state.HandshakeTrafficSecrets13.Server,
		transcript,
	)
	if err != nil {
		t.Fatal(err)
	}
	finishedTranscriptHash, err := transcript.sum()
	if err != nil {
		t.Fatal(err)
	}
	if verifyFinishedData13(
		sha256.New,
		state.HandshakeTrafficSecrets13.Server,
		finishedTranscriptHash,
		verifyData,
	) != nil {
		t.Error(verifyFinishedData13(
			sha256.New,
			state.HandshakeTrafficSecrets13.Server,
			finishedTranscriptHash,
			verifyData,
		))
	}
}

func FuzzCanonicalHandshake13(f *testing.F) {
	f.Add(makeRawHandshake13(f, handshake.Header{
		Type:           handshake.TypeClientHello,
		Length:         2,
		FragmentLength: 2,
	}, []byte{0x01, 0x02}))
	f.Add([]byte{byte(handshake.TypeClientHello), 0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, err := canonicalHandshake13(data)
		if err != nil {
			return
		}
		if !(len(canonical) >= tlsHandshakeHeaderLength13) {
			t.Fatalf("expected %v >= %v", len(canonical), tlsHandshakeHeaderLength13)
			return
		}
		if len(canonical)-tlsHandshakeHeaderLength13 != int(util.BigEndianUint24(canonical[1:])) {
			t.Errorf("expected %v, got %v", len(canonical)-tlsHandshakeHeaderLength13, int(util.BigEndianUint24(canonical[1:])))
		}
		if data[0] != canonical[0] {
			t.Errorf("expected %v, got %v", data[0], canonical[0])
		}
		if !reflect.DeepEqual(data[handshake.HeaderLength:], canonical[tlsHandshakeHeaderLength13:]) {
			t.Errorf("expected %v, got %v", data[handshake.HeaderLength:], canonical[tlsHandshakeHeaderLength13:])
		}
	})
}

func makeRawHandshake13(tb testing.TB, header handshake.Header, body []byte) []byte {
	tb.Helper()

	rawHeader, err := header.Marshal()
	if err != nil {
		tb.Error(err)
	}

	return append(rawHeader, body...)
}

func canonicalTranscriptHandshake13(typ handshake.Type, body []byte) []byte {
	out := make([]byte, tlsHandshakeHeaderLength13+len(body))
	out[0] = byte(typ)
	util.PutBigEndianUint24(out[1:], uint32(len(body)))
	copy(out[tlsHandshakeHeaderLength13:], body)

	return out
}

func hashTranscript13(messages ...[]byte) []byte {
	hash := sha256.New()
	for _, message := range messages {
		_, _ = hash.Write(message)
	}

	return hash.Sum(nil)
}

func pskClientHelloTranscript13(tb testing.TB, binder []byte) ([]byte, []byte) {
	tb.Helper()

	msg := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		CipherSuiteIDs:     []uint16{0x1301},
		CompressionMethods: []*protocol.CompressionMethod{{}},
		Extensions: []extension.Extension{
			&extension.PreSharedKey{
				Identities: []extension.PskIdentity{
					{
						Identity:            []byte("psk-identity"),
						ObfuscatedTicketAge: 0x01020304,
					},
				},
				Binders: []extension.PskBinderEntry{binder},
			},
		},
	}

	body, err := msg.Marshal()
	if err != nil {
		tb.Error(err)
	}

	full := canonicalTranscriptHandshake13(handshake.TypeClientHello, body)
	truncatedLen := len(full) - (2 + 1 + len(binder))
	if !(truncatedLen > tlsHandshakeHeaderLength13) {
		tb.Errorf("expected %v > %v", truncatedLen, tlsHandshakeHeaderLength13)
	}

	return full, append([]byte(nil), full[:truncatedLen]...)
}

func hmacSHA25613(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)

	return mac.Sum(nil)
}
