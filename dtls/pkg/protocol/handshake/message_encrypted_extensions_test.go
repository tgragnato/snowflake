// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

var errMarshalEncryptedExtensionsTest = errors.New("marshal encrypted extensions test")

type failingEncryptedExtensionsExtension struct{}

func (f *failingEncryptedExtensionsExtension) Marshal() ([]byte, error) {
	return nil, errMarshalEncryptedExtensionsTest
}

func (f *failingEncryptedExtensionsExtension) Unmarshal([]byte) error {
	return nil
}

func (f *failingEncryptedExtensionsExtension) TypeValue() extension.TypeValue {
	return extension.ALPNTypeValue
}

func TestMessageEncryptedExtensionsType(t *testing.T) {
	msg := &MessageEncryptedExtensions{}
	if TypeEncryptedExtensions != msg.Type() {
		t.Errorf("expected %v, got %v", TypeEncryptedExtensions, msg.Type())
	}
}

func TestMessageEncryptedExtensionsMarshal(t *testing.T) {
	t.Run("NoExtensions", func(t *testing.T) {
		raw, err := (&MessageEncryptedExtensions{}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte{0x00, 0x00}, raw) {
			t.Errorf("expected %v, got %v", []byte{0x00, 0x00}, raw)
		}
	})

	t.Run("WithExtensions", func(t *testing.T) {
		raw, err := (&MessageEncryptedExtensions{
			Extensions: []extension.Extension{
				&extension.ALPN{ProtocolNameList: []string{"h2", "http/1.1"}},
				&extension.UseExtendedMasterSecret{Supported: true},
			},
		}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte{
			0x00, 0x16, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x0e, // ALPN extension length
			0x00, 0x0c, // ALPN protocol name list length
			0x02, 0x68, 0x32, // h2
			0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
			0x00, 0x17, // extended_master_secret
			0x00, 0x00, // extended_master_secret extension length
		}, raw) {
			t.Errorf("expected %v, got %v", []byte{
				0x00, 0x16, // extensions length
				0x00, 0x10, // ALPN
				0x00, 0x0e, // ALPN extension length
				0x00, 0x0c, // ALPN protocol name list length
				0x02, 0x68, 0x32, // h2
				0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
				0x00, 0x17, // extended_master_secret
				0x00, 0x00, // extended_master_secret extension length
			}, raw)
		}
	})

	t.Run("ExtensionMarshalError", func(t *testing.T) {
		raw, err := (&MessageEncryptedExtensions{
			Extensions: []extension.Extension{&failingEncryptedExtensionsExtension{}},
		}).Marshal()
		if !errors.Is(err, errMarshalEncryptedExtensionsTest) {
			t.Errorf("expected error %v, got %v", errMarshalEncryptedExtensionsTest, err)
		}
		if raw != nil {
			t.Errorf("expected nil, got %v", raw)
		}
	})
}

func TestMessageEncryptedExtensionsUnmarshal(t *testing.T) {
	t.Run("EmptyExtensionList", func(t *testing.T) {
		msg := &MessageEncryptedExtensions{}

		err := msg.Unmarshal([]byte{0x00, 0x00})
		if err != nil {
			t.Fatal(err)
		}
		if len(msg.Extensions) != 0 {
			t.Error("expected empty")
		}
	})

	t.Run("ZeroLengthBuffer", func(t *testing.T) {
		msg := &MessageEncryptedExtensions{}

		err := msg.Unmarshal([]byte{})
		if !errors.Is(err, dtlserrors.ErrBufferTooSmall) {
			t.Fatalf("expected error %v, got %v", dtlserrors.ErrBufferTooSmall, err)
		}
		if len(msg.Extensions) != 0 {
			t.Error("expected empty")
		}
	})

	t.Run("WithExtensions", func(t *testing.T) {
		msg := &MessageEncryptedExtensions{}

		err := msg.Unmarshal([]byte{
			0x00, 0x16, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x0e, // ALPN extension length
			0x00, 0x0c, // ALPN protocol name list length
			0x02, 0x68, 0x32, // h2
			0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
			0x00, 0x17, // extended_master_secret
			0x00, 0x00, // extended_master_secret extension length
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(msg.Extensions) != 2 {
			t.Fatalf("expected len %d, got %d", 2, len(msg.Extensions))
		}

		alpn, ok := msg.Extensions[0].(*extension.ALPN)
		if !ok {
			t.Fatal("expected true")
		}
		if !reflect.DeepEqual([]string{"h2", "http/1.1"}, alpn.ProtocolNameList) {
			t.Errorf("expected %v, got %v", []string{"h2", "http/1.1"}, alpn.ProtocolNameList)
		}

		extendedMasterSecret, ok := msg.Extensions[1].(*extension.UseExtendedMasterSecret)
		if !ok {
			t.Fatal("expected true")
		}
		if !extendedMasterSecret.Supported {
			t.Error("expected true")
		}
	})

	t.Run("ShortExtensionListHeader", func(t *testing.T) {
		previouslyParsedExts := []extension.Extension{
			&extension.UseExtendedMasterSecret{Supported: true},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{0x00})
		if !errors.Is(err, dtlserrors.ErrBufferTooSmall) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrBufferTooSmall, err)
		}
		if !reflect.DeepEqual(previouslyParsedExts, msg.Extensions) {
			t.Errorf("expected %v, got %v", previouslyParsedExts, msg.Extensions)
		}
	})

	t.Run("MismatchedExtensionListLength", func(t *testing.T) {
		previouslyParsedExts := []extension.Extension{
			&extension.UseExtendedMasterSecret{Supported: true},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{0x00, 0x01})
		if !errors.Is(err, dtlserrors.ErrLengthMismatch) {
			t.Errorf("expected error %v, got %v", dtlserrors.ErrLengthMismatch, err)
		}
		if !reflect.DeepEqual(previouslyParsedExts, msg.Extensions) {
			t.Errorf("expected %v, got %v", previouslyParsedExts, msg.Extensions)
		}
	})

	t.Run("ExtensionUnmarshalError", func(t *testing.T) {
		previouslyParsedExts := []extension.Extension{
			&extension.UseExtendedMasterSecret{Supported: true},
		}
		msg := &MessageEncryptedExtensions{Extensions: previouslyParsedExts}

		err := msg.Unmarshal([]byte{
			0x00, 0x06, // extensions length
			0x00, 0x10, // ALPN
			0x00, 0x02, // ALPN extension length
			0x00, 0x00, // empty ALPN protocol name list
		})
		if !errors.Is(err, extension.ErrALPNInvalidFormat) {
			t.Errorf("expected error %v, got %v", extension.ErrALPNInvalidFormat, err)
		}
		if !reflect.DeepEqual(previouslyParsedExts, msg.Extensions) {
			t.Errorf("expected %v, got %v", previouslyParsedExts, msg.Extensions)
		}
	})
}
