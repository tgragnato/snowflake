package covertdtls

import (
	"errors"

	"github.com/pion/webrtc/v4"
)

func SetCovertDTLSSettings(config *CovertDTLSConfig, s *webrtc.SettingEngine) error {
	if config == nil && s == nil {
		return errors.New("nil pointers where passed to SetCovertDTLSSettings")
	}

	// DTLS ClientHello mimicry/randomization support has been removed.
	// This function remains for compatibility with existing configuration
	// interfaces, but does not modify the SettingEngine.
	return nil
}
