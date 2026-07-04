package covertdtls

import (
	"errors"
	"strings"
)

const (
	// CovertDTLSConfigRandomize is a config string used for CovertDTLSConfig to enable ClientHello randomization.
	CovertDTLSConfigRandomize = "randomize"
	// CovertDTLSConfigMimic is a config string used for CovertDTLSConfig to enable ClientHello mimicking of the latest Chrome or Firefox version.
	CovertDTLSConfigMimic = "mimic"
	// CovertDTLSConfigRandomizeMimic is a config string used for CovertDTLSConfig to enable ClientHello mimicking of a random Chrome or Firefox fingerprint.
	CovertDTLSConfigRandomizeMimic = "randomizemimic"
	// CovertDTLSConfigDisable is a config string used for CovertDTLSConfig to disable the feature.
	CovertDTLSConfigDisable = "disable"
)

// CovertDTLSConfig is used to configure DTLS client hello behavior.
// This wrapper preserves compatibility with existing configuration interfaces,
// but current code no longer uses external DTLS ClientHello mimicry.
type CovertDTLSConfig struct {
	Randomize   bool
	Mimic       bool
	Fingerprint string
}

// ParseCovertDTLSConfigString creates a CovertDTLSConfig from a config string.
// Valid configurations strings are: mimic, randomize, randomizemimic and disable.
// Using randomizemimic is recommended for best stability and provides fingerprint-resistance against allow-listing.
// Using randomize is less stable and provides better fingerprint-resistance against block-listing.
func ParseCovertDTLSConfigString(str string) (CovertDTLSConfig, error) {
	config := CovertDTLSConfig{}
	str = strings.ToLower(str)
	switch str {
	case CovertDTLSConfigRandomize:
		config.Randomize = true
	case CovertDTLSConfigMimic:
		config.Mimic = true
	case CovertDTLSConfigRandomizeMimic:
		config.Randomize = true
		config.Mimic = true
	case CovertDTLSConfigDisable:
		config.Randomize = false
		config.Mimic = false
	default:
		return config, errors.New("unknown config string given to ParseCovertDTLSConfigString")
	}

	return config, nil
}
