// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import "github.com/pion/dtls/v3/pkg/protocol/extension"

// SRTPProtectionProfile defines the parameters and options that are in effect for the SRTP processing
// https://tools.ietf.org/html/rfc5764#section-4.1.2
type SRTPProtectionProfile = extension.SRTPProtectionProfile

const (
	SRTP_AES128_CM_HMAC_SHA1_80 SRTPProtectionProfile = extension.SRTP_AES128_CM_HMAC_SHA1_80
	SRTP_AES128_CM_HMAC_SHA1_32 SRTPProtectionProfile = extension.SRTP_AES128_CM_HMAC_SHA1_32
	SRTP_AES256_CM_SHA1_80      SRTPProtectionProfile = extension.SRTP_AES256_CM_SHA1_80
	SRTP_AES256_CM_SHA1_32      SRTPProtectionProfile = extension.SRTP_AES256_CM_SHA1_32
	SRTP_NULL_HMAC_SHA1_80      SRTPProtectionProfile = extension.SRTP_NULL_HMAC_SHA1_80
	SRTP_NULL_HMAC_SHA1_32      SRTPProtectionProfile = extension.SRTP_NULL_HMAC_SHA1_32
	SRTP_AEAD_AES_128_GCM       SRTPProtectionProfile = extension.SRTP_AEAD_AES_128_GCM
	SRTP_AEAD_AES_256_GCM       SRTPProtectionProfile = extension.SRTP_AEAD_AES_256_GCM
)
