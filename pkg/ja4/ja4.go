package ja4

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/voukatas/go-ja4/internal/util"
)

func ParseClientHelloForJA4(payload []byte, protocol byte) (string, error) {
	offset := 0

	// Skip TLS/DTLS record header (5 bytes)
	offset += 5

	if offset+4 > len(payload) {
		return "", fmt.Errorf("payload too short")
	}

	// Handshake Type and Length
	handshakeType := payload[offset]
	handshakeLength := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])
	offset += 4

	// CLIENT_HELLO
	if handshakeType != 0x01 {
		return "", fmt.Errorf("not a Client Hello message")
	}

	if offset+handshakeLength > len(payload) {
		return "", fmt.Errorf("incomplete Client Hello message")
	}

	// Start building the JA4 fingerprint
	var ja4Str strings.Builder
	ja4Str.WriteByte(protocol)

	// Client Version
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for client version")
	}
	clientVersion := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Initialize TLS Version
	tlsVersion := "00"

	// Skip Random (32 bytes)
	if offset+32 > len(payload) {
		return "", fmt.Errorf("payload too short for server random")
	}
	offset += 32

	// Session ID
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for session ID length")
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLen > len(payload) {
		return "", fmt.Errorf("incomplete cipher suites data")
	}

	ciphers := make([]uint16, 0)

	for i := 0; i < cipherSuitesLen; i += 2 {
		cipher := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if !util.IsGreaseValue(cipher) {
			ciphers = append(ciphers, cipher)
		}
	}
	offset += cipherSuitesLen

	// Compression Methods
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for compression methods length")
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	// Extensions
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	extensions := make([]uint16, 0)
	extensionCountWithSNI_ALPN := 0
	sniFound := false
	alpn := "00"
	sigAlgoCount := 0
	signatureAlgorithms := make([]uint16, 0)
	supportedVersionsFound := false
	highestSupportedVersion := uint16(0)

	extensionsEnd := offset + extensionsLen

	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > extensionsEnd || offset+extLen > len(payload) {
			break
		}

		extDataEnd := offset + extLen

		if util.IsGreaseValue(extType) {
			// Skip GREASE extension
			offset = extDataEnd
			continue
		}

		extensionCountWithSNI_ALPN++

		if extType != 0x0000 && extType != 0x0010 { // SNI_EXT and ALPN_EXT
			extensions = append(extensions, extType)
		}

		if extType == 0x0000 { // SNI_EXT
			sniFound = true
		}

		if extType == 0x0010 && extLen > 0 { // ALPN_EXT
			alpnOffset := offset
			if alpnOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for ALPN list length")
			}
			alpnListLen := int(binary.BigEndian.Uint16(payload[alpnOffset : alpnOffset+2]))
			alpnOffset += 2
			if alpnOffset+alpnListLen > extDataEnd {
				return "", fmt.Errorf("incomplete ALPN list")
			}
			if alpnListLen > 0 {
				if alpnOffset+1 > extDataEnd {
					return "", fmt.Errorf("payload too short for ALPN string length")
				}
				alpnStrLen := int(payload[alpnOffset])
				alpnOffset += 1
				if alpnOffset+alpnStrLen > extDataEnd {
					return "", fmt.Errorf("incomplete ALPN string")
				}
				if alpnStrLen > 0 {
					alpnValue := payload[alpnOffset : alpnOffset+alpnStrLen]
					// Get the ALPN string
					alpnStr := string(alpnValue)
					if !util.IsAlnum(alpnValue[0]) {
						alpn = "99"
					} else {
						alpn = alpnStr
					}
				}
			}
		}

		// SIGNATURE_ALGORITHMS_EXT
		if extType == 0x000d {
			sigOffset := offset
			if sigOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for signature algorithms length")
			}
			sigAlgsLen := int(binary.BigEndian.Uint16(payload[sigOffset : sigOffset+2]))
			sigOffset += 2
			if sigOffset+sigAlgsLen > extDataEnd {
				return "", fmt.Errorf("incomplete signature algorithms data")
			}
			for j := 0; j < sigAlgsLen; j += 2 {
				sigAlgo := binary.BigEndian.Uint16(payload[sigOffset+j : sigOffset+j+2])
				if !util.IsGreaseValue(sigAlgo) {
					signatureAlgorithms = append(signatureAlgorithms, sigAlgo)
					sigAlgoCount++
				}
			}
		}

		// SUPPORTED_VERSIONS_EXT
		if extType == 0x002b {
			supportedVersionsFound = true
			svOffset := offset
			if svOffset+1 > extDataEnd {
				return "", fmt.Errorf("payload too short for supported versions length")
			}
			svLen := int(payload[svOffset])
			svOffset += 1
			if svOffset+svLen > extDataEnd {
				return "", fmt.Errorf("incomplete supported versions data")
			}
			for j := 0; j < svLen; j += 2 {
				if svOffset+j+1 >= extDataEnd {
					break
				}
				version := binary.BigEndian.Uint16(payload[svOffset+j : svOffset+j+2])
				//fmt.Printf("--- client hello version in hex %x \n", version)
				if !util.IsGreaseValue(version) && version > highestSupportedVersion {
					highestSupportedVersion = version
				}
			}
		}

		// Move to the next extension
		offset = extDataEnd
	}

	// Determine TLS Version
	if supportedVersionsFound {
		tlsVersion = util.MapTLSVersion(highestSupportedVersion)
	} else {
		tlsVersion = util.MapTLSVersion(clientVersion)
	}

	// SNI Indicator
	sniIndicator := 'i'
	if sniFound {
		sniIndicator = 'd'
	}

	// Cipher Count
	cipherCountDisplay := len(ciphers)
	if cipherCountDisplay > 99 {
		cipherCountDisplay = 99
	}

	// Extension Count
	totalExtensionCount := extensionCountWithSNI_ALPN
	if totalExtensionCount > 99 {
		totalExtensionCount = 99
	}

	// Build the JA4 string up to ALPN
	ja4Str.WriteString(tlsVersion)
	ja4Str.WriteByte(byte(sniIndicator))

	// ALPN Characters
	alpnFirstChar := '0'
	alpnLastChar := '0'
	if len(alpn) > 0 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = rune(alpn[len(alpn)-1])
	}

	// Build the complete JA4 string
	ja4Str.WriteString(fmt.Sprintf("%02d%02d%c%c_", cipherCountDisplay, totalExtensionCount, alpnFirstChar, alpnLastChar))

	// Sort ciphers
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })

	// Compute JA4_b (Cipher Hash)
	cipherStr := util.BuildHexList(ciphers)
	var ja4b string
	if len(ciphers) == 0 {
		ja4b = "000000000000"
	} else {
		ja4b = util.ComputeTruncatedSHA256(cipherStr)
	}
	ja4Str.WriteString(ja4b)
	ja4Str.WriteByte('_')

	// Sort extensions
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })

	// Compute JA4_c (Extension Hash)
	extStr := util.BuildHexList(extensions)
	if sigAlgoCount > 0 {
		extStr += "_"
		sigAlgoStr := util.BuildHexList(signatureAlgorithms)
		extStr += sigAlgoStr
	}

	var ja4c string
	if len(extensions) == 0 {
		ja4c = "000000000000"
	} else {
		ja4c = util.ComputeTruncatedSHA256(extStr)
	}
	ja4Str.WriteString(ja4c)

	return ja4Str.String(), nil
}
