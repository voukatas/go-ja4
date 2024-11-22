package ja4

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/voukatas/go-ja4/internal/util"
)

func ParseServerHelloForJA4S(payload []byte, protocol byte) (string, error) {
	offset := 0

	// Skip TLS record header (5 bytes)
	if len(payload) < 5 {
		return "", fmt.Errorf("payload too short for TLS record header")
	}
	offset += 5

	// Check if payload length is sufficient
	if offset+4 > len(payload) {
		return "", fmt.Errorf("payload too short for Handshake Protocol header")
	}

	// Handshake Type and Length
	handshakeType := payload[offset]
	handshakeLength := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])
	offset += 4

	// SERVER_HELLO
	if handshakeType != 0x02 {
		return "", fmt.Errorf("not a Server Hello message")
	}

	if offset+handshakeLength > len(payload) {
		return "", fmt.Errorf("incomplete Server Hello message")
	}

	// Start building the JA4S fingerprint
	var ja4sStr strings.Builder
	ja4sStr.WriteByte(protocol)

	// Server Version
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for server version")
	}
	serverVersion := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Initialize TLS Version
	tlsVersion := "00"

	// Skip Random (32 bytes)
	if offset+32 > len(payload) {
		return "", fmt.Errorf("payload too short for server random")
	}
	offset += 32

	// Session ID Length
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for session ID length")
	}
	sessionIDLen := int(payload[offset])
	offset += 1

	// Session ID
	if offset+sessionIDLen > len(payload) {
		return "", fmt.Errorf("payload too short for session ID")
	}
	offset += sessionIDLen

	// Cipher Suite
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for cipher suite")
	}
	cipherSuite := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Compression Method
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for compression method")
	}
	offset += 1

	// Initialize variables for extensions
	extensions := make([]uint16, 0)
	alpnChosen := "00"
	extensionCountWithSNI_ALPN := 0
	supportedVersionsFound := false
	highestSupportedVersion := uint16(0)

	// Check if there are extensions
	if offset < len(payload) {
		// Extensions Length
		if offset+2 > len(payload) {
			return "", fmt.Errorf("payload too short for extensions length")
		}
		extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2

		if offset+extensionsLen > len(payload) {
			return "", fmt.Errorf("payload too short for extensions")
		}

		extensionsEnd := offset + extensionsLen

		// Parse Extensions
		for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
			extType := binary.BigEndian.Uint16(payload[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
			offset += 4

			if offset+extLen > extensionsEnd || offset+extLen > len(payload) {
				break
			}

			if util.IsGreaseValue(extType) {
				// Skip GREASE extension
				offset = extensionsEnd
				continue
			}

			extensionCountWithSNI_ALPN++

			// Collect extension types
			// SNI_EXT and ALPN_EXT
			if extType != 0x0000 && extType != 0x0010 {
				extensions = append(extensions, extType)
			}

			// ALPN_EXT
			if extType == 0x0010 && extLen > 0 {
				alpnOffset := offset
				if alpnOffset+2 > extensionsEnd {
					return "", fmt.Errorf("payload too short for ALPN list length")
				}
				alpnListLen := int(binary.BigEndian.Uint16(payload[alpnOffset : alpnOffset+2]))
				alpnOffset += 2
				if alpnOffset+alpnListLen > extensionsEnd {
					return "", fmt.Errorf("incomplete ALPN list")
				}
				if alpnListLen > 0 {
					if alpnOffset+1 > extensionsEnd {
						return "", fmt.Errorf("payload too short for ALPN string length")
					}
					alpnStrLen := int(payload[alpnOffset])
					alpnOffset += 1
					if alpnOffset+alpnStrLen > extensionsEnd {
						return "", fmt.Errorf("incomplete ALPN string")
					}
					if alpnStrLen > 0 {
						alpnValue := payload[alpnOffset : alpnOffset+alpnStrLen]
						// Get the ALPN string
						alpnStr := string(alpnValue)
						if !util.IsAlnum(alpnValue[0]) {
							alpnChosen = "99"
						} else {
							alpnChosen = alpnStr
						}
					}
				}
			}

			// SUPPORTED_VERSIONS_EXT
			if extType == 0x002b {
				supportedVersionsFound = true
				svOffset := offset
				if svOffset+1 > extensionsEnd {
					return "", fmt.Errorf("payload too short for supported versions length")
				}
				//svLen := int(payload[svOffset])
				//svOffset += 1
				if svOffset+extLen > extensionsEnd {
					return "", fmt.Errorf("incomplete supported versions data")
				}

				//fmt.Printf("--- svLen :%x\n", extLen)
				if extLen != 2 {
					return "", fmt.Errorf("invalid supported versions length in ServerHello")
				}

				selectedVersion := binary.BigEndian.Uint16(payload[svOffset : svOffset+2])
				//fmt.Printf("--- selected version: %x", selectedVersion)

				if !util.IsGreaseValue(selectedVersion) {
					highestSupportedVersion = selectedVersion
				}

			}

			// Move to the next extension
			offset += extLen
		}

	}

	// Build the JA4S fingerprint

	// Determine TLS Version
	if supportedVersionsFound {
		tlsVersion = util.MapTLSVersion(highestSupportedVersion)
	} else {
		tlsVersion = util.MapTLSVersion(serverVersion)
	}

	// Extension Count
	totalExtensionCount := extensionCountWithSNI_ALPN
	if totalExtensionCount > 99 {
		totalExtensionCount = 99
	}

	numExtensions := totalExtensionCount

	// ALPN Characters
	alpnFirstChar := '0'
	alpnLastChar := '0'
	if len(alpnChosen) > 0 {
		alpnFirstChar = rune(alpnChosen[0])
		alpnLastChar = rune(alpnChosen[len(alpnChosen)-1])
	}
	//fmt.Println("---tlsversion: ", tlsVersion)
	ja4s_a := fmt.Sprintf("%s%02d%c%c", tlsVersion, numExtensions, alpnFirstChar, alpnLastChar)

	// JA4S_b: Cipher Suite Chosen
	ja4s_b := fmt.Sprintf("%04x", cipherSuite)

	// JA4S_c: Truncated SHA256 Hash of the Extensions
	extStr := util.BuildHexList(extensions)

	var ja4s_c string
	if len(extensions) == 0 {
		ja4s_c = "000000000000"
	} else {
		ja4s_c = util.ComputeTruncatedSHA256(extStr)
	}

	// Construct the complete JA4S fingerprint
	ja4sStr.WriteString(ja4s_a)
	ja4sStr.WriteString("_")
	ja4sStr.WriteString(ja4s_b)
	ja4sStr.WriteString("_")
	ja4sStr.WriteString(ja4s_c)

	return ja4sStr.String(), nil
}
