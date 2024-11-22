package util

func IsGreaseValue(val uint16) bool {
	highByte := uint8(val >> 8)
	lowByte := uint8(val & 0xff)
	return (val&0x0f0f) == 0x0a0a && highByte == lowByte
}

func MapTLSVersion(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfefd:
		return "d2" // DTLS 1.2
	case 0xfeff:
		return "d1" // DTLS 1.0
	case 0xfefc:
		return "d3" // DTLS 1.3
	default:
		return "00"
	}
}

// func IsTLSClientHelloComplete(data []byte) bool {
// 	if len(data) < 6 {
// 		return false
// 	}
// 	// TLS Handshake
// 	if data[0] != 0x16 {
// 		return false
// 	}
//
// 	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
// 	totalLength := 5 + recordLength
//
// 	if len(data) < totalLength {
// 		return false
// 	}
//
// 	// Handshake Type: Client Hello
// 	if data[5] != 0x01 {
// 		return false
// 	}
//
// 	return true
// }
//
// func IsTLSServerHelloComplete(data []byte) bool {
// 	if len(data) < 6 {
// 		return false
// 	}
//
// 	// TLS Handshake
// 	if data[0] != 0x16 {
// 		return false
// 	}
//
// 	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
// 	totalLength := 5 + recordLength
// 	if len(data) < totalLength {
// 		return false
// 	}
//
// 	// Handshake Type: Server Hello
// 	if data[5] != 0x02 {
// 		return false
// 	}
//
// 	return true
// }
