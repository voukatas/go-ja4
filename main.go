package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

const maxBufferSize = 16 * 1024 // 16 KB

func isGreaseValue(val uint16) bool {
	highByte := uint8(val >> 8)
	lowByte := uint8(val & 0xff)
	return (val&0x0f0f) == 0x0a0a && highByte == lowByte
}

func mapTLSVersion(version uint16) string {
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

func isAlnum(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b))
}

func buildHexList(values []uint16) string {
	hexList := make([]string, len(values))
	for i, val := range values {
		hexList[i] = fmt.Sprintf("%04x", val)
	}
	return strings.Join(hexList, ",")
}

func computeTruncatedSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:6])
}

func parseClientHelloForJA4(payload []byte, protocol byte) (string, error) {
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
		if !isGreaseValue(cipher) {
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

		if isGreaseValue(extType) {
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
					if !isAlnum(alpnValue[0]) {
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
				if !isGreaseValue(sigAlgo) {
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
				if !isGreaseValue(version) && version > highestSupportedVersion {
					highestSupportedVersion = version
				}
			}
		}

		// Move to the next extension
		offset = extDataEnd
	}

	// Determine TLS Version
	if supportedVersionsFound {
		tlsVersion = mapTLSVersion(highestSupportedVersion)
	} else {
		tlsVersion = mapTLSVersion(clientVersion)
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
	cipherStr := buildHexList(ciphers)
	var ja4b string
	if len(ciphers) == 0 {
		ja4b = "000000000000"
	} else {
		ja4b = computeTruncatedSHA256(cipherStr)
	}
	ja4Str.WriteString(ja4b)
	ja4Str.WriteByte('_')

	// Sort extensions
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })

	// Compute JA4_c (Extension Hash)
	extStr := buildHexList(extensions)
	if sigAlgoCount > 0 {
		extStr += "_"
		sigAlgoStr := buildHexList(signatureAlgorithms)
		extStr += sigAlgoStr
	}

	var ja4c string
	if len(extensions) == 0 {
		ja4c = "000000000000"
	} else {
		ja4c = computeTruncatedSHA256(extStr)
	}
	ja4Str.WriteString(ja4c)

	return ja4Str.String(), nil
}

func parseServerHelloForJA4S(payload []byte, protocol byte) (string, error) {
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

			if isGreaseValue(extType) {
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
						if !isAlnum(alpnValue[0]) {
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

				if !isGreaseValue(selectedVersion) {
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
		tlsVersion = mapTLSVersion(highestSupportedVersion)
	} else {
		tlsVersion = mapTLSVersion(serverVersion)
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
	extStr := buildHexList(extensions)

	var ja4s_c string
	if len(extensions) == 0 {
		ja4s_c = "000000000000"
	} else {
		ja4s_c = computeTruncatedSHA256(extStr)
	}

	// Construct the complete JA4S fingerprint
	ja4sStr.WriteString(ja4s_a)
	ja4sStr.WriteString("_")
	ja4sStr.WriteString(ja4s_b)
	ja4sStr.WriteString("_")
	ja4sStr.WriteString(ja4s_c)

	return ja4sStr.String(), nil
}

func isTLSClientHelloComplete(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	// TLS Handshake
	if data[0] != 0x16 {
		return false
	}

	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	totalLength := 5 + recordLength

	if len(data) < totalLength {
		return false
	}

	// Handshake Type: Client Hello
	if data[5] != 0x01 {
		return false
	}

	return true
}

func isTLSServerHelloComplete(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// TLS Handshake
	if data[0] != 0x16 {
		return false
	}

	recordLength := int(binary.BigEndian.Uint16(data[3:5]))
	totalLength := 5 + recordLength
	if len(data) < totalLength {
		return false
	}

	// Handshake Type: Server Hello
	if data[5] != 0x02 {
		return false
	}

	return true
}

type streamFactory struct{}

func (s *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	//fmt.Printf("New stream from %v to %v\n", net.Src(), net.Dst())
	go processStream(&r, net)
	return &r
}

func processStream(r *tcpreader.ReaderStream, net gopacket.Flow) {
	// fmt.Printf("Processing stream from %v to %v\n", net.Src(), net.Dst())
	// defer fmt.Printf("Finished processing stream from %v to %v\n", net.Src(), net.Dst())
	var buffer bytes.Buffer
	tmp := make([]byte, 1600)

	for {
		n, err := r.Read(tmp)
		if err != nil {
			if err == io.EOF {
				break
			}

			log.Println("Error reading from stream:", err)
			return
		}

		buffer.Write(tmp[:n])

		// Process all complete messages in the buffer
		for {
			data := buffer.Bytes()

			if len(data) < 6 {
				// Not enough data for TLS record header and handshake type
				break
			}

			// TLS Handshake
			if data[0] != 0x16 {
				// Not a TLS Handshake message, skip a byte
				buffer.Next(1)
				continue
			}

			recordLength := int(binary.BigEndian.Uint16(data[3:5]))
			totalLength := 5 + recordLength

			if len(data) < totalLength {
				// Not enough data for the complete TLS record
				break
			}

			// Get the handshake type
			handshakeType := data[5]

			// Client Hello
			if handshakeType == 0x01 {
				//fmt.Println("Complete TLS Client Hello message detected")

				// 't' for TCP
				protocol := 't'
				ja4Fingerprint, err := parseClientHelloForJA4(data[:totalLength], byte(protocol))
				if err != nil {
					fmt.Println("Error parsing TLS Client Hello:", err)
				} else {
					fmt.Printf("JA4 Fingerprint: %s network: %v\n", ja4Fingerprint, net)
				}

				// Remove the processed data from the buffer
				buffer.Next(totalLength)
				continue

			} else if handshakeType == 0x02 { // Server Hello
				//fmt.Println("Complete TLS Server Hello message detected")

				protocol := 't' // 't' for TCP
				ja4sFingerprint, err := parseServerHelloForJA4S(data[:totalLength], byte(protocol))
				if err != nil {
					fmt.Println("Error parsing TLS Server Hello:", err)
				} else {
					//fmt.Printf("JA4S Fingerprint: %s\n", ja4sFingerprint)
					fmt.Printf("JA4S Fingerprint: %s network: %v\n", ja4sFingerprint, net)
				}

				// Remove the processed data from the buffer
				buffer.Next(totalLength)
				continue
			} else {
				// Not interested in other handshake types
				// Skip the entire TLS record
				buffer.Next(totalLength)
				continue
			}
		}

		// Reset buffer if it grows too large
		if buffer.Len() > maxBufferSize {
			buffer.Reset()
		}
	}
}

func main() {

	// If too much memory is used change to 1600
	handle, err := pcap.OpenLive("enp0s3", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//err = handle.SetBPFFilter("tcp port 443")
	err = handle.SetBPFFilter("tcp")
	if err != nil {
		log.Fatal(err)
	}

	// Till here is normal flow
	streamFactory := &streamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	// Open pcap files
	//handle, err := pcap.OpenOffline("pcap/badcurveball.pcap")
	//handle, err := pcap.OpenOffline("pcap/ipv6.pcapng")
	//handle, err := pcap.OpenOffline("pcap/tls-handshake.pcapng")
	//handle, err := pcap.OpenOffline("pcap/weird_case_mine.pcapng")
	//handle, err := pcap.OpenOffline("pcap/tls12.pcap") // SYN packet is missing, gopacket requires the syn packet for the frame reassembly
	//handle, err := pcap.OpenOffline("pcap/weird_case_2_w_syn.pcap")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer handle.Close()
	// End of pcap files

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("DLT: ", handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			//fmt.Println("Received a Packet")

			if packet == nil {
				return
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				//fmt.Println("Processing a TCP packet")
				tcp := tcpLayer.(*layers.TCP)
				assembler.AssembleWithTimestamp(
					packet.NetworkLayer().NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				// Process UDP packet for QUIC/UDP
			}
		case <-ticker.C:
			// Avoid resource leak by cleaning up
			cutoff := time.Now().Add(-2 * time.Minute)
			flushedConn, closedConn := assembler.FlushWithOptions(tcpassembly.FlushOptions{CloseAll: false, T: cutoff})
			fmt.Printf("FlushWithOptions - flushedConn: %v closedConn: %v\n", flushedConn, closedConn)
		}
	}
}
