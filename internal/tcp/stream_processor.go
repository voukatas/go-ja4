package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/voukatas/go-ja4/internal/model"
	"github.com/voukatas/go-ja4/internal/parser"
	"github.com/voukatas/go-ja4/pkg/ja4"
)

const maxBufferSize = 16 * 1024 // 16 KB

func processStream(r *tcpreader.ReaderStream, net gopacket.Flow, ja4Map, ja4sMap map[string]*model.FingerprintRecord) {
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
				ja4Fingerprint, err := ja4.ParseClientHelloForJA4(data[:totalLength], byte(protocol))
				if err != nil {
					fmt.Println("Error parsing TLS Client Hello:", err)
				} else {
					fmt.Printf("JA4 Fingerprint: %s network: %v\n", ja4Fingerprint, net)
					if val := ja4Map[ja4Fingerprint]; val != nil {
						parser.PrintRecord(val)
					}
				}

				// Remove the processed data from the buffer
				buffer.Next(totalLength)
				continue

			} else if handshakeType == 0x02 { // Server Hello
				//fmt.Println("Complete TLS Server Hello message detected")

				protocol := 't' // 't' for TCP
				ja4sFingerprint, err := ja4.ParseServerHelloForJA4S(data[:totalLength], byte(protocol))
				if err != nil {
					fmt.Println("Error parsing TLS Server Hello:", err)
				} else {
					//fmt.Printf("JA4S Fingerprint: %s\n", ja4sFingerprint)
					fmt.Printf("JA4S Fingerprint: %s network: %v\n", ja4sFingerprint, net)
					if val := ja4sMap[ja4sFingerprint]; val != nil {
						parser.PrintRecord(val)
					}
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
