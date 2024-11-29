package parser

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/voukatas/go-ja4/internal/model"
)

func LoadFingerPrints(fileName string) (map[string]*model.FingerprintRecord, map[string]*model.FingerprintRecord, error) {
	file, err := os.Open(fileName)
	if err != nil {
		//log.Println("Failed to open file: %v", err)
		return nil, nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	// Read opening bracket of the JSON array
	_, err = decoder.Token()
	if err != nil {
		//log.Fatalf("Failed to read JSON token: %v", err)
		return nil, nil, fmt.Errorf("failed to read json token: %v", err)
	}

	ja4Map := make(map[string]*model.FingerprintRecord)
	ja4sMap := make(map[string]*model.FingerprintRecord)

	// Decode each element in the array
	for decoder.More() {
		var record model.FingerprintRecord
		err := decoder.Decode(&record)
		if err != nil {
			//log.Fatalf("Failed to decode JSON: %v", err)
			return nil, nil, fmt.Errorf("failed to decode json: %v", err)
		}

		recordPointer := &record

		if record.Ja4Fingerprint != nil {
			ja4Map[*record.Ja4Fingerprint] = recordPointer
		}
		if record.Ja4sFingerprint != nil {
			ja4sMap[*record.Ja4sFingerprint] = recordPointer
		}
	}

	// Read closing bracket
	_, err = decoder.Token()
	if err != nil {
		//log.Fatalf("Failed to read closing JSON token: %v", err)
		return nil, nil, fmt.Errorf("failed to read closing json token: %v", err)
	}

	// fmt.Printf("Number of Ja4Fingerprints: %d\n", len(ja4Map))
	// fmt.Printf("Number of Ja4sFingerprints: %d\n", len(ja4sMap))
	//
	// fmt.Println("Map based on Ja4Fingerprint:")
	// for key, value := range ja4Map {
	// 	fmt.Printf("Key: %s\n", key)
	// 	PrintRecord(value)
	// }
	//
	// fmt.Println("\nMap based on Ja4sFingerprint:")
	// for key, value := range ja4sMap {
	// 	fmt.Printf("Key: %s\n", key)
	// 	PrintRecord(value)
	// }

	return ja4Map, ja4sMap, nil
}

func PrintRecord(record *model.FingerprintRecord) {
	fmt.Printf("  Application: %s\n", deref(record.Application))
	fmt.Printf("  Library: %s\n", deref(record.Library))
	fmt.Printf("  Device: %s\n", deref(record.Device))
	fmt.Printf("  OS: %s\n", deref(record.OS))
	fmt.Printf("  User Agent String: %s\n", deref(record.UserAgentString))
	fmt.Printf("  Certificate Authority: %s\n", deref(record.CertificateAuthority))
	fmt.Printf("  Observation Count: %d\n", record.ObservationCount)
	fmt.Printf("  Verified: %t\n", record.Verified)
	fmt.Printf("  Notes: %s\n", deref(record.Notes))
	fmt.Printf("  JA4 Fingerprint: %s\n", deref(record.Ja4Fingerprint))
	fmt.Printf("  JA4 Fingerprint String: %s\n", deref(record.Ja4FingerprintString))
	fmt.Printf("  JA4s Fingerprint: %s\n", deref(record.Ja4sFingerprint))
	fmt.Printf("  JA4h Fingerprint: %s\n", deref(record.Ja4hFingerprint))
	fmt.Printf("  JA4x Fingerprint: %s\n", deref(record.Ja4xFingerprint))
	fmt.Printf("  JA4t Fingerprint: %s\n", deref(record.Ja4tFingerprint))
	fmt.Printf("  JA4ts Fingerprint: %s\n", deref(record.Ja4tsFingerprint))
	fmt.Printf("  JA4tscan Fingerprint: %s\n", deref(record.Ja4tscanFingerprint))
	fmt.Println()
}

func deref(str *string) string {
	if str == nil {
		return "<nil>"
	}
	return *str
}
