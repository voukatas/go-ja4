package util

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"
)

func IsAlnum(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b))
}

func BuildHexList(values []uint16) string {
	hexList := make([]string, len(values))
	for i, val := range values {
		hexList[i] = fmt.Sprintf("%04x", val)
	}
	return strings.Join(hexList, ",")
}

func ComputeTruncatedSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:6])
}
