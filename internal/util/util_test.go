package util

import (
	"testing"
)

// helper
func TestComputeTruncatedSHA256(t *testing.T) {
	str := "this is a test"
	expected := "2e9975854897"
	res := ComputeTruncatedSHA256(str)

	if res != expected {
		t.Errorf("expected %v received %v", expected, res)
	}
}

func TestIsAlnum(t *testing.T) {
	num := byte('2')
	letter := byte('a')
	symbol := byte('!')

	if !IsAlnum(num) {
		t.Errorf("expected %v received %v", true, false)
	}

	if !IsAlnum(letter) {
		t.Errorf("expected %v received %v", true, false)
	}

	if IsAlnum(symbol) {
		t.Errorf("expected %v received %v", false, true)
	}

}

func TestBuildHexList(t *testing.T) {
	values := []uint16{0, 3, 10, 65535}

	expected := "0000,0003,000a,ffff"
	res := BuildHexList(values)

	if expected != res {
		t.Errorf("expected %v received %v", expected, res)

	}

}
