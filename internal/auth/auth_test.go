package auth

import (
	"testing"
)

func TestEncryption(t *testing.T) {
	passw, err := HashPassword("i love google translate ㋡")
	if err != nil {
		t.Errorf("%v", err)
	}
	if err = CheckPasswordHash(passw, "i love google translate ㋡"); err != nil {
		t.Errorf("Value must be the same")
	}
}
