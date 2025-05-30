package auth

import (
	"github.com/google/uuid"
	"net/http"
	"testing"
	"time"
)

func TestEncryption(t *testing.T) {
	passw, err := HashPassword("i love google translate ㋡")
	if err != nil {
		t.Logf("%v", err)
	}
	t.Logf("test passw: %s", passw)
	if err = CheckPasswordHash(passw, "i love google translate ㋡"); err != nil {
		t.Log("Value must be the same")
	}
}

func TestJwt(t *testing.T) {
	testsecret := "haha-this-is-so-secret"
	testid := uuid.New()
	string, err := MakeJWT(testid, testsecret, time.Duration(time.Second*5))
	if err != nil {
		t.Logf("%v", err)
	}
	t.Logf("TestJwttoken: %s\n", string)
	id, err := ValidateJWT(string, testsecret)
	if err != nil {
		t.Logf("%v", err)
	}
	t.Logf("TestJwtid: %s\n", id)
	if testid != id {
		t.Errorf("ids must be equal")
	}
}

func TestBearerTokenReceiver(t *testing.T) {
	header := http.Header{}
	header.Add("authorization", "pollo")
	string, err := GetBearerToken(header)
	t.Logf("Tokenreceivertoken: %s\n", string)
	if err != nil {
		t.Errorf("%v", err)
	}
	if string != header.Get("authorization") {
		t.Error("Token does not match header's")
	}
}
