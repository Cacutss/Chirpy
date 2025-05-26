package auth

import (
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(passw string) (string, error) {
	encrypted, err := bcrypt.GenerateFromPassword([]byte(passw), 12)
	return string(encrypted), err
}

func CheckPasswordHash(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}
