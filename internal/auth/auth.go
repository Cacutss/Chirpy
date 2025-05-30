package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
)

func HashPassword(passw string) (string, error) {
	encrypted, err := bcrypt.GenerateFromPassword([]byte(passw), 12)
	return string(encrypted), err
}

func CheckPasswordHash(hash, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}

func MakeJWT(userID uuid.UUID, tokensecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Issuer: "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	})
	return token.SignedString([]byte(tokensecret))
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) { return []byte(tokenSecret), nil })
	if err != nil {
		return uuid.UUID{}, err
	}
	id, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	returnid, err := uuid.Parse(id)
	if err != nil {
		return uuid.UUID{}, err
	}
	return returnid, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	tokenstring := headers.Get("Authorization")
	if tokenstring == "" {
		return "", errors.New("No token or invalid token")
	}
	token := strings.TrimPrefix(tokenstring, "Bearer ")
	return token, nil
}

func MakeRefreshToken() (string, error) {
	randomdata := make([]byte, 32)
	rand.Read(randomdata)
	stringed := hex.EncodeToString(randomdata)
	return stringed, nil
}
