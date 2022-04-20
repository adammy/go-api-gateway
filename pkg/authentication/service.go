package authentication

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	jwt "github.com/golang-jwt/jwt/v4"
)

var _ service = (*servicer)(nil)

const (
	commonExponent = 65537
)

type servicer struct {
	jwksUri    string
	publicKeys map[string]*rsa.PublicKey
}

func NewService(jwksUri string) *servicer {
	return &servicer{
		jwksUri:    jwksUri,
		publicKeys: make(map[string]*rsa.PublicKey),
	}
}

func (s *servicer) SetPublicKeys() error {
	var jwks rawJwks

	r, err := http.Get(s.jwksUri)
	if err != nil {
		return fmt.Errorf("http error getting keys: %w", err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("http status code is non-200: %d", r.StatusCode)
	}

	err = json.NewDecoder(r.Body).Decode(&jwks)
	if err != nil {
		return fmt.Errorf("error decoding json: %w", err)
	}

	for _, jwk := range jwks.Keys {
		if (jwk.ID != nil) && (jwk.Use == "sig") && (jwk.Type == "RSA") && (jwk.Algorithm == "RS256") && (jwk.Exponent == "AQAB") {
			modulus, _ := base64.RawURLEncoding.DecodeString(jwk.Modulus)
			rsakey := rsa.PublicKey{
				N: new(big.Int).SetBytes(modulus),
				E: commonExponent,
			}
			s.publicKeys[*jwk.ID] = &rsakey
		}
	}

	return nil
}

func (s *servicer) Verify(tokenString string) error {
	jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})

	return errors.New("not implemented")
}
