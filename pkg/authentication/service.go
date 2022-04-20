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

var _ Service = (*Servicer)(nil)

const (
	commonExponent = 65537
)

// Servicer implements Service.
type Servicer struct {
	jwksURI    string
	publicKeys map[string]*rsa.PublicKey
}

// NewService creates a servicer.
func NewService(jwksURI string) *Servicer {
	return &Servicer{
		jwksURI:    jwksURI,
		publicKeys: make(map[string]*rsa.PublicKey),
	}
}

// SetPublicKeys gets the public keys and caches them in-mem.
func (s *Servicer) SetPublicKeys() error {
	var jwks rawJwks

	resp, err := http.Get(s.jwksURI)
	if err != nil {
		return fmt.Errorf("http error getting keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status code is non-200: %d", resp.StatusCode)
	}

	err = json.NewDecoder(resp.Body).Decode(&jwks)
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

// Verify TODO.
func (s *Servicer) Verify(tokenString string) error {
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})
	if err != nil {
		return fmt.Errorf("TODO %w", err)
	}

	return errors.New("not implemented")
}
