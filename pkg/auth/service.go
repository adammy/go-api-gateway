package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

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

// NewService creates a Servicer.
func NewService(jwksURI string) *Servicer {
	return &Servicer{
		jwksURI:    jwksURI,
		publicKeys: make(map[string]*rsa.PublicKey),
	}
}

// SetPublicKeys will fetch keys from an OIDC endpoint and store them internally on the Service.
func (s *Servicer) SetPublicKeys() error {
	var jwks JWKSResponse

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
			s.AddPublicKey(*jwk.ID, &rsakey)
		}
	}

	return nil
}

// AddPublicKey will add a public key to the Service.
func (s *Servicer) AddPublicKey(id string, key *rsa.PublicKey) {
	s.publicKeys[id] = key
}

// Verify will validate that an incoming JWT is valid.
func (s *Servicer) Verify(tokenString string) error {
	if tokenString == "" {
		return &UnauthorizedError{
			Err: errors.New("access token not provided"),
		}
	}

	if !strings.HasPrefix(tokenString, "Bearer ") {
		return &UnauthorizedError{
			Err: errors.New("invalid token type"),
		}
	}

	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"]
		if kid != nil && kid != "" {
			return s.publicKeys[kid.(string)], nil
		}
		return nil, &ForbiddenError{
			Err: errors.New("kid not present in header"),
		}
	})

	if err != nil {
		return &ForbiddenError{
			Err: err,
		}
	}

	if !token.Valid {
		return &ForbiddenError{
			Err: errors.New("invalid token"),
		}
	}

	if token.Header["alg"] == nil {
		return &ForbiddenError{
			Err: errors.New("alg must be defined"),
		}
	}

	if token.Claims.(jwt.MapClaims)["iss"] != "https://id.adammy.com/oauth2/default" {
		return &ForbiddenError{
			Err: errors.New("invalid iss"),
		}
	}

	return nil
}
