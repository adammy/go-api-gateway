package authentication

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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
			s.AddPublicKey(*jwk.ID, &rsakey)
		}
	}

	return nil
}

// Verify the incoming JWT is valid.
func (s *Servicer) Verify(tokenString string) error {
	if tokenString == "" {
		return &UnauthorizedError{Message: "access token not provided"}
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"]
		if kid != nil && kid != "" {
			return s.publicKeys[kid.(string)], nil
		}
		return nil, &ForbiddenError{Message: "kid not present in header"}
	})

	if err != nil {
		return &ForbiddenError{Message: err.Error()}
	} else if !token.Valid {
		return &ForbiddenError{Message: "invalid token"}
	} else if token.Header["alg"] == nil {
		return &ForbiddenError{Message: "alg must be defined"}
	} else if token.Claims.(jwt.MapClaims)["iss"] != "https://id.adammy.com/oauth2/default" {
		return &ForbiddenError{Message: "invalid iss"}
	}

	return nil
}

// AddPublicKey adds a RSA key to the service.
func (s *Servicer) AddPublicKey(id string, key *rsa.PublicKey) {
	s.publicKeys[id] = key
}
