package authentication

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

const (
	modulusString        = "tab9oKAaGbQ8IgEgqvfidMkS4_zZCei3qS8YXqbY9c9y8VsATMjN7MpoqzIf1cs0MKiW7TSvgKo4VjdGe4nNxlketHhoJNqK5bLMd0jrbGvIyJSAlRTIli3f-nnRrS8Vtr-4AWgzJIkmk0jgu6y7YsVakCXGI23F_mr_adWE6GC1vRwcnMr1CBCnXev1CiIpH8UMh1gZjSxu6IZQYoxevPqzrtn5aXfXvno1cvEIAE91HzAW3VNWmG_MJDTTBYUjvbneNrG8WYMQgiR5IRXdMqzb-4KApGb-kjzIqaNovH9uScM8Ru32pTzg5yofGXfnW6jG-XG34WYBCXubS4GT7w"
	algorithmType        = "RSA"
	algorithm            = "RS256"
	commonExponentString = "AQAB"
	issuer               = "https://id.adammy.com/oauth2/default"
)

var (
	keyIds        = []string{"123", "456"}
	modulusBytes  = []byte{181, 166, 253, 160, 160, 26, 25, 180, 60, 34, 1, 32, 170, 247, 226, 116, 201, 18, 227, 252, 217, 9, 232, 183, 169, 47, 24, 94, 166, 216, 245, 207, 114, 241, 91, 0, 76, 200, 205, 236, 202, 104, 171, 50, 31, 213, 203, 52, 48, 168, 150, 237, 52, 175, 128, 170, 56, 86, 55, 70, 123, 137, 205, 198, 89, 30, 180, 120, 104, 36, 218, 138, 229, 178, 204, 119, 72, 235, 108, 107, 200, 200, 148, 128, 149, 20, 200, 150, 45, 223, 250, 121, 209, 173, 47, 21, 182, 191, 184, 1, 104, 51, 36, 137, 38, 147, 72, 224, 187, 172, 187, 98, 197, 90, 144, 37, 198, 35, 109, 197, 254, 106, 255, 105, 213, 132, 232, 96, 181, 189, 28, 28, 156, 202, 245, 8, 16, 167, 93, 235, 245, 10, 34, 41, 31, 197, 12, 135, 88, 25, 141, 44, 110, 232, 134, 80, 98, 140, 94, 188, 250, 179, 174, 217, 249, 105, 119, 215, 190, 122, 53, 114, 241, 8, 0, 79, 117, 31, 48, 22, 221, 83, 86, 152, 111, 204, 36, 52, 211, 5, 133, 35, 189, 185, 222, 54, 177, 188, 89, 131, 16, 130, 36, 121, 33, 21, 221, 50, 172, 219, 251, 130, 128, 164, 102, 254, 146, 60, 200, 169, 163, 104, 188, 127, 110, 73, 195, 60, 70, 237, 246, 165, 60, 224, 231, 42, 31, 25, 119, 231, 91, 168, 198, 249, 113, 183, 225, 102, 1, 9, 123, 155, 75, 129, 147, 239}
	rsaKeyModulus = new(big.Int).SetBytes(modulusBytes)
	now           = time.Now().Unix()
)

func TestNewService(t *testing.T) {
	svc := NewService("")

	assert.NotNil(t, svc)
	assert.Implements(t, (*Service)(nil), svc)
	assert.IsType(t, &Servicer{}, svc)
}

func TestSetPublicKeys(t *testing.T) {
	tests := map[string]struct {
		jwks       interface{}
		statusCode int
		expected   map[string]*rsa.PublicKey
		httpError  bool
		error      bool
	}{
		"all valid keys": {
			jwks: rawJwks{
				Keys: []jwk{
					getJwk(keyIds[0], "sig"),
					getJwk(keyIds[1], "sig"),
				},
			},
			statusCode: http.StatusOK,
			expected: map[string]*rsa.PublicKey{
				keyIds[0]: {
					N: rsaKeyModulus,
					E: commonExponent,
				},
				keyIds[1]: {
					N: rsaKeyModulus,
					E: commonExponent,
				},
			},
		},
		"some valid keys": {
			jwks: rawJwks{
				Keys: []jwk{
					getJwk(keyIds[0], "sig"),
					getJwk(keyIds[1], "enc"),
				},
			},
			statusCode: http.StatusOK,
			expected: map[string]*rsa.PublicKey{
				keyIds[0]: {
					N: rsaKeyModulus,
					E: commonExponent,
				},
			},
		},
		"no keys": {
			jwks:       rawJwks{Keys: []jwk{}},
			statusCode: http.StatusOK,
			expected:   map[string]*rsa.PublicKey{},
		},
		"invalid json": {
			jwks:       "super invalid",
			statusCode: http.StatusOK,
			error:      true,
		},
		"http error": {
			httpError: true,
			error:     true,
		},
		"non-200 http status": {
			statusCode: http.StatusNotFound,
			error:      true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				server *httptest.Server
				svc    *Servicer
			)

			if !tc.httpError {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.statusCode)
					err := json.NewEncoder(w).Encode(tc.jwks)
					if err != nil {
						assert.FailNow(t, "unable to encode jwks data: %w", err)
					}
				}))
				svc = NewService(server.URL)
			} else {
				svc = NewService("http://127.0.0.1:99999")
			}

			err := svc.SetPublicKeys()
			if !tc.error {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, svc.publicKeys)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	tests := map[string]struct {
		claims            jwt.StandardClaims
		emptyToken        bool
		forbiddenError    bool
		unauthorizedError bool
	}{
		"valid jwt": {
			claims: jwt.StandardClaims{Issuer: issuer, IssuedAt: now, NotBefore: now, ExpiresAt: now + 900},
		},
		"empty token": {emptyToken: true, unauthorizedError: true},
		"expired jwt": {
			claims:         jwt.StandardClaims{Issuer: issuer, IssuedAt: now, NotBefore: now, ExpiresAt: now - 900},
			forbiddenError: true,
		},
		"not before is later": {
			claims:         jwt.StandardClaims{Issuer: issuer, IssuedAt: now, NotBefore: now + 900, ExpiresAt: now + 900},
			forbiddenError: true,
		},
		"invalid issuer": {
			claims:         jwt.StandardClaims{Issuer: "invalid issuer", IssuedAt: now, NotBefore: now, ExpiresAt: now + 900},
			forbiddenError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				tokenString string
			)
			svc := NewService("")

			if !tc.emptyToken {
				publicKey, token, err := getKeyAndToken(keyIds[0], tc.claims)
				if err != nil {
					assert.FailNow(t, "unable to generate key and token")
				}
				tokenString = token
				svc.AddPublicKey(keyIds[0], publicKey)
			}
			err := svc.Verify(tokenString)

			if tc.forbiddenError {
				assert.Error(t, err)
				assert.IsType(t, &ForbiddenError{}, err)
			} else if tc.unauthorizedError {
				assert.Error(t, err)
				assert.IsType(t, &UnauthorizedError{}, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAddPublicKey(t *testing.T) {
	svc := NewService("")
	publicKey, _, err := getKeyAndToken(keyIds[0], jwt.StandardClaims{})
	if err != nil {
		assert.FailNow(t, "unable to generate key")
	}

	svc.AddPublicKey(keyIds[0], publicKey)

	assert.Equal(t, map[string]*rsa.PublicKey{keyIds[0]: publicKey}, svc.publicKeys)
}

func getJwk(id, use string) jwk {
	return jwk{
		ID:        &id,
		Type:      algorithmType,
		Algorithm: algorithm,
		Use:       use,
		Exponent:  commonExponentString,
		Modulus:   modulusString,
	}
}

func getKeyAndToken(id string, claims jwt.StandardClaims) (*rsa.PublicKey, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("error generating random key: %w", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = id

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("error singing the token: %w", err)
	}

	return &privateKey.PublicKey, tokenString, nil
}
