package authentication

import (
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	keyIds       = []string{"dpz1tNeVtWqQ9oLqLQCv5Q3AbYTy8wziDFaa4ZyL_wE", "xh_g87i9ClF9ZeZ4BA9Kq6cG0SyL8BbM1rPSpRvrdUY"}
	modulusBytes = []byte{181, 166, 253, 160, 160, 26, 25, 180, 60, 34, 1, 32, 170, 247, 226, 116, 201, 18, 227, 252, 217, 9, 232, 183, 169, 47, 24, 94, 166, 216, 245, 207, 114, 241, 91, 0, 76, 200, 205, 236, 202, 104, 171, 50, 31, 213, 203, 52, 48, 168, 150, 237, 52, 175, 128, 170, 56, 86, 55, 70, 123, 137, 205, 198, 89, 30, 180, 120, 104, 36, 218, 138, 229, 178, 204, 119, 72, 235, 108, 107, 200, 200, 148, 128, 149, 20, 200, 150, 45, 223, 250, 121, 209, 173, 47, 21, 182, 191, 184, 1, 104, 51, 36, 137, 38, 147, 72, 224, 187, 172, 187, 98, 197, 90, 144, 37, 198, 35, 109, 197, 254, 106, 255, 105, 213, 132, 232, 96, 181, 189, 28, 28, 156, 202, 245, 8, 16, 167, 93, 235, 245, 10, 34, 41, 31, 197, 12, 135, 88, 25, 141, 44, 110, 232, 134, 80, 98, 140, 94, 188, 250, 179, 174, 217, 249, 105, 119, 215, 190, 122, 53, 114, 241, 8, 0, 79, 117, 31, 48, 22, 221, 83, 86, 152, 111, 204, 36, 52, 211, 5, 133, 35, 189, 185, 222, 54, 177, 188, 89, 131, 16, 130, 36, 121, 33, 21, 221, 50, 172, 219, 251, 130, 128, 164, 102, 254, 146, 60, 200, 169, 163, 104, 188, 127, 110, 73, 195, 60, 70, 237, 246, 165, 60, 224, 231, 42, 31, 25, 119, 231, 91, 168, 198, 249, 113, 183, 225, 102, 1, 9, 123, 155, 75, 129, 147, 239}
)

func TestNewService(t *testing.T) {
	t.Parallel()

	svc := NewService("")

	assert.NotNil(t, svc)
	assert.Implements(t, (*Service)(nil), svc)
	assert.IsType(t, &Servicer{}, svc)
}

func TestSetPublicKeys(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		name       string
		jwks       interface{}
		statusCode int
		expected   map[string]*rsa.PublicKey
		httpError  bool
		error      bool
	}{
		"all valid keys": {
			jwks: rawJwks{
				Keys: []jwk{
					{
						ID:        &keyIds[0],
						Type:      "RSA",
						Algorithm: "RS256",
						Use:       "sig",
						Exponent:  "AQAB",
						Modulus:   "tab9oKAaGbQ8IgEgqvfidMkS4_zZCei3qS8YXqbY9c9y8VsATMjN7MpoqzIf1cs0MKiW7TSvgKo4VjdGe4nNxlketHhoJNqK5bLMd0jrbGvIyJSAlRTIli3f-nnRrS8Vtr-4AWgzJIkmk0jgu6y7YsVakCXGI23F_mr_adWE6GC1vRwcnMr1CBCnXev1CiIpH8UMh1gZjSxu6IZQYoxevPqzrtn5aXfXvno1cvEIAE91HzAW3VNWmG_MJDTTBYUjvbneNrG8WYMQgiR5IRXdMqzb-4KApGb-kjzIqaNovH9uScM8Ru32pTzg5yofGXfnW6jG-XG34WYBCXubS4GT7w",
					},
					{
						ID:        &keyIds[1],
						Type:      "RSA",
						Algorithm: "RS256",
						Use:       "sig",
						Exponent:  "AQAB",
						Modulus:   "tab9oKAaGbQ8IgEgqvfidMkS4_zZCei3qS8YXqbY9c9y8VsATMjN7MpoqzIf1cs0MKiW7TSvgKo4VjdGe4nNxlketHhoJNqK5bLMd0jrbGvIyJSAlRTIli3f-nnRrS8Vtr-4AWgzJIkmk0jgu6y7YsVakCXGI23F_mr_adWE6GC1vRwcnMr1CBCnXev1CiIpH8UMh1gZjSxu6IZQYoxevPqzrtn5aXfXvno1cvEIAE91HzAW3VNWmG_MJDTTBYUjvbneNrG8WYMQgiR5IRXdMqzb-4KApGb-kjzIqaNovH9uScM8Ru32pTzg5yofGXfnW6jG-XG34WYBCXubS4GT7w",
					},
				},
			},
			statusCode: http.StatusOK,
			expected: map[string]*rsa.PublicKey{
				keyIds[0]: {
					N: new(big.Int).SetBytes(modulusBytes),
					E: commonExponent,
				},
				keyIds[1]: {
					N: new(big.Int).SetBytes(modulusBytes),
					E: commonExponent,
				},
			},
		},
		"some valid keys": {
			jwks: rawJwks{
				Keys: []jwk{
					{
						ID:        &keyIds[0],
						Type:      "RSA",
						Algorithm: "RS256",
						Use:       "sig",
						Exponent:  "AQAB",
						Modulus:   "tab9oKAaGbQ8IgEgqvfidMkS4_zZCei3qS8YXqbY9c9y8VsATMjN7MpoqzIf1cs0MKiW7TSvgKo4VjdGe4nNxlketHhoJNqK5bLMd0jrbGvIyJSAlRTIli3f-nnRrS8Vtr-4AWgzJIkmk0jgu6y7YsVakCXGI23F_mr_adWE6GC1vRwcnMr1CBCnXev1CiIpH8UMh1gZjSxu6IZQYoxevPqzrtn5aXfXvno1cvEIAE91HzAW3VNWmG_MJDTTBYUjvbneNrG8WYMQgiR5IRXdMqzb-4KApGb-kjzIqaNovH9uScM8Ru32pTzg5yofGXfnW6jG-XG34WYBCXubS4GT7w",
					},
					{
						ID:        &keyIds[1],
						Type:      "RSA",
						Algorithm: "RS256",
						Use:       "enc",
						Exponent:  "AQAB",
						Modulus:   "tab9oKAaGbQ8IgEgqvfidMkS4_zZCei3qS8YXqbY9c9y8VsATMjN7MpoqzIf1cs0MKiW7TSvgKo4VjdGe4nNxlketHhoJNqK5bLMd0jrbGvIyJSAlRTIli3f-nnRrS8Vtr-4AWgzJIkmk0jgu6y7YsVakCXGI23F_mr_adWE6GC1vRwcnMr1CBCnXev1CiIpH8UMh1gZjSxu6IZQYoxevPqzrtn5aXfXvno1cvEIAE91HzAW3VNWmG_MJDTTBYUjvbneNrG8WYMQgiR5IRXdMqzb-4KApGb-kjzIqaNovH9uScM8Ru32pTzg5yofGXfnW6jG-XG34WYBCXubS4GT7w",
					},
				},
			},
			statusCode: http.StatusOK,
			expected: map[string]*rsa.PublicKey{
				keyIds[0]: {
					N: new(big.Int).SetBytes(modulusBytes),
					E: commonExponent,
				},
			},
		},
		"no keys": {
			jwks: rawJwks{
				Keys: []jwk{},
			},
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
			t.Parallel()
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
