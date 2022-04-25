package auth

import (
	"crypto/rsa"
)

// Service contains business logic for auth.
type Service interface {
	SetPublicKeys() error
	AddPublicKey(id string, key *rsa.PublicKey)
	Verify(tokenString string) error
}
