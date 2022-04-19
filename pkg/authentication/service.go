package authentication

import (
	"crypto/rsa"
	"errors"

	jwt "github.com/golang-jwt/jwt/v4"
)

type service struct {
	publicKeys map[string]*rsa.PublicKey
}

func NewService() *service {
	return &service{
		publicKeys: make(map[string]*rsa.PublicKey),
	}
}

func SetPublicKeys() {

}

func (s *service) Verify(tokenString string) error {
	jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("AllYourBase"), nil
	})

	return errors.New("not implemented")
}
