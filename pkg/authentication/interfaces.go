package authentication

type service interface {
	SetPublicKeys() error
	Verify(tokenString string) error
}
