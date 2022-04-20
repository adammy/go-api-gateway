package authentication

// Service contains business logic for authentication.
type Service interface {
	SetPublicKeys() error
	Verify(tokenString string) error
}
