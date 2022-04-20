package authentication

type jwk struct {
	// ID of the key
	ID *string `json:"kid"`

	// Identifiers the cryptographic algorithm family used with the key, such as "RSA" or "EC"
	Type string `json:"kty"`

	// Identifies the intended use of the key, such as signature "sig" or encryption "enc"
	Use string `json:"use"`

	// identifies the algorithm intended for use with the key
	Algorithm string `json:"alg"`

	Modulus string `json:"n"`

	Exponent string `json:"e"`
}

type rawJwks struct {
	Keys []jwk `json:"keys"`
}
