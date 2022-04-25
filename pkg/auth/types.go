package auth

// JWK is a slim version of a JSON Web Key.
type JWK struct {
	// ID of the key.
	ID *string `json:"kid"`

	// Type identifiers the cryptographic algorithm family used with the key, such as "RSA".
	Type string `json:"kty"`

	// Use identifies the intended use of the key, such as "sig" (signature) or "enc" (encryption).
	Use string `json:"use"`

	// Algorithm identifies the algorithm intended for use with the key.
	Algorithm string `json:"alg"`

	// Modulus of the RSA public key.
	Modulus string `json:"n"`

	// Exponent of the RSA public key.
	Exponent string `json:"e"`
}

// JWKSResponse is the wrapper for a list of keys.
type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}
