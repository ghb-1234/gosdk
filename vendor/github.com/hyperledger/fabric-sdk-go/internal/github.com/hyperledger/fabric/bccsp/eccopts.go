package bccsp

// ECDSAP256KeyGenOpts contains options for ECDSA key generation with curve P-256.
type ECCP256KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *ECCP256KeyGenOpts) Algorithm() string {
	return ECDSAP256
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *ECCP256KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}
