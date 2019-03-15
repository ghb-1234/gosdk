package bccsp

/*
* 以下为国密硬件加密参素
 */
type SM2KeyGenOpts struct {
	Temporary bool
}

func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyGenOpts struct {
	Temporary bool
}

func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PrivateKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM2PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM4ImportKeyOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}
