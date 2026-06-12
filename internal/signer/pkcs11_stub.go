//go:build !pkcs11

package signer

import "fmt"

// PKCS11Config is declared in the default build so callers compile; the backend
// itself requires the `pkcs11` build tag (and cgo).
type PKCS11Config struct {
	ModulePath string
	TokenLabel string
	Pin        string
	KeyLabel   string
}

// NewPKCS11Backend is unavailable unless built with -tags pkcs11.
func NewPKCS11Backend(_ PKCS11Config) (Backend, error) {
	return nil, fmt.Errorf("signer: built without pkcs11 support; rebuild with -tags pkcs11")
}
