// Package collect is the pull-based gateway transport (ADR 0005). The protected
// Core (Harbor) PULLS pending enrollment candidates from each registered gateway
// over a leaf-pinned mTLS channel, re-verifies + issues them, and pushes the
// results back — so the internet-facing gateway initiates nothing, holds no mesh
// identity, and needs no trust (Core re-verifies every candidate). This file is
// the mTLS identity layer: self-signed certs pinned by leaf-SHA-256 (no CA),
// matching the ADR's "Harbor pins the gateway's cert; the gateway accepts only
// Harbor's client cert" model.
package collect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ServerTLS is the gateway's collect-listener TLS config: present serverCert and
// require a client cert that matches the pinned Harbor client cert (clientPin =
// SHA-256 of Harbor's client-cert DER). Default chain verification is replaced by
// leaf pinning.
func ServerTLS(serverCert tls.Certificate, clientPin [32]byte) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{serverCert},
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: pinVerifier(clientPin),
	}
}

// ClientTLS is Harbor's collect-dialer TLS config: present clientCert and require
// the gateway's server cert to match its pinned leaf (serverPin = SHA-256 of the
// gateway's server-cert DER, from the registry). InsecureSkipVerify disables the
// default CA-chain check precisely because we pin the self-signed leaf instead.
func ClientTLS(clientCert tls.Certificate, serverPin [32]byte) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{clientCert},
		InsecureSkipVerify:    true, //nolint:gosec // leaf-pinned mTLS: chain verification is intentionally replaced by VerifyPeerCertificate
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: pinVerifier(serverPin),
	}
}

// pinVerifier checks the peer's leaf cert DER against a SHA-256 pin in constant time.
func pinVerifier(pin [32]byte) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("collect: peer presented no certificate")
		}
		got := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(got[:], pin[:]) != 1 {
			return errors.New("collect: peer certificate pin mismatch")
		}
		return nil
	}
}

// PinFromCertPEM computes the leaf pin (SHA-256 of the cert DER) from a PEM cert —
// what goes in the registry / config as the pinned identity.
func PinFromCertPEM(pemBytes []byte) ([32]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return [32]byte{}, errors.New("collect: not a CERTIFICATE PEM")
	}
	return sha256.Sum256(block.Bytes), nil
}

// GenerateSelfSigned mints a self-signed P256 cert + PKCS#8 key (PEM) usable as
// either a collect server or client identity (both EKUs set). The peer pins it by
// leaf SHA-256, so there is no CA and no chain to validate.
func GenerateSelfSigned(commonName string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("collect: create cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
