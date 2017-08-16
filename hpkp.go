package gopkp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// Compute the fingerprint used in Public-Key-Pins* HTTP headers for HPKP
func CertificatePin(cert *x509.Certificate) string {
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return `pin-sha256="` + base64.StdEncoding.EncodeToString(spkiHash[:]) + `"`
}
