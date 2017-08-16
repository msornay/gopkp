package gopkp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// Public key pin
type Pin struct {
	// Indicates if the pinning must be enforced
	ReportOnly bool

	// Number of seconds during which the host is pinned
	MaxAge int

	// URI where pin validation failures should be reported
	ReportURI string

	// Indicates if the pinning policy applies to subdomains
	IncludeSubDomains bool

	// SPKI fingerprints
	Fingerprints []string
}

// Compute the Subject Public Key Info fingerprint used in Public-Key-Pins* HTTP headers for HPKP
func SPKIFingerprint(cert *x509.Certificate) string {
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return `pin-sha256="` + base64.StdEncoding.EncodeToString(spkiHash[:]) + `"`
}
