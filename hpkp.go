package gopkp

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
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

type PinHeader struct {
	Name  string
	Value string
}

// Format HTTP header field name and value
func (pin *Pin) FormatHeader() PinHeader {
	h := PinHeader{}

	if pin.ReportOnly {
		h.Name = "Public-Key-Pins-Report-Only"
	} else {
		h.Name = "Public-Key-Pins"
	}

	var directives []string
	directives = append(directives, fmt.Sprintf("max-age=%d", pin.MaxAge))
	if pin.ReportURI != "" {
		directives = append(directives, fmt.Sprintf(`report-uri="%s"`, pin.ReportURI))
	}
	if pin.IncludeSubDomains {
		directives = append(directives, "includeSubDomains")
	}
	for _, fp := range pin.Fingerprints {
		directives = append(directives, fmt.Sprintf(`pin-sha256="%s"`, fp))
	}
	h.Value = strings.Join(directives, ";")

	return h
}

// Compute the Subject Public Key Info fingerprint used in Public-Key-Pins* HTTP headers for HPKP
func SPKIFingerprint(cert *x509.Certificate) string {
	// sha256 is the only allowed algorithm for now
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return `pin-sha256="` + base64.StdEncoding.EncodeToString(spkiHash[:]) + `"`
}
