package gopkp

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

var pemCert = `-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIJANtTvIhD6YA7MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODE2MTEzMTI1WhcNMTgwODE2MTEzMTI1WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAvEAjEIHLBgMyT1EQ20+oz2qCZmH8KYFsivkwVw7X27BEK8ef0NrqYdG9
pPwsl0X2eM596XZC6aaFEGMg5RhiP7AmgbUkHWVYqj0tYVL9vdBGWL+HpLNmODet
RdctZjXci1QzfMkFNgcgoN2cMIrqo2Nqfno8R78Sr0JGh59JxQm9TaTBcA89ATFZ
MV2cD0P3qIMh1W6kIlJZffncCkMCR6fwloXYe9PRHJDEO9Uao95kYtP8koVgMwKN
agpvcgv5dZwt+DBQQ/XXqTC5jQKRIhauXWNqJ0fLfQAVR2sxRha5PnWGkgI0tGBa
pifYUCsNE0KSe64s4K+VmJ7naiB9+wIDAQABo1MwUTAdBgNVHQ4EFgQUqWh89N0X
vr633YNebAqWcGo53CcwHwYDVR0jBBgwFoAUqWh89N0Xvr633YNebAqWcGo53Ccw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAhpc4YCgoEmPCrL9B
8UwB6rfQcKWwzJHuBo1cOEakY6PLq96kYPtQ6UtrjSRxBscilPNIOVSz0mAHG7aQ
9wAMSwN4sgUPlavbEy17oDmYudRzQFvY92Lpo9OMpc9fpL/T6nOwk6f1+QHc86zg
helrShsWtgbib4v1I3sk9z0rm2LW+Vf7+ETcqSKx+8G46neytH8Ncg1a9Y/eHHN5
AZc6AvYhDIpDZX93T/YcD40RfeNbhe7BJAR1IACb5pj7Isk40BK2RTNuk5TKnyLa
2i3r467jQffpfWSTJYxQM6CNkN4tBzlH2JFAuAUk9Be8DkzZtX1aV6QiXRMasSRg
BX2Uhw==
-----END CERTIFICATE-----
`

func TestSPKIFingerprint(t *testing.T) {
	pemBlock, _ := pem.Decode([]byte(pemCert))
	cert, _ := x509.ParseCertificate(pemBlock.Bytes)
	pin := SPKIFingerprint(cert)

	// Pin computed with openssl :
	//   openssl x509 -noout -in cert.pem -pubkey | \
	//   openssl asn1parse -noout -inform pem -out public.key
	//   openssl dgst -sha256 -binary public.key | openssl enc -base64
	if pin != `pin-sha256="Fo67lPV7KHjuFUIYTo79OkNnD+xL/2id9MJBtjz4goo="` {
		t.Error("Invalid pin: " + pin)
	}
}

func TestFormatHeader(t *testing.T) {
	tests := []struct {
		pin                *Pin
		expectedName       string
		expectedDirectives []string
	}{
		{
			pin:          &Pin{ReportOnly: false},
			expectedName: "Public-Key-Pins",
		}, {
			pin:          &Pin{ReportOnly: true},
			expectedName: "Public-Key-Pins-Report-Only",
		}, {
			pin:                &Pin{MaxAge: 2592000},
			expectedDirectives: []string{"max-age=2592000"},
		}, {
			pin:                &Pin{ReportURI: "https://acme.org/pkp-report"},
			expectedDirectives: []string{`report-uri="https://acme.org/pkp-report"`},
		}, {
			pin:                &Pin{IncludeSubDomains: true},
			expectedDirectives: []string{"includeSubDomains"},
		}, {
			pin:                &Pin{Fingerprints: []string{"Fo67lPV7KHjuFUIYTo79OkNnD+xL/2id9MJBtjz4goo="}},
			expectedDirectives: []string{`pin-sha256="Fo67lPV7KHjuFUIYTo79OkNnD+xL/2id9MJBtjz4goo="`},
		}, {
			pin: &Pin{
				ReportOnly:        false,
				MaxAge:            2592000,
				ReportURI:         "https://acme.org/pkp-report",
				IncludeSubDomains: true,
				Fingerprints: []string{
					"Fo67lPV7KHjuFUIYTo79OkNnD+xL/2id9MJBtjz4goo=",
					"dzRWTVwHfvhJ2caIeEtXi6TE2ZZKWLI8gUksgADUcZs=",
				},
			},
			expectedName: "Public-Key-Pins",
			expectedDirectives: []string{
				"max-age=2592000",
				`report-uri="https://acme.org/pkp-report"`,
				"includeSubDomains",
				`pin-sha256="Fo67lPV7KHjuFUIYTo79OkNnD+xL/2id9MJBtjz4goo="`,
				`pin-sha256="dzRWTVwHfvhJ2caIeEtXi6TE2ZZKWLI8gUksgADUcZs="`,
			},
		},
	}

	for _, tc := range tests {
		h := tc.pin.FormatHeader()
		if tc.expectedName != "" && h.Name != tc.expectedName {
			t.Errorf("Invalid header field name got %s expected %s", h.Name, tc.expectedName)
		}
		directives := make(map[string]bool) // Set of directives
		for _, d := range strings.Split(h.Value, ";") {
			directives[d] = true
		}
		for _, ed := range tc.expectedDirectives {
			if _, ok := directives[ed]; !ok {
				t.Errorf("Expected directive %s is missing", ed)
			}
		}
	}

}
