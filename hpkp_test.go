package gopkp

import (
	"crypto/x509"
	"encoding/pem"
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
