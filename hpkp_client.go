package gopkp

import (
	"net/http"
)

type HPKPTransport struct {
	http.Transport
}

func (tr *HPKPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// XXX tls.Config offers VerifyPeerCertificates which looks promising to
	// follow the RFC which recommends to perform pin validation "as soon as
	// possible"
	resp, err := tr.Transport.RoundTrip(r)

	pin, pinRO := ParseHeader(resp.Header)
	if pin != nil {
	}
	if pinRO != nil {
	}

	return resp, err
}
