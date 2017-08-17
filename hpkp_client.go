package gopkp

import (
	"log"
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
	log.Printf("%+v\n", resp.TLS)
	return resp, err
}
