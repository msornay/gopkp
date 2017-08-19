package gopkp

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransport(t *testing.T) {

	// XXX Using NewTLSServer will be simpler in Go 1.9 : https://tip.golang.org/pkg/net/http/httptest/#example_NewTLSServer

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
	}))
	defer ts.Close()

	cert, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	certpool := x509.NewCertPool()
	certpool.AddCert(cert)

	client := http.Client{
		Transport: &HPKPTransport{
			http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certpool,
				},
			},
		},
	}

	client.Get(ts.URL)
}
