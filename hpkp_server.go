// HTTP Public Key Pinning (RFC 7469)
//
// https://tools.ietf.org/html/rfc7469
package gopkp

import (
	"net/http"
)

type hpkp struct {
	pkpHeader   string
	pkproHeader string

	next http.Handler
}

// HPKP handler acts as a middleware to add HTTP Public Key Pinning headers to
// HTTP responses. It can be used with any framework supporting http.Handler
// (net/http, gorilla..)
//
// Example:
//    mux := http.NewServeMux()
//    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
//    	w.Write([]byte("I'm just a happy litle server\n"))
//    })
//    handler := HPKP()(mux)
//    err := http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", handler)
//    if err != nil {
//    	log.Fatal(err)
//    }
func HPKP() func(next http.Handler) http.Handler {
	fn := func(next http.Handler) http.Handler {
		return hpkp{next: next}
	}
	return fn
}

func (h hpkp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Do not include PKP header field in HTTP responses conveyed over
	// non-secure transport.
	if r.TLS != nil {
		w.Header().Set("HPKP", "hpkp")
	}

	h.next.ServeHTTP(w, r)
}
