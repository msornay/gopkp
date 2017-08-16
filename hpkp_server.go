// HTTP Public Key Pinning (RFC 7469)
//
// https://tools.ietf.org/html/rfc7469
package gopkp

import (
	"log"
	"net/http"
)

// HPKP handler acts as a middleware to add HTTP Public Key Pinning headers to
// HTTP responses. It can be used with any framework supporting http.Handler
// (net/http, gorilla..)
func HPKP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// Do not include PKP header field in HTTP responses conveyed over
		// non-secure transport.
		if r.TLS != nil {
			w.Header().Set("HPKP", "hpkp")
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("I'm just a happy litle server\n"))
	})
	handler := HPKP(mux)
	// err := http.ListenAndServe(":8081", handler)
	err := http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", handler)
	if err != nil {
		log.Fatal(err)
	}
}
