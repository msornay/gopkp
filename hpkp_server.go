// HTTP Public Key Pinning (RFC 7469)
//
// https://tools.ietf.org/html/rfc7469
package gopkp

import (
	"errors"
	"net/http"
)

type hpkp struct {
	pins []PinHeader
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
//	  hpkp, _ := HPKP(
//	  	  &Pin{
//	  		  MaxAge: 60 * 24 * 3600,
//	  		  Fingerprints: []string{
//	  		  	"Fo67lPV7KHjuFUIYTo79OkNnD+xL/2id9MJBtjz4goo=",
//	  		  },
//	  	  },
//	  	  nil,
//	  )
//	  handler := hpkp(testHandler())
//    err := http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", handler)
//    if err != nil {
//    	log.Fatal(err)
//    }
func HPKP(pin, pinRO *Pin) (func(next http.Handler) http.Handler, error) {
	var pins []PinHeader
	if pin != nil {
		if pin.ReportOnly {
			return nil, errors.New("pin argument must not be a report-only pin")
		}
		pins = append(pins, pin.FormatHeader())
	}
	if pinRO != nil {
		if !pinRO.ReportOnly {
			return nil, errors.New("pinRO argument must be a report-only pin")
		}
		pins = append(pins, pinRO.FormatHeader())
	}
	fn := func(next http.Handler) http.Handler {
		return hpkp{pins: pins, next: next}
	}
	return fn, nil
}

func (h hpkp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Do not include PKP header field in HTTP responses conveyed over
	// non-secure transport.
	if r.TLS != nil {
		for _, p := range h.pins {
			w.Header().Set(p.Name, p.Value)
		}
	}
	h.next.ServeHTTP(w, r)
}
