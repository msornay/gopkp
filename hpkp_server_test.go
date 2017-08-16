package gopkp

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func ExampleHPKP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("I'm just a happy litle server\n"))
	})
	handler := HPKP(mux)
	err := http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", handler)
	if err != nil {
		log.Fatal(err)
	}
}

func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("I'm just a happy litle server\n"))
	})
}

func TestPKPHeader(t *testing.T) {

	tests := []struct {
		url               string
		expectedPKPHeader string
	}{
		{ // non-secure transport
			url:               "http://acme.org",
			expectedPKPHeader: "",
		}, {
			url:               "https://acme.org",
			expectedPKPHeader: "hpkp",
		},
	}

	handler := HPKP(testHandler())

	for _, tc := range tests {
		req := httptest.NewRequest("GET", tc.url, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		resp := w.Result()

		pkpHeader := resp.Header.Get("hpkp")
		if pkpHeader != tc.expectedPKPHeader {
			t.Errorf("Invalid PKP header got %s expected %s", pkpHeader, tc.expectedPKPHeader)
		}

	}

}
