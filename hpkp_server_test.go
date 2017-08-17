package gopkp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("I'm just a happy litle server\n"))
	})
}

func TestPKPHeader(t *testing.T) {

	tests := []struct {
		url          string
		expectHeader bool
	}{
		{ // non-secure transport
			url:          "http://acme.org",
			expectHeader: false,
		}, {
			url:          "https://acme.org",
			expectHeader: true,
		},
	}

	h, _ := HPKP(
		&Pin{
			MaxAge: 60 * 24 * 3600,
			Fingerprints: []string{
				"Fo67lPV7KHjuFUIYTo79OkNnD+xL/2id9MJBtjz4goo=",
			},
		},
		nil,
	)
	handler := h(testHandler())

	for _, tc := range tests {
		req := httptest.NewRequest("GET", tc.url, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		resp := w.Result()

		hdr := resp.Header.Get("Public-Key-Pins")
		if !tc.expectHeader && hdr != "" {
			t.Errorf("Unexpected HPKP header")
			continue
		}
		if tc.expectHeader && hdr == "" {
			t.Errorf("Missing HPKP header")
			continue
		}
	}
}
