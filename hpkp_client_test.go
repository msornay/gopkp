package gopkp

import (
	"fmt"
	"net/http"
	"testing"
)

func TestTransport(t *testing.T) {
	client := &http.Client{
		Transport: &HPKPTransport{},
	}
	resp, _ := client.Get("https://www.google.fr")
	fmt.Printf("%+v\n", resp)
}
