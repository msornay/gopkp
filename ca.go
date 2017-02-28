// Generate self-signed certificates suitables for a certificate authority

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

func generatePriv() (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}


func certTemplate(name string) (*x509.Certificate, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{name, },
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
	}, nil
}

func createCACert(priv *ecdsa.PrivateKey) ([]byte, error) {
	template, err := certTemplate("XXX")
	if err != nil {
		return nil, err
	}
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return derBytes, nil
}


// func issueCert(caCert []byte, caPriv *ecdsa.PrivateKey, string host) {

// }


func main() {
	priv, err := generatePriv()
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return
	}

	derBytes, err := createCACert(priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
		return
	}

	certOut, err := os.Create("cacert.pem")
	if err != nil {
		log.Fatalf("failed to open cacert.pem for writing: %s", err)
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()
	log.Print("written cacert.pem\n")

	keyOut, err := os.OpenFile("cakey.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Print("failed to open cakey.pem for writing:", err)
		return
	}

	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
		os.Exit(2)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	keyOut.Close()
	log.Print("written cakey.pem\n")
}
