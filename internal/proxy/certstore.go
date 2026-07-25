package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CertStore manages the CA certificate used for MITM interception.
type CertStore struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	tlsCert tls.Certificate
	dir    string
}

// NewCertStore loads or generates a CA certificate in the given directory.
func NewCertStore(dir string) (*CertStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}

	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	cs := &CertStore{dir: dir}

	// Try loading existing CA
	if _, err := os.Stat(certPath); err == nil {
		if err := cs.load(certPath, keyPath); err == nil {
			return cs, nil
		}
	}

	// Generate new CA
	if err := cs.generate(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	return cs, nil
}

// TLSCert returns the CA TLS certificate for use with goproxy.
func (cs *CertStore) TLSCert() tls.Certificate {
	return cs.tlsCert
}

// CACert returns the parsed CA certificate.
func (cs *CertStore) CACert() *x509.Certificate {
	return cs.caCert
}

// CAKey returns the CA private key.
func (cs *CertStore) CAKey() *ecdsa.PrivateKey {
	return cs.caKey
}

func (cs *CertStore) load(certPath, keyPath string) error {
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}

	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

	caKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA key is not ECDSA")
	}

	cs.caCert = caCert
	cs.caKey = caKey
	cs.tlsCert = tlsCert
	return nil
}

func (cs *CertStore) generate(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "AOBTD Proxy CA",
			Organization: []string{"AOBTD"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// Write cert PEM
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Write key PEM
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Parse back for in-memory use
	caCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	cs.caCert = caCert
	cs.caKey = key
	cs.tlsCert = tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return nil
}
