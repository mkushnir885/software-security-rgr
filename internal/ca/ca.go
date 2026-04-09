package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type CA struct {
	privKey *rsa.PrivateKey
	cert    *x509.Certificate
}

func New() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nodeCA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{privKey: key, cert: cert}, nil
}

func (ca *CA) CertDER() []byte {
	return ca.cert.Raw
}

func (ca *CA) IssueNodeCert(pub *rsa.PublicKey, nodeID int) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(nodeID + 1)),
		Subject:      pkix.Name{CommonName: fmt.Sprintf("node%d", nodeID)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.privKey)
}

// Verify checks that certDER was signed by this CA.
func (ca *CA) Verify(certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
