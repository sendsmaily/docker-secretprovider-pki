package cert

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/pkg/errors"
)

// Bundle is the normalized certificate bundle.
type Bundle struct {
	Certificate *tls.Certificate
	CAPool      *x509.CertPool
}

// LoadBundle loads a bundle from a file on disk.
func LoadBundle(path string) (*Bundle, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	bundle := &Bundle{
		Certificate: &tls.Certificate{},
		CAPool:      x509.NewCertPool(),
	}

	for {
		block, rest := pem.Decode(raw)

		if block == nil {
			break
		} else if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "error parsing certificate")
			}

			if cert.IsCA {
				bundle.CAPool.AddCert(cert)
			} else {
				bundle.Certificate.Certificate = append(bundle.Certificate.Certificate, cert.Raw)
			}

		} else if block.Type == "RSA PRIVATE KEY" {
			bundle.Certificate.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		} else if block.Type == "PRIVATE KEY" {
			bundle.Certificate.PrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		}

		raw = rest
	}

	return bundle, nil
}
