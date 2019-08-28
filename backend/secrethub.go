package backend

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/pkg/errors"
	"github.com/secrethub/secrethub-go/pkg/secrethub"
)

// NewSecrethubBackend creates a Secrethub backend for the PKI plugin.
func NewSecrethubBackend() (*SecrethubBackend, error) {
	creds, err := ioutil.ReadFile("/secrethub/credential")
	if err != nil {
		return nil, errors.Wrap(err, "secrethub")
	}

	credential, err := secrethub.NewCredential(string(creds), "")
	if err != nil {
		return nil, errors.Wrap(err, "secrethub")
	}

	return &SecrethubBackend{
		client: secrethub.NewClient(credential, nil),
	}, nil
}

// SecrethubBackend is PKI backend which stores root CA on Secrethub.
type SecrethubBackend struct {
	client secrethub.Client
}

// Load fetches the CA bundle used for issuing new certificates from Secrethub.
func (b SecrethubBackend) Load(ca string) (*tls.Certificate, error) {
	c, err := b.client.Secrets().Versions().GetWithData(fmt.Sprintf("%s/cert.pem", ca))
	if err != nil {
		return nil, errors.Wrap(err, "error fetching CA certificate")
	}

	k, err := b.client.Secrets().Versions().GetWithData(fmt.Sprintf("%s/key.pem", ca))
	if err != nil {
		return nil, errors.Wrap(err, "error fetching CA private key")
	}

	cert := &tls.Certificate{}

	raw := c.Data
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		} else if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
		raw = rest
	}

	cert.PrivateKey, err = x509.ParsePKCS1PrivateKey(k.Data)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing private key")
	}

	return cert, nil
}
