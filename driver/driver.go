package driver

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// PrivateKeyLength specifies the length for RSA private keys generated.
const PrivateKeyLength int = 2048

// CABackend declares interface for loading root CAs.
type CABackend interface {
	Load(name string) (*tls.Certificate, error)
}

// NewDriver creates a new PKI driver.
func NewDriver(ca CABackend, client *client.Client) (*Driver, error) {
	return &Driver{
		ca:     ca,
		client: client,
	}, nil
}

// Driver is the TLS certificate issuer.
type Driver struct {
	ca     CABackend
	client *client.Client
}

// Get retrieves a PKI certificate bundle from the issuing backend
// and creates a certificate response.
func (d Driver) Get(request secrets.Request) secrets.Response {
	// Handle them panics.
	defer func() {
		if r := recover(); r != nil {
			zap.S().Errorf("pki: error issuing certificate: %s", r)
		}
	}()

	zap.S().Debugf("pki: got request for certificate: %#v", request)

	// For now the secrets.Request.SecretLabels value does not get populated.
	// To work around this, the secret's labels are inspected on the daemon.
	meta, _, err := d.client.SecretInspectWithRaw(context.Background(), request.SecretName)
	if err != nil {
		return secrets.Response{
			Err: fmt.Sprintf("pki: error inspecting secret: %s", err.Error()),
		}
	}

	certRequest := CertRequest{}
	if err := certRequest.FromSecretLabels(meta.Spec.Labels); err != nil {
		return secrets.Response{
			Err: fmt.Sprintf("pki: error parsing configuration from secret labels: %s", err.Error()),
		}
	}

	bundle, err := d.IssueCertificate(certRequest)
	if err != nil {
		return secrets.Response{
			Err: fmt.Sprintf("pki: error issuing certificate: %s", err.Error()),
		}
	}

	return secrets.Response{
		Value:      bundle,
		DoNotReuse: true,
	}
}

// IssueCertificate creates a new TLS certificate with specified config.
func (d Driver) IssueCertificate(config CertRequest) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, MaxSerialNumber)
	if err != nil {
		return nil, errors.Wrap(err, "error generating certificate serial number")
	}

	ca, err := d.ca.Load(config.CAName)
	if err != nil {
		return nil, errors.Wrap(err, "error loading CA bundle")
	}

	rootCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "error parsing CA certificate")
	}

	now := time.Now()

	cert := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			OrganizationalUnit: rootCert.Subject.OrganizationalUnit,
			Organization:       rootCert.Subject.Organization,
			Country:            rootCert.Subject.Country,
			Province:           rootCert.Subject.Province,
			Locality:           rootCert.Subject.Locality,
			StreetAddress:      rootCert.Subject.StreetAddress,
			PostalCode:         rootCert.Subject.PostalCode,
		},
		NotBefore:   now,
		NotAfter:    now.Add(config.Lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: config.Usage,
	}

	for _, name := range config.DNSNames {
		cert.DNSNames = append(cert.DNSNames, name)
	}

	for _, addr := range config.IPAddrs {
		cert.IPAddresses = append(cert.IPAddresses, addr)
	}

	key, err := rsa.GenerateKey(rand.Reader, PrivateKeyLength)
	if err != nil {
		return nil, errors.Wrap(err, "error generating private key")
	}

	signed, err := x509.CreateCertificate(rand.Reader, &cert, rootCert, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "error signing certificate")
	}

	bundle := &bytes.Buffer{}

	if err := pem.Encode(bundle, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, err
	}

	if err := pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: signed}); err != nil {
		return nil, err
	}

	for _, cert := range ca.Certificate {
		if err := pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return nil, err
		}
	}

	return bundle.Bytes(), nil
}
