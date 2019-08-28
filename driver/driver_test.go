package driver_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"

	"docker-secretprovider-pki/backend"
	"docker-secretprovider-pki/driver"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PKI Docker secret provider driver", func() {
	var (
		drv *driver.Driver
		err error
	)

	BeforeEach(func() {
		drv, err = driver.NewDriver(&backend.TestBackend{}, nil)
		Expect(err).To(BeNil())
	})

	Describe("Issuing certificates", func() {
		When("Certificate request configuration is valid", func() {
			var bundle []byte

			BeforeEach(func() {
				bundle, err = drv.IssueCertificate(driver.CertRequest{
					CAName:     "test",
					CommonName: "Test Certificate",
					DNSNames:   []string{"smaily.testing", "local.smaily.testing"},
					IPAddrs:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.16.0.1")},
					Usage:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				})
				Expect(err).To(BeNil())
			})

			It("should issue a TLS certificate bundle", func() {
				cert, err := parsePKIBundle(bundle)
				Expect(err).To(BeNil())

				Expect(len(cert.Certificate)).To(Equal(2))
				Expect(cert.PrivateKey).ToNot(BeNil())
			})

			It("should sign the certificate in the bundle with root certificate key", func() {
				cert, err := parsePKIBundle(bundle)
				Expect(err).To(BeNil())

				signedCert, err := x509.ParseCertificate(cert.Certificate[0])
				Expect(err).To(BeNil())

				rootCert, err := x509.ParseCertificate(cert.Certificate[1])
				Expect(err).To(BeNil())

				// Sanity check to validate the root cert is in the `rootCert` variable,
				// and not the other way around. This works on the assumption that root
				// certificate is self signed (which it is with the testing backend).
				Expect(rootCert.AuthorityKeyId).To(Equal(rootCert.SubjectKeyId))

				// As per RFC 3280, section 4.2.1.1 and 4.2.1.2:
				// https://tools.ietf.org/html/rfc3280#section-4.2.1.1
				Expect(signedCert.AuthorityKeyId).To(Equal(rootCert.SubjectKeyId))
			})
		})
	})
})

func parsePKIBundle(bundle []byte) (cert *tls.Certificate, err error) {
	raw := make([]byte, len(bundle))
	copy(raw, bundle)

	cert = &tls.Certificate{}

	for {
		block, rest := pem.Decode(raw)

		if block == nil {
			break
		} else if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else if block.Type == "RSA PRIVATE KEY" {
			cert.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		} else if block.Type == "PRIVATE KEY" {
			cert.PrivateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
		}

		raw = rest
	}

	return cert, nil
}
