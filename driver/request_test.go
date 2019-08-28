package driver_test

import (
	"crypto/x509"
	"net"
	"time"

	"docker-secretprovider-pki/driver"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certificate request object", func() {
	var (
		certRequest driver.CertRequest
		labels      map[string]string
	)

	BeforeEach(func() {
		certRequest = driver.CertRequest{}
		labels = map[string]string{
			"pki.ca":        "test",
			"pki.cn":        "test certificate",
			"pki.usage":     "server-client",
			"pki.lifetime":  "24h",
			"pki.dns_names": "server.test,cluster.server.test,node.cluster.server.test",
			"pki.ip_addrs":  "127.0.0.1,172.16.0.1",
		}
	})

	Describe("Loading request from label values", func() {
		When("Labels are parsed", func() {
			BeforeEach(func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err).To(BeNil())
			})

			It("should extract CA name", func() {
				Expect(certRequest.CAName).To(Equal("test"))
			})

			It("should extract common name", func() {
				Expect(certRequest.CommonName).To(Equal("test certificate"))
			})

			It("should extract certficate usage", func() {
				Expect(certRequest.Usage).To(ConsistOf(x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth))
			})

			It("should extract certificate lifetime", func() {
				Expect(certRequest.Lifetime).To(Equal(24 * time.Hour))
			})

			It("should extract DNS names", func() {
				Expect(certRequest.DNSNames).To(ConsistOf("server.test", "cluster.server.test", "node.cluster.server.test"))
			})

			It("should extract IP addresses", func() {
				Expect(certRequest.IPAddrs).To(ConsistOf(net.ParseIP("127.0.0.1"), net.ParseIP("172.16.0.1")))
			})
		})
	})

	Describe("Handling missing required fields", func() {
		When("CA name is not specified", func() {
			BeforeEach(func() {
				delete(labels, "pki.ca")
			})

			It("should return a required field error", func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err.Error()).To(Equal("label 'pki.ca' is required to issue a certificate"))
			})
		})

		When("Certificate common name is not specified", func() {
			BeforeEach(func() {
				delete(labels, "pki.cn")
			})

			It("should return a required field error", func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err.Error()).To(Equal("label 'pki.cn' is required to issue a certificate"))
			})
		})

		When("Certificate usage is not specified", func() {
			BeforeEach(func() {
				delete(labels, "pki.usage")
			})

			It("should return a required field error", func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err.Error()).To(Equal("label 'pki.usage' is required to issue a certificate"))
			})
		})

		When("Duration is not specified", func() {
			BeforeEach(func() {
				delete(labels, "pki.lifetime")
			})

			It("should default to a predefined value", func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err).To(BeNil())
				Expect(certRequest.Lifetime).To(Equal(driver.DefaultCertLifetime))
			})
		})
	})

	Describe("Handling invalid label values", func() {
		When("Certificate usage specified is not allowed", func() {
			BeforeEach(func() {
				labels["pki.usage"] = "not allowed"
			})

			It("should return a disallowed usage error", func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err.Error()).To(Equal("disallowed usage requested for certificate: not allowed"))
			})
		})

		When("Lifetime is not specified as a duration", func() {
			BeforeEach(func() {
				labels["pki.lifetime"] = "not a duration"
			})

			It("should return a duration parse error", func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err.Error()).To(ContainSubstring("error parsing requested certificate lifetime"))
			})
		})

		When("IP addresses can not be parsed", func() {
			BeforeEach(func() {
				labels["pki.ip_addrs"] = "127.0.0.1,not an IP address"
			})

			It("should return an IP address parse error", func() {
				err := certRequest.FromSecretLabels(labels)
				Expect(err.Error()).To(Equal("error parsing IP address from: 'not an IP address'"))
			})
		})
	})
})
