package driver

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// Certificate issuing base configuration.
var (
	MaxSerialNumber = new(big.Int).Lsh(big.NewInt(1), 128)

	DefaultCertLifetime = 24 * time.Hour
)

// CertRequest specifies the configuration for a new certificate.
type CertRequest struct {
	CAName     string             `label:"pki.ca"`
	CommonName string             `label:"pki.cn"`
	DNSNames   []string           `label:"pki.dns_names"`
	IPAddrs    []net.IP           `label:"pki.ip_addrs"`
	Usage      []x509.ExtKeyUsage `label:"pki.usage"`
	Lifetime   time.Duration      `label:"pki.lifetime"`
}

// FromSecretLabels populates the configuration from a map of secret's labels.
func (c *CertRequest) FromSecretLabels(labels map[string]string) error {
	if value, exists := labels["pki.ca"]; exists {
		c.CAName = value
	} else {
		return errors.New("label 'pki.ca' is required to issue a certificate")
	}

	if value, exists := labels["pki.cn"]; exists {
		c.CommonName = value
	} else {
		return errors.New("label 'pki.cn' is required to issue a certificate")
	}

	if value, exists := labels["pki.usage"]; exists {
		switch value {
		case "server":
			c.Usage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "client":
			c.Usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case "client-server", "server-client":
			c.Usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		default:
			return errors.New(fmt.Sprintf("disallowed usage requested for certificate: %s", value))
		}
	} else {
		return errors.New("label 'pki.usage' is required to issue a certificate")
	}

	if value, exists := labels["pki.dns_names"]; exists {
		c.DNSNames = strings.Split(value, ",")
	}

	if value, exists := labels["pki.ip_addrs"]; exists {
		for _, addr := range strings.Split(value, ",") {
			a := net.ParseIP(addr)
			if a == nil {
				return errors.New(fmt.Sprintf("error parsing IP address from: '%s'", addr))
			}

			c.IPAddrs = append(c.IPAddrs, a)
		}
	}

	if value, exists := labels["pki.lifetime"]; exists {
		d, err := time.ParseDuration(value)
		if err != nil {
			return errors.New(fmt.Sprintf("error parsing requested certificate lifetime: %s", err))
		}

		c.Lifetime = d
	} else {
		c.Lifetime = DefaultCertLifetime
	}

	return nil
}
