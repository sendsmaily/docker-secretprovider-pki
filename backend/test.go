package backend

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

var testingCert = []byte(`-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIUQLjy+87FJI8Rnk43XPmhzylOI/QwDQYJKoZIhvcNAQEL
BQAwgYMxCzAJBgNVBAYTAkVFMREwDwYDVQQIEwhIYXJqdW1hYTEQMA4GA1UEBxMH
VGFsbGlubjEYMBYGA1UEChMPU2VuZHNtYWlseSwgTExDMQ8wDQYDVQQLEwZEZXZP
cHMxJDAiBgNVBAMTG1BLSSBQcm92aWRlciBUZXN0IEF1dGhvcml0eTAeFw0xOTEw
MTExMDA1MDBaFw0yOTEwMDgxMDA1MDBaMIGLMQswCQYDVQQGEwJFRTERMA8GA1UE
CBMISGFyanVtYWExEDAOBgNVBAcTB1RhbGxpbm4xGDAWBgNVBAoTD1NlbmRzbWFp
bHksIExMQzEPMA0GA1UECxMGRGV2T3BzMSwwKgYDVQQDEyNQS0kgUHJvdmlkZXIg
SW50ZXJtZWRpYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBALD3IgX/vXHSJtyjywdV23ASpKaZDGtZ8/64VLhxteGFP7oIy7jGwpX8
vfDs5pHkcFg9AaEzZDSrRyevc9/vjNcC2LFzHSWiVjbkX9sjFUodgKUYtYDDILy3
pFM5oVsr9oSqrk5I8bJoXswh9RRzg1l1MoDZ1vVBD1QKyR9ie+eGndllEJKBWdyQ
5z2hNC64eMyve0RSNtKUe0JdeQYWOq9QLPrdaxMYLyuKg78r+FD/QoA9e5Gh4z4r
9kvaNK1rCCCbtttb1L3qWGZjM8fd5bN2ZLFMnAndFtHOqeDUJzkOmHwv/DDC/K5x
bUfLME94cRopSeU49T51eO5bc4rXmCcCAwEAAaNmMGQwDgYDVR0PAQH/BAQDAgGG
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFCpyKAfkIQ9QJhSH9AhtSmUC
d9/3MB8GA1UdIwQYMBaAFN1cGYQCHrd4XsoxF9sYB5lcDoFEMA0GCSqGSIb3DQEB
CwUAA4IBAQBPnf+AwHgXMqDLbZYs8068mgyHuoxm15FzQVjc4opNBkb9dnrsSdKV
MWk83wActR4E6TmDytqe9PFitqG5D8xgpczH9ouYjIvCOhqfOAnJJnzrMpmgfzO0
eITn+qpbXdCpqs8zwgwFhP0WpsNiC/TH0NfvX0YR9httPi1UttVsrdF8T3MewLNY
2U25gQZJbXV+UzttEy/kGnV7/wFzG76uA6aSjr6FkOYTptJhE49/SNXADyCNs7bl
+q5e0uyVTt35EyOjnucR1vCkKqjo5oVNVsH7OXmJT+KkgHqGtEQOBdXIhvgpUph3
S+08Hkn4jKpFv4niU2zEVMe+xazUm8jC
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID2DCCAsCgAwIBAgIUBA9Y/OGy5NOWfcA9XnNac7eekvMwDQYJKoZIhvcNAQEL
BQAwgYMxCzAJBgNVBAYTAkVFMREwDwYDVQQIEwhIYXJqdW1hYTEQMA4GA1UEBxMH
VGFsbGlubjEYMBYGA1UEChMPU2VuZHNtYWlseSwgTExDMQ8wDQYDVQQLEwZEZXZP
cHMxJDAiBgNVBAMTG1BLSSBQcm92aWRlciBUZXN0IEF1dGhvcml0eTAeFw0xOTEw
MTExMDA0MDBaFw0zNDEwMDcxMDA0MDBaMIGDMQswCQYDVQQGEwJFRTERMA8GA1UE
CBMISGFyanVtYWExEDAOBgNVBAcTB1RhbGxpbm4xGDAWBgNVBAoTD1NlbmRzbWFp
bHksIExMQzEPMA0GA1UECxMGRGV2T3BzMSQwIgYDVQQDExtQS0kgUHJvdmlkZXIg
VGVzdCBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/
VJi1/+k+B0+6cS8GqC4UVUzB+qjmpmLgWT4SGNmevAlAUA++lFQhvS9GdTzxE9lt
BB3zEdlpzOyvXUdwU2tgTw8QDCcdtmlYVdS9FjYCaF8gn25c0rbd5uqqPHqJJycP
QbChmR+W8zZT8afrdGGyLZC1lxs8JgSOnfhdnFU1LZUZf3PRuAsWW3Z4ysBagm1u
j4bD13HT1KJBanh27b7bmJI5LcjHR0uI7WNk1d5a6lOMHOTm+e5Fps7vU/sHJUwf
6bpmEWuT1hWA248QUDgMhx9IkgtkD85YxpFWyK3v+9UAfhGLUrYAXwDjfXIooIeP
2gtPKm0fI9eCkWmgdi6jAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdDgQWBBTdXBmEAh63eF7KMRfbGAeZXA6BRDANBgkqhkiG
9w0BAQsFAAOCAQEAIO9f9SxI44/96brJgU4taWWZTyN4SrBHtCGP+flRolHf74IR
Gq9tW8oTWGqkV61Zfc5VXlUkh75eqsgUfe9XWkqZvbuM4idg55+8YTgQgYgZg2+T
iIXYCg/NT6F+hq7+cm5UwNFZcHHAwa2chqCVEXcYB3ioWQ8TZMc4VKApf7/c0al8
TgZzX1nhb2jFhZP/UfsfFQSAzydaplvEvLye+6DNu0b89W6fok4lgjTsnxNDoi9i
vPNKSBR/D5I1XAoVzlPZFe5gAnJb09zhfQoK6NNPsSgkVlTeBzkQX2wZh5hPq78l
MkIozXyZfT0YlCIwRnXJRkt/wNGuQYN6dmFQ6g==
-----END CERTIFICATE-----
`)

var testingKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsPciBf+9cdIm3KPLB1XbcBKkppkMa1nz/rhUuHG14YU/ugjL
uMbClfy98OzmkeRwWD0BoTNkNKtHJ69z3++M1wLYsXMdJaJWNuRf2yMVSh2ApRi1
gMMgvLekUzmhWyv2hKquTkjxsmhezCH1FHODWXUygNnW9UEPVArJH2J754ad2WUQ
koFZ3JDnPaE0Lrh4zK97RFI20pR7Ql15BhY6r1As+t1rExgvK4qDvyv4UP9CgD17
kaHjPiv2S9o0rWsIIJu221vUvepYZmMzx93ls3ZksUycCd0W0c6p4NQnOQ6YfC/8
MML8rnFtR8swT3hxGilJ5Tj1PnV47ltziteYJwIDAQABAoIBAFqumRm33i0oQk/I
Ay8EGQmKFCNmxA1yr+x0Kr3FTy18aZZ8EWDjQS04sWB3FQPnqoYc5Ovk+NFgf3rf
lqJHD8XSKJZt5Z62XDWOu2wAw1USXyy6x69uziTGegdHvd6JXa7IA8AL8wa4IvO5
5uuO8dzyiGmst1FAAInRaRSTE+kkoTJSsE+81/S1nxS+P4xf81TG0AhWE/ArRCoq
HpemQLgFEaXSN+ArFA+bMFXxM3Z1tOdQLCE5NTcURZgPMZkRAn/7h49PMYmPGsG/
H6cQWZCz9ojOenLv1CFLfKuSqJvbhePRyClMATHklR/hPtKmCFofc9X2DJ0NlTJD
czcRxskCgYEA1u0ZKEvrJGWgB6CjlYoktSi3bUvrelHaP61XiPl5EZKPQWQx1TUG
LROr+fZsHZ1OcYbwQ9PCAlFN+GXITc0QXWMcoL45u9RrQyn2tqss1pybAM131YnI
zBiBwIcOMq1/nTbrM2icEMczgEWhchduL2Ra0oO4TKyI9BfMa4udoDMCgYEA0sjd
uoj5M8SjA8YFtJOsZWSbNYRNuyq9UzmfVdMN9iawF2flqqjol1gwgAiSaTzRXQOZ
fyxEUI2J/WiHqcEDA7UK2xdD86ktVR/uJrpXRYYnrax/E6YIFkzYPFFitCKix7ba
O0MT5grELiZ314sCRJNA3RMrpLovxCmqk6b55D0CgYAZKqY5e7pLBsNYYU0GY6is
tdnUqIEoT5FYx3lqhpvQnPK9W3giWRUiDh2jJWG/jf3zeTOFHbSoBNE2duSfh5WU
+dgOUnf8MIFm2fETrrOPZcMYsvaHQJ0MmQoIe0gEUyCQTi/4UxWDOXAkYwLmkyvJ
zNx9rgLUp5dZzbeYGD8a1QKBgGib8Zba1bqAc1qzEy/MPjnP1UuZDq6+Blngdhg0
92/bQXdMQ+oPi+dYiDFyj58U5N7ho3M+9+R2ai5Oi02PEbzsQ6f6AupRYsMlZp7n
ydoiO1zxB9wrgUX3+zTsOy0lJ14wfFv+7Ug0vaodw0pAne6EmiNdmUJWeNBE0XgX
3VsNAoGAfMw29/Wa1pgzXZL6lvUTpHIjcZr0OujOCYWAt69wPa26ZcAusDNr8QCv
wxWxMbCyOnHfL5HYqi4AFCmXkN4KcF+aOh/rJLHfYyRStrR4GOrBSjL4oTbb0mgs
NC/3eW/RhqeK872hSJW1kWQpXrvzJkErLAe0VHi8MZhdSxk47Ng=
-----END RSA PRIVATE KEY-----
`)

// NewTestBackend creates a new test CA backend.
func NewTestBackend() (*TestBackend, error) {
	return &TestBackend{}, nil
}

// TestBackend is a PKI backend used for testing.
type TestBackend struct{}

// Load returns testing root CA certificate.
func (b TestBackend) Load(ca string) (cert *tls.Certificate, err error) {
	cert = &tls.Certificate{}

	raw := testingCert
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		} else if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
		raw = rest
	}

	block, _ := pem.Decode(testingKey)
	if block == nil {
		return nil, errors.New("got empty decode result for private key")
	}

	cert.PrivateKey, err = b.parsePrivateKey(block)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing private key")
	}

	return cert, nil
}

func (b TestBackend) parsePrivateKey(block *pem.Block) (key interface{}, err error) {
	if block.Type == "PRIVATE KEY" {
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else {
		err = errors.Errorf("unknown key type: %s", block.Type)
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}
