package backend

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

var testingCert = []byte(`-----BEGIN CERTIFICATE-----
MIIEJzCCAw+gAwIBAgIUG579BxCtbC0pf7fiKupsvH9Xz9swDQYJKoZIhvcNAQEL
BQAwgaIxCzAJBgNVBAYTAkVFMREwDwYDVQQIDAhIYXJqdW1hYTEQMA4GA1UEBwwH
VGFsbGlubjEXMBUGA1UECgwOU2VuZHNtYWlseSBMTEMxDzANBgNVBAsMBkRldk9w
czEiMCAGA1UEAwwZUEtJIHByb3ZpZGVyIHRlc3Rpbmcgcm9vdDEgMB4GCSqGSIb3
DQEJARYRZGV2b3BzQHNtYWlseS5jb20wHhcNMTkwODI3MDYyMTM2WhcNMjkwODI0
MDYyMTM2WjCBojELMAkGA1UEBhMCRUUxETAPBgNVBAgMCEhhcmp1bWFhMRAwDgYD
VQQHDAdUYWxsaW5uMRcwFQYDVQQKDA5TZW5kc21haWx5IExMQzEPMA0GA1UECwwG
RGV2T3BzMSIwIAYDVQQDDBlQS0kgcHJvdmlkZXIgdGVzdGluZyByb290MSAwHgYJ
KoZIhvcNAQkBFhFkZXZvcHNAc21haWx5LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOax1uVaNP6vYzERF/yy70ePs2qsyzwRZd2WWde3RXlKyA4H
vQfMMW3qKf9wRBfLlM7nUuYZjYg7TwGeZ99PSPaLVNktPmngWAi7q4aSru+l6tvq
LE46TD1s5otyhDeMhUx01w1Mwt17nJs267ROUQ2G/bsMKWbpxjTd22s0KpbuFXXT
DwdUa4PdW1gw5M/d9yYSUeEeFUKI2p9BpozQBF5k5IXXhp2eZUnJRziI2lOqQtcn
RIQJ8nYnGMflbeGlawhReHWyNSZGZZtgy+z8FFMVgGLD4FGN9Sls0iEE0G6uEVOx
Q0FdlmBgTVRsxU7QS6U6iGlgE56HuaiL8BYCUhUCAwEAAaNTMFEwHQYDVR0OBBYE
FCXrOddgfKQ8RZBriX4P7zd9Ez3iMB8GA1UdIwQYMBaAFCXrOddgfKQ8RZBriX4P
7zd9Ez3iMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAMvcZV2f
AIx9g08B4NdyV4T4LxVICIGpvqlq0WLO4eprLZmMq+Vik1TJqIsuaeTOM5FXj4ZF
eAS2+USGFOaWIJbWuwkiwvdmJiGIS8JhKicOutgQ+XUbPO/w3hORxMJlVr7TBVdf
GLJRURfPww4J8oIP9d9ZswEzZg0wntFtV6L8JrcQKEENsDam7wS6TfrcOZ0msaMW
xsNU9wnqEf8sHfHdJ5/DoZxjErQp69TDN+pD+mMf5e4/dnY67AOZXOA2j63GUNXC
Ke/ouNT5TyiYIndJNNOEN46RAML21aTAdixK+l2VCPz0C04eFJ3qZ4YBREg1Gc8a
qBKL27koGZ9HZ1w=
-----END CERTIFICATE-----
`)

var testingKey = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDmsdblWjT+r2Mx
ERf8su9Hj7NqrMs8EWXdllnXt0V5SsgOB70HzDFt6in/cEQXy5TO51LmGY2IO08B
nmffT0j2i1TZLT5p4FgIu6uGkq7vperb6ixOOkw9bOaLcoQ3jIVMdNcNTMLde5yb
Nuu0TlENhv27DClm6cY03dtrNCqW7hV10w8HVGuD3VtYMOTP3fcmElHhHhVCiNqf
QaaM0AReZOSF14adnmVJyUc4iNpTqkLXJ0SECfJ2JxjH5W3hpWsIUXh1sjUmRmWb
YMvs/BRTFYBiw+BRjfUpbNIhBNBurhFTsUNBXZZgYE1UbMVO0EulOohpYBOeh7mo
i/AWAlIVAgMBAAECggEAIZXAaFFyp6VW9ny7lkFijnOANkaDq/IId3L9D2eSCK93
YnuD7I+wnoTZqmNotmIf/uM0cWVE8pFX1i9+hccgIyxzpM5uaLGNf2/677OJHkB0
aaG044qfMM4a3jBEyWV+vnvAFyKWt/HYAczEEdLY//QoGkQR/vaHsYie+gN1M9Wc
qUve5SOmRc9Q8KYyob6Q8YWsvhDzK3ZM2RGNOkXTXQEqTofA7MpXNjukto9GyrXl
9QVlco29OIEPxp7bor9UQ7mRsb4dtufhPnZzyqhU9H3PDghLiLN/P6BZq0EvDEjs
nwOBICaXPpaKK/zusZqOFZbop72hTvgefpxNyVufgQKBgQD4h+u9rWrOOXBJ3vib
Cj4Ls8yqMERcutGQgmn1qu7KsY8e4Ijh4ja2y4LKRe/WsTARWduKXNmhgaYY0TRI
fWc5g6v6Y7ofu9aw5vgIZmXMwOZS3D+1VOCQ71N5aYig5oyUyDsCYip9GkVoMtvk
v+2ILcqCejxH7s722bamrP3MtQKBgQDtoLHkF8IUmTAPWtDmCmOA3nebuxu/OhtB
b6kvE2+vEVvXTx9hgR6lYci63pTmSAJz9BHWwcKpYqqwSEvuNaoOVyvha0vkqYc7
r2ZecsFT6xVnpZrMbsOpvoYIhxyafySZ+w0R5igWUUyzbMWi9x6o8/1rQnG2lKn9
vMELi7Mr4QKBgQDcCUK++RVxpcrzrBRA9+184OAX4Yn063X00nHLjl3CWTfUZ4jp
LCWy6zVNrmOsmc1r3zmPI6uO4UFUAYyfjV9hvWD622aDCAQJNURt83K3uCVzQQqq
mY4E487s1HGhutzGMQyFjLH/ds3ydezXdtFvWtNLd7t9GEJmrNSYdtpxbQKBgCt9
D1FpL7HJX0xQGI8hM5iwHj+3/JoArmBJaTMeYYAusxoydtHHaa5muO/KMIH8h8Zk
0qb1CwUo84gTkyHjXF4HghZdJqSQihlYPmnmoo8TJPW1DyF+2/xCzBDfeVKlFjPA
CGJQNuHuuxTTQVBT3Z6aGLT6kgkSKBIx6zqLtJzBAoGAOb99J2wnnleJRSitUpaJ
NnVAaPlTRVkAVgYDbY4bLbz4uz6wSnS5iYfH8wp3kHhBSTps6F40FP2WuRU2EesD
zDXiVO/FX+R5c6+iHW+Doi5LiAsavFtXQDxXgrozXBgkCbuarvqH3xk3It3PNgcf
M/e/i4JlQtMxFlVUin8PgUE=
-----END PRIVATE KEY-----
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

	block, _ := pem.Decode(testingCert)
	if block == nil {
		return nil, errors.New("got empty decode result for certificate")
	}

	cert.Certificate = append(cert.Certificate, block.Bytes)

	block, _ = pem.Decode(testingKey)
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
