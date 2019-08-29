# Overview

The PKI provider Docker plugin allows running a private PKI issuing (ephemeral) TLS certificates.

## Configuring the plugin

Plugin accepts following configuration values:
- `BACKEND`: allowed values `secrethub`, `test`. Leaving it unspecified will make the plugin exit with error.

The configuration values can be specified using Docker's `docker plugin set` subcommand.

For example:
```
$ docker plugin set sendsmaily/pki:latest BACKEND=test
```

## Issuing certificates

The `example` directory contains a complete example for using the plugin.

The certificate issuing process is integrated with Docker secrets engine. To issue a certificate, a Docker secret
needs to be created with the plugin specified as its driver. Issued certificate is configured using secret's labels.

Plugin accepts following configuration labels for secrets:
- `pki.ca`: name of the CA to use,
- `pki.cn`: Common Name for the certificate,
- `pki.dns_names`: DNS SANS for the certificate
- `pki.ip_addrs`: IP SANS for the certificate (most likely you won't be using this, but it exists for some potential edge cases),
- `pki.usage`: Extended Key Usage specification for the certificate. Valid values: `server`, `client`, `server-client` (and also `client-server`), and
- `pki.lifetime`: lifetime for the certificate specified as Go duration, defaults to: `24h`.

> Certificate revocations are and will not be implemented. Read up on the philosophy behind that [here](https://www.vaultproject.io/docs/secrets/pki/index.html#keep-certificate-lifetimes-short-for-crl-39-s-sake).

# Design

The plugin consists of two main components:
- a driver responsible for issuing the certificates, and
- a pluggable CA backend responsible for providing CA for signing issued certificates.

`Driver` is the implementation of Docker secret provider plugin's `Driver` interface. The driver receives a request for
the certificate, validates it returning errors if needed, and signes the certificate using a CA fetched from the backend.

The CA backend is responsible for returning CA certificates and private keys, returning errors when the CA requested does
not exist.
