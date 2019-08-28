# Overview

This is an example for using the PKI provider.

It implements a simple HTTPS server and client using mTLS for communication.

# Running

Getting the example running is somewhat involved. It assumes you're running a one node Swarm cluster locally.

Start by installing and configuring the PKI provider plugin:
```
$ docker plugin install --alias sendsmaily/pki:latest --grant-all-permissions sendsmaily/docker-provider-pki:latest
$ docker plugin set sendsmaily/pki:latest BACKEND=test
```

Then build the example's Docker image:
```
$ docker build -t sendsmaily/pki-example:latest .
```

Set up the secrets:
```
$ docker secret create \
--driver sendsmaily/pki:latest \
--label pki.ca=test \
--label pki.cn="Example server" \
--label pki.dns_names=localhost,pki_example_server \
--label pki.usage=server \
pki_example_server_bundle
```
```
$ docker secret create \
--driver sendsmaily/pki:latest \
--label pki.ca=test \
--label pki.cn="Example client" \
--label pki.dns_names=localhost,pki_example_server \
--label pki.usage=client \
pki_example_client_bundle
```

Create a network for the services:
```
$ docker network create --driver overlay --attachable pki_example
```

Create and launch the services:
```
$ docker service create \
--init \
--name pki_example_server \
--network pki_example \
--secret source=pki_example_server_bundle,target=bundle.pem,mode=0400 \
sendsmaily/pki-example:latest \
server
```
```
$ docker service create \
--init \
--name pki_example_client \
--network pki_example \
--secret source=pki_example_client_bundle,target=bundle.pem,mode=0400 \
sendsmaily/pki-example:latest \
client
```

And marvel at the mutually authenticated TLS connection awesomeness:
```
$ docker service logs -f pki_example_server
```
Or
```
$ docker service logs -f pki_example_client
```

To clean up:
```
$ docker service rm pki_example_server pki_example_client
$ docker secret rm pki_example_server_bundle pki_example_client_bundle
$ docker network rm pki_example
```
