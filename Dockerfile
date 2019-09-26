FROM golang:1.12-alpine AS builder

ENV GO111MODULE=on

RUN apk add --no-cache git gcc libc-dev

COPY . /go/src/github.com/sendsmaily/docker-secretprovider-pki

WORKDIR /go/src/github.com/sendsmaily/docker-secretprovider-pki

RUN set -ex && go install -mod vendor --ldflags '-extldflags "-static"'


FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /go/bin/docker-secretprovider-pki .

CMD ["docker-secretprovider-pki"]
