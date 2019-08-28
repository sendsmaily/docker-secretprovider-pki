FROM golang:1.12-alpine

ENV GO111MODULE=on

RUN apk add --no-cache git

WORKDIR /go/src/example

COPY go.mod .
COPY go.sum .
RUN go get

COPY . /go/src/example
RUN set -ex && go install --ldflags '-extldflags "-static"' example/server/
RUN set -ex && go install --ldflags '-extldflags "-static"' example/client/
