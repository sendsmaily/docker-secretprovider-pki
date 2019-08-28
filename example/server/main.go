package main

import (
	"crypto/tls"
	"net"
	"net/http"

	"go.uber.org/zap"

	"example/cert"
)

func main() {
	logger, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(logger)

	zap.S().Info("Starting server...")
	http.HandleFunc("/", handler)

	bundle, err := cert.LoadBundle("/run/secrets/bundle.pem")
	if err != nil {
		zap.S().Fatalf("Error loading certificate bundle: %s", err)
	}

	server := http.Server{Addr: ":443", Handler: nil}

	conn, err := net.Listen("tcp", server.Addr)
	if err != nil {
		zap.S().Fatalf("Error listening on '%s': %s", server.Addr, err)
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*bundle.Certificate},
		ClientCAs:    bundle.CAPool,
	}

	listener := tls.NewListener(conn, tlsConfig)

	zap.S().Info("Listening on :443")
	if err := server.Serve(listener); err != nil {
		zap.S().Fatalf("Server error: %s", err)
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	zap.S().Infof("%s: %+v", req.RemoteAddr, req.TLS)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Bork."))
}
