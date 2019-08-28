package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"go.uber.org/zap"

	"example/cert"
)

func main() {
	logger, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(logger)

	bundle, err := cert.LoadBundle("/run/secrets/bundle.pem")
	if err != nil {
		zap.S().Fatalf("Error loading certificate bundle: %s", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*bundle.Certificate},
		RootCAs:      bundle.CAPool,
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	zap.S().Info("Starting client...")
	for {
		r, err := client.Get("https://pki_example_server:443/")
		if err != nil {
			log.Fatal(err)
		}

		// Read the response body
		defer r.Body.Close()
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			zap.S().Error(err)
		}

		// Print the response body to stdout
		zap.S().Infof("%s", body)

		time.Sleep(time.Second)
	}
}
