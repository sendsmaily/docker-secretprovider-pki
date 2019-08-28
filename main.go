package main

import (
	"net/http"
	"os"

	"github.com/docker/docker/client"
	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"docker-secretprovider-pki/backend"
	"docker-secretprovider-pki/driver"
)

func main() {
	logger, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(logger)

	zap.S().Info("pki: initializing...")

	var httpClient *http.Client
	dockerClient, err := client.NewClient("unix:///docker.sock", "1.35", httpClient, nil)
	if err != nil {
		zap.S().Fatalf("pki: error creating docker client: %v", err)
	}

	var ca driver.CABackend
	switch os.Getenv("BACKEND") {
	case "secrethub":
		ca, err = backend.NewSecrethubBackend()
	case "test":
		ca, err = backend.NewTestBackend()
	default:
		err = errors.New("backend not configured. Use `docker plugin set <plugin alias> BACKEND=<value>`")
	}

	if err != nil {
		zap.S().Fatalf("pki: error initializing CA backend: %s", err)
	}

	drv, err := driver.NewDriver(ca, dockerClient)
	if err != nil {
		zap.S().Fatalf("pki: error initializing PKI driver: %s", err)
	}

	handler := secrets.NewHandler(drv)
	if err := handler.ServeUnix("plugin", 0); err != nil {
		zap.S().Fatalf("pki: %s", err)
	}
}
