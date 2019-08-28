package driver_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPKISecretDriver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Secrets driver suite")
}
