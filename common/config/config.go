package config

import (
	"github.com/docker/docker/api/server"

	"github.com/openshift/prowapi/prow"
)

// AppConfig is the main configuration for the Prow API application.
type AppConfig struct {
	// HTTP is the configuration for the HTTP server.
	HTTP       server.Config             `json:"http" yaml:"http"`
	// Prow is the configuration for accessing the Kubernetes.
	Prow prow.Config `json:"prow" yaml:"prow"`
}
