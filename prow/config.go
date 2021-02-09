package prow

import (
	"fmt"
	"os"
	"time"

	core "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"
)

type Config struct {
	Connection KubernetesConfig `json:"connection" yaml:"connection"`
}

// The following Kubernetes source code has been ported from the ContainerSSH Kubernetes Backend.

// KubernetesConfig configures the connection to the Kubernetes cluster.
type KubernetesConfig struct {
	// Host is a host string, a host:port pair, or a URL to the Kubernetes apiserver. Defaults to kubernetes.default.svc.
	Host string `json:"host" yaml:"host" comment:"a host string, a host:port pair, or a URL to the base of the apiserver." default:"kubernetes.default.svc"`
	// APIPath is a sub-path that points to the API root. Defaults to /api
	APIPath string `json:"path" yaml:"path" comment:"APIPath is a sub-path that points to an API root." default:"/api"`

	// Username is the username for basic authentication.
	Username string `json:"username" yaml:"username" comment:"Username for basic authentication"`
	// Password is the password for basic authentication.
	Password string `json:"password" yaml:"password" comment:"Password for basic authentication"`

	// Insecure means that the server should be accessed without TLS verification. This is NOT recommended.
	Insecure bool `json:"insecure" yaml:"insecure" comment:"Server should be accessed without verifying the TLS certificate." default:"false"`
	// ServerName sets the server name to be set in the SNI and used by the client for TLS verification.
	ServerName string `json:"serverName" yaml:"serverName" comment:"ServerName is passed to the server for SNI and is used in the client to check server certificates against."`

	// CertFile points to a file that contains the client certificate used for authentication.
	CertFile string `json:"certFile" yaml:"certFile" comment:"File containing client certificate for TLS client certificate authentication."`
	// KeyFile points to a file that contains the client key used for authentication.
	KeyFile string `json:"keyFile" yaml:"keyFile" comment:"File containing client key for TLS client certificate authentication"`
	// CAFile points to a file that contains the CA certificate for authentication.
	CAFile string `json:"caCertFile" yaml:"caCertFile" comment:"File containing trusted root certificates for the server"`

	// CertData contains a PEM-encoded certificate for TLS client certificate authentication.
	CertData string `json:"cert" yaml:"cert" comment:"PEM-encoded certificate for TLS client certificate authentication"`
	// KeyData contains a PEM-encoded client key for TLS client certificate authentication.
	KeyData string `json:"key" yaml:"key" comment:"PEM-encoded client key for TLS client certificate authentication"`
	// CAData contains a PEM-encoded trusted root certificates for the server.
	CAData string `json:"caCert" yaml:"caCert" comment:"PEM-encoded trusted root certificates for the server"`

	// BearerToken contains a bearer (service) token for authentication.
	BearerToken string `json:"bearerToken" yaml:"bearerToken" comment:"Bearer (service token) authentication"`
	// BearerTokenFile points to a file containing a bearer (service) token for authentication.
	// Set to /var/run/secrets/kubernetes.io/serviceaccount/token to use service token in a Kubernetes kubeConfigCluster.
	BearerTokenFile string `json:"bearerTokenFile" yaml:"bearerTokenFile" comment:"Path to a file containing a BearerToken. Set to /var/run/secrets/kubernetes.io/serviceaccount/token to use service token in a Kubernetes kubeConfigCluster."`

	// QPS indicates the maximum QPS to the master from this client. Defaults to 5.
	QPS float32 `json:"qps" yaml:"qps" comment:"QPS indicates the maximum QPS to the master from this client." default:"5"`
	// Burst indicates the maximum burst for throttle.
	Burst int `json:"burst" yaml:"burst" comment:"Maximum burst for throttle." default:"10"`
	// Timeout for HTTP calls.
	Timeout time.Duration `json:"timeout" yaml:"timeout" comment:"Timeout for HTTP calls" default:"15s"`
}

// Validate validates the connection parameters.
func (c KubernetesConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("no host specified")
	}
	if c.APIPath == "" {
		return fmt.Errorf("no API path specified")
	}
	if c.BearerTokenFile != "" {
		if _, err := os.Stat(c.BearerTokenFile); err != nil {
			return fmt.Errorf("bearer token file %s not found (%w)", c.BearerTokenFile, err)
		}
	}
	return nil
}

// GetRESTConfig returns a configuration for the REST client.
func (c KubernetesConfig) GetRESTConfig() (restclient.Config, error) {
	if err := c.Validate(); err != nil {
		return restclient.Config{}, err
	}
	return restclient.Config{
		Host:    c.Host,
		APIPath: c.APIPath,
		ContentConfig: restclient.ContentConfig{
			GroupVersion:         &core.SchemeGroupVersion,
			NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		},
		Username:        c.Username,
		Password:        c.Password,
		BearerToken:     c.BearerToken,
		BearerTokenFile: c.BearerTokenFile,
		Impersonate:     restclient.ImpersonationConfig{},
		TLSClientConfig: restclient.TLSClientConfig{
			Insecure:   c.Insecure,
			ServerName: c.ServerName,
			CertFile:   c.CertFile,
			KeyFile:    c.KeyFile,
			CAFile:     c.CAFile,
			CertData:   []byte(c.CertData),
			KeyData:    []byte(c.KeyData),
			CAData:     []byte(c.CAData),
		},
		UserAgent: "ProwAPI",
		QPS:       c.QPS,
		Burst:     c.Burst,
		Timeout:   c.Timeout,
	}, nil
}

