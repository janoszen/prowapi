package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	prowX509 "github.com/openshift/prowapi/common/x509"
)

// Config is the configuration structure for the Prow API clients.
type Config struct {
	// URL is the base URL for requests.
	Endpoint string `json:"url" yaml:"url" comment:"Base URL of the server to connect."`

	// Timeout is the time the client should wait for a response.
	Timeout time.Duration `json:"timeout" yaml:"timeout" comment:"HTTP call timeout." default:"2s"`

	// CACert is either the CA certificate to expect on the server in PEM format
	//         or the name of a file containing the PEM.
	CACert string `json:"cacert" yaml:"cacert" comment:"CA certificate in PEM format to use for host verification. Note: due to a bug in Go on Windows this has to be explicitly provided."`

	// ClientCert is a PEM containing an x509 certificate to present to the server or a file name containing the PEM.
	ClientCert string `json:"cert" yaml:"cert" comment:"Client certificate file in PEM format."`
	// ClientKey is a PEM containing a private key to use to connect the server or a file name containing the PEM.
	ClientKey string `json:"key" yaml:"key" comment:"Client key file in PEM format."`

	// caCertPool is for internal use only. It contains the loaded CA certificates after Validate.
	caCertPool *x509.CertPool
	// cert is for internal use only. It contains the loaded TLS key and certificate after Validate.
	cert *tls.Certificate
}

// Validate validates the client configuration and returns an error if it is invalid.
func (config *Config) Validate() error {
	_, err := url.ParseRequestURI(config.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %s", config.Endpoint)
	}
	if config.Timeout < 100*time.Millisecond {
		return fmt.Errorf("timeout value %s is too low, must be at least 100ms", config.Timeout.String())
	}

	if strings.TrimSpace(config.CACert) != "" {
		caCert, err := prowX509.LoadPEM(config.CACert)
		if err != nil {
			return fmt.Errorf("failed to load CA certificate (%w)", err)
		}

		config.caCertPool = x509.NewCertPool()
		if !config.caCertPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("invalid CA certificate provided")
		}
	} else if strings.HasPrefix(config.Endpoint, "https://") {
		config.caCertPool, err = x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf(
				"system certificate pool unusable and no explicit CA certificate was given (%w)",
				err,
			)
		}
	}

	if config.ClientCert != "" && config.ClientKey == "" {
		return fmt.Errorf("client certificate provided without client key")
	} else if config.ClientCert == "" && config.ClientKey != "" {
		return fmt.Errorf("client key provided without client certificate")
	}

	if config.ClientCert != "" && config.ClientKey != "" {
		clientCert, err := prowX509.LoadPEM(config.ClientCert)
		if err != nil {
			return fmt.Errorf("failed to load client certificate (%w)", err)
		}
		clientKey, err := prowX509.LoadPEM(config.ClientKey)
		if err != nil {
			return fmt.Errorf("failed to load client certificate (%w)", err)
		}
		cert, err := tls.X509KeyPair(clientCert, clientKey)
		if err != nil {
			return fmt.Errorf("failed to load certificate or key (%w)", err)
		}
		config.cert = &cert
	}

	return nil
}

func (config Config) createTLSConfig() (*tls.Config, error) {
	if !strings.HasPrefix(config.Endpoint, "https://") {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	if config.caCertPool != nil {
		tlsConfig.RootCAs = config.caCertPool
	}
	if config.cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*config.cert}
	}
	return tlsConfig, nil
}
