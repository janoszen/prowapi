package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	prowX509 "github.com/openshift/prowapi/common/x509"
)

// Config configures the Server.
type Config struct {
	// Listen is the IP and port to listen on for connections.
	Listen string `json:"listen"`
	// Key contains either a file name to a private key, or the private key itself in PEM format to use as a server key.
	Key string `json:"key" yaml:"key"`
	// Cert contains either a file to a certificate, or the certificate itself in PEM format to use as a server
	// certificate.
	Cert string `json:"cert" yaml:"cert"`
	// ClientCACert contains either a file or a certificate in PEM format to verify the connecting clients by.
	ClientCACert string `json:"clientcacert" yaml:"clientcacert"`

	// cert is for internal use only. It contains the key and certificate after Validate.
	cert *tls.Certificate
	// clientCAPool is for internal use only. It contains the client CA pool after Validate.
	clientCAPool *x509.CertPool
}

// Validate validates the server configuration.
func (config *Config) Validate() error {
	if config.Listen == "" {
		return fmt.Errorf("no listen address provided")
	}
	if _, _, err := net.SplitHostPort(config.Listen); err != nil {
		return fmt.Errorf("invalid listen address provided (%w)", err)
	}
	if config.Cert != "" && config.Key == "" {
		return fmt.Errorf("certificate provided without a key")
	}
	if config.Cert == "" && config.Key != "" {
		return fmt.Errorf("key provided without certificate")
	}

	if config.Cert != "" && config.Key != "" {
		pemCert, err := prowX509.LoadPEM(config.Cert)
		if err != nil {
			return fmt.Errorf("failed to load certificate (%w)", err)
		}
		pemKey, err := prowX509.LoadPEM(config.Key)
		if err != nil {
			return fmt.Errorf("failed to load key (%w)", err)
		}
		cert, err := tls.X509KeyPair(pemCert, pemKey)
		if err != nil {
			return fmt.Errorf("failed to load key/certificate (%w)", err)
		}
		config.cert = &cert
	}

	if config.ClientCACert != "" {
		clientCaCert, err := prowX509.LoadPEM(config.ClientCACert)
		if err != nil {
			return fmt.Errorf("failed to load client CA certificate (%w)", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(clientCaCert) {
			return fmt.Errorf("failed to load client CA certificate")
		}
		config.clientCAPool = caCertPool
	}

	return nil
}

func (config *Config) createServerTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{
			tls.X25519,
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}

	tlsConfig.Certificates = []tls.Certificate{*config.cert}

	if config.clientCAPool != nil {
		tlsConfig.ClientCAs = config.clientCAPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConfig, nil
}

