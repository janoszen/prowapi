package server

import (
	"crypto/tls"
	"fmt"
	"sync"
)

func NewServer(config Config) (Server, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("server configuration is invalid (%w)", err)
	}
	var tlsConfig *tls.Config
	if config.cert != nil {
		var err error
		tlsConfig, err = config.createServerTLSConfig()
		if err != nil {
			return nil, err
		}
	}

	return &server{
		lock:      &sync.Mutex{},
		config:    config,
		tlsConfig: tlsConfig,
		srv:       nil,
	}, nil
}