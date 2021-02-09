package client

import (
	"fmt"
	"net/http"
)

func NewClient(config Config) (ProwClient, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("failed to create Prow client (%w)", err)
	}

	tlsConfig, err := config.createTLSConfig()
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return &client{
		httpClient: httpClient,
	}, nil
}
