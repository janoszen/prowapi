package client

import (
	"net/http"
)

type client struct {
	httpClient *http.Client
}
