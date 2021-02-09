package server

import (
	"context"
)

// Server is the main service running for the Prow API.
type Server interface {
	// Start runs the server in the background until Stop is called. If an error happens during startup
	// it is returned from Start.
	Start() error

	// Stop triggers the server to stop if it has been run before. The shutdownContext provides the server
	// a timeout by which to stop. The context MUST NOT be an empty context or a client may hold the server stop
	// forever. Stop blocks until the server has stopped.
	Stop(shutdownContext context.Context)

	// Run runs the server in the foreground and returns when the server has stopped. If an error happened during run
	// the error is returned.
	Run() error

	// Wait waits for the server to stop and returns the error that happened during run.
	Wait() error
}
