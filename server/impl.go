package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
)

type server struct {
	lock      *sync.Mutex
	config    Config
	tlsConfig *tls.Config
	srv       *http.Server
	lastError error
	done      chan struct{}
}

func (s *server) Start() error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.srv != nil {
		// Desired state is running
		return nil
	}
	s.done = make(chan struct{})
	s.lastError = nil
	s.srv = &http.Server{
		Addr:      s.config.Listen,
		Handler:   s,
		TLSConfig: s.tlsConfig,
	}
	listener, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		s.lock.Unlock()
		return err
	}

	go func() {
		defer func() {
			s.lock.Lock()
			close(s.done)
			_ = listener.Close()
			s.srv = nil
			s.lock.Unlock()
		}()
		if s.srv.TLSConfig != nil {
			// certFile and keyFile are left empty intentionally, otherwise go HTTP will try to read the files and
			// override our TLS configuration.
			s.lastError = s.srv.ServeTLS(listener, "", "")
		} else {
			s.lastError = s.srv.Serve(listener)
		}
	}()
	return nil
}

func (s *server) Stop(shutdownContext context.Context) {
	s.lock.Lock()
	if s.srv == nil {
		s.lock.Unlock()
		return
	}
	srv := s.srv
	s.lock.Unlock()
	_ = srv.Shutdown(shutdownContext)
}

func (s *server) Run() error {
	if err := s.Start(); err != nil {
		return err
	}
	return s.Wait()
}

func (s *server) Wait() error {
	s.lock.Lock()
	if s.srv == nil {
		s.lock.Unlock()
		return nil
	}
	done := s.done
	s.lock.Unlock()
	<-done
	return s.lastError
}

func (s *server) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {

}
