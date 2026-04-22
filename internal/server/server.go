package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// Server wraps the HTTP server with graceful shutdown.
type Server struct {
	httpServer  *http.Server
	onShutdown  []func()
}

// New creates a new Server.
func New(handler http.Handler, port int) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf(":%d", port),
			Handler:      handler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}
}

// OnShutdown registers a callback to run during graceful shutdown (e.g. closing DB pool).
func (s *Server) OnShutdown(fn func()) {
	s.onShutdown = append(s.onShutdown, fn)
}

// Start begins listening and handles graceful shutdown on SIGINT/SIGTERM.
func (s *Server) Start() error {
	// Channel for shutdown signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Channel for server errors
	errCh := make(chan error, 1)

	go func() {
		log.Info().Str("addr", s.httpServer.Addr).Msg("starting aegis server")
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		log.Info().Str("signal", sig.String()).Msg("shutting down server")
	}

	// Graceful shutdown with 30s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	// Run shutdown callbacks (close DB pool, etc.)
	for _, fn := range s.onShutdown {
		fn()
	}

	log.Info().Msg("server stopped gracefully")
	return nil
}
