package cmd

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
	"user-auth/internal/controller"
	"user-auth/internal/router"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

const (
	ReadTimeout     = 5 * time.Second
	WriteTimeout    = 10 * time.Second
	IdleTimeout     = 120 * time.Second
	ShutdownTimeout = 10 * time.Second
)

// Start HTTP server and handle graceful shutdown with GIN router
func RunServer(ctx context.Context, addr string, ctrl controller.Controller, apiKey string, accessTokenSecret string) error {
	logPrefix := "[RunServer]"
	r := gin.Default()
	router.SetupRouter(r, ctrl, apiKey, accessTokenSecret)

	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	// Create a wait errgroup to manage multiple goroutines
	g, ctx := errgroup.WithContext(ctx)

	// Run server
	g.Go(func() error {
		log.Printf("%s[Server starting on %s]", logPrefix, addr)
		return server.ListenAndServe()
	})

	// Run graceful shutdown
	g.Go(func() error {
		<-ctx.Done()
		log.Printf("%s[Gracefully shutting down server...]", logPrefix)

		shutdownCtx, cancel := context.WithTimeout(ctx, ShutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	})

	// Wait for all goroutines to exit
	if err := g.Wait(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("%s[Server error: %v]", logPrefix, err)
		return err
	}
	return nil
}
