package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

// Build-time variables (injected via -ldflags)
var (
	Version   = "dev"
	BuildDate = "unknown"
	VCSRef    = "unknown"
)

type jsonResponse map[string]interface{}

// writeJSON writes a JSON response and logs write errors.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		// Log the error — don't expose internals to the client
		log.Printf("error encoding JSON response: %v", err)
	}
}

// securityHeadersMiddleware sets common security headers.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// Basic XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Content Security Policy — minimal; adjust per app needs
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		// Referrer policy
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// helloHandler responds with an info message.
func helloHandler(w http.ResponseWriter, r *http.Request) {
	resp := fmt.Sprintf(
		"Hello, secure world! This is the SLSA L3 test application.\n\nVersion: %s\nBuild Date: %s\nCommit: %s",
		Version, BuildDate, VCSRef,
	)
	// Small text response; use Write and log errors
	if _, err := w.Write([]byte(resp)); err != nil {
		log.Printf("error writing hello response: %v", err)
	}
}

// healthHandler returns a short JSON health status.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, jsonResponse{"status": "healthy", "version": Version})
}

// readyHandler returns readiness JSON.
func readyHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, jsonResponse{"status": "ready"})
}

// versionHandler returns version metadata as JSON.
func versionHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, jsonResponse{
		"version":   Version,
		"buildDate": BuildDate,
		"gitCommit": VCSRef,
	})
}

func main() {
	// Flags
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	helpFlag := flag.Bool("help", false, "Print help information and exit")
	healthFlag := flag.Bool("health", false, "Perform health check and exit (for Docker HEALTHCHECK)")
	portFlag := flag.Int("port", 8080, "Port to listen on")
	flag.Parse()

	// Handle version/help flags
	if *versionFlag {
		fmt.Printf("Version:    %s\n", Version)
		fmt.Printf("Build Date: %s\n", BuildDate)
		fmt.Printf("Git Commit: %s\n", VCSRef)
		os.Exit(0)
	}
	if *helpFlag {
		fmt.Println("SLSA L3 Demo Application")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		fmt.Println("\nEndpoints:")
		fmt.Println("  GET /           - Hello world message")
		fmt.Println("  GET /health     - Health check endpoint")
		fmt.Println("  GET /ready      - Readiness check endpoint")
		fmt.Println("  GET /version    - Version information")
		os.Exit(0)
	}

	// If healthFlag is used (for Docker HEALTHCHECK), do a quick HTTP GET with timeout
	if *healthFlag {
		client := &http.Client{
			Timeout: 3 * time.Second,
		}
		url := "http://localhost:" + strconv.Itoa(*portFlag) + "/health"
		resp, err := client.Get(url)
		if err != nil {
			log.Fatalf("health check failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			fmt.Println("Health check: OK")
			os.Exit(0)
		}
		fmt.Printf("Health check failed: status %d\n", resp.StatusCode)
		os.Exit(1)
	}

	// Router and middleware
	r := mux.NewRouter()
	r.Use(securityHeadersMiddleware)
	r.HandleFunc("/", helloHandler).Methods("GET")
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/ready", readyHandler).Methods("GET")
	r.HandleFunc("/version", versionHandler).Methods("GET")

	// Server configuration with timeouts
	srv := &http.Server{
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		// Don't set Addr yet — we bind below after validating the port
	}

	addr := ":" + strconv.Itoa(*portFlag)
	log.Printf("Starting server on %s", addr)
	log.Printf("Version: %s, Build Date: %s, Commit: %s", Version, BuildDate, VCSRef)

	// Start server in background goroutine so we can handle graceful shutdown
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}

	// Channel to capture errors from ListenAndServe
	serverErrCh := make(chan error, 1)
	go func() {
		// srv.Serve will return http.ErrServerClosed on graceful shutdown
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	// Setup signal handling for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-stop:
		log.Printf("Received signal %s — shutting down", sig)
	case err := <-serverErrCh:
		if err != nil {
			log.Fatalf("server error: %v", err)
		}
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		if err := srv.Close(); err != nil {
			log.Printf("server close failed: %v", err)
		}
	}
	log.Println("server stopped")
}
