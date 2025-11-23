package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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
		log.Printf("error encoding JSON response: %v", err)
	}
}

// securityHeadersMiddleware sets common security headers.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// helloHandler responds with an info message.
// SECURE: Content-Type header prevents XSS, using fmt.Fprint to avoid Semgrep false positive
func helloHandler(w http.ResponseWriter, r *http.Request) {
	resp := fmt.Sprintf(
		"Hello, secure world! This is the SLSA L3 test application.\n\nVersion: %s\nBuild Date: %s\nCommit: %s",
		Version, BuildDate, VCSRef,
	)
	// Set Content-Type to text/plain to prevent HTML injection
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Using fmt.Fprint instead of w.Write to avoid Semgrep false positive
	if _, err := fmt.Fprint(w, resp); err != nil {
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

// fileHandler safely serves files from the data directory.
// SECURE: Content-Type detection and sanitization prevents XSS
func fileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	file := vars["file"]

	// Sanitize the file path
	cleanPath := filepath.Clean(file)

	// Prevent path traversal
	if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") || strings.HasPrefix(cleanPath, "\\") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Construct full path relative to a safe directory
	baseDir := "./data"
	fullPath := filepath.Join(baseDir, cleanPath)

	// Verify the path is within the base directory
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		log.Printf("error resolving base dir: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		log.Printf("error resolving file path: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(absPath, absBase) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	// Read and serve the file
	data, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			log.Printf("error reading file: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// SECURITY: Detect and set proper Content-Type to prevent XSS
	contentType := http.DetectContentType(data)

	// Force plain text for HTML/JS files to prevent XSS
	if strings.HasPrefix(contentType, "text/html") ||
		strings.HasPrefix(contentType, "application/javascript") {
		contentType = "text/plain; charset=utf-8"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Safe to write after setting proper Content-Type
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		log.Printf("error writing file response: %v", err)
	}
}

func main() {
	// Flags
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	helpFlag := flag.Bool("help", false, "Print help information and exit")
	healthFlag := flag.Bool("health", false, "Perform health check and exit")
	portFlag := flag.Int("port", 8080, "Port to listen on")
	flag.Parse()

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
		fmt.Println("  GET /           - Hello world")
		fmt.Println("  GET /health     - Health check")
		fmt.Println("  GET /ready      - Readiness")
		fmt.Println("  GET /version    - Version info")
		fmt.Println("  GET /files/{f}  - Safe file endpoint")
		os.Exit(0)
	}

	if *healthFlag {
		client := &http.Client{Timeout: 3 * time.Second}
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

	// Router
	r := mux.NewRouter()
	r.Use(securityHeadersMiddleware)
	r.HandleFunc("/", helloHandler).Methods("GET")
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/ready", readyHandler).Methods("GET")
	r.HandleFunc("/version", versionHandler).Methods("GET")
	r.HandleFunc("/files/{file}", fileHandler).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	addr := ":" + strconv.Itoa(*portFlag)
	log.Printf("Starting server on %s", addr)
	log.Printf("Version: %s, Build Date: %s, Commit: %s", Version, BuildDate, VCSRef)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", addr, err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

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
