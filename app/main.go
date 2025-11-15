package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

// Build-time variables (injected via -ldflags)
var (
	Version   = "dev"
	BuildDate = "unknown"
	VCSRef    = "unknown"
)

// Simple HTTP handler
func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(fmt.Sprintf(
		"Hello, secure world! This is the SLSA L3 test application.\n\nVersion: %s\nBuild Date: %s\nCommit: %s",
		Version, BuildDate, VCSRef,
	))); err != nil {
		log.Printf("Error writing hello response: %v", err)
	}
}

// Health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"status":"healthy","version":"%s"}`, Version))); err != nil {
		log.Printf("Error writing health response: %v", err)
	}
}

// Readiness check endpoint
func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ready"}`)); err != nil {
		log.Printf("Error writing readiness response: %v", err)
	}
}

// Version information endpoint
func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(fmt.Sprintf(`{
	"version": "%s",
	"buildDate": "%s",
	"gitCommit": "%s"
}`, Version, BuildDate, VCSRef))); err != nil {
		log.Printf("Error writing version response: %v", err)
	}
}

func main() {
	// Command-line flags
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	helpFlag := flag.Bool("help", false, "Print help information and exit")
	healthFlag := flag.Bool("health", false, "Perform health check and exit (for Docker HEALTHCHECK)")
	port := flag.String("port", "8080", "Port to listen on")
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
		fmt.Println("  GET /           - Hello world message")
		fmt.Println("  GET /health     - Health check endpoint")
		fmt.Println("  GET /ready      - Readiness check endpoint")
		fmt.Println("  GET /version    - Version information")
		os.Exit(0)
	}

	if *healthFlag {
		resp, err := http.Get("http://localhost:" + *port + "/health")
		if err != nil {
			log.Fatalf("Health check failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Println("Health check: OK")
			os.Exit(0)
		} else {
			fmt.Printf("Health check failed: status %d\n", resp.StatusCode)
			os.Exit(1)
		}
	}

	// Create router
	r := mux.NewRouter()
	r.HandleFunc("/", helloHandler).Methods("GET")
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/ready", readyHandler).Methods("GET")
	r.HandleFunc("/version", versionHandler).Methods("GET")

	// Log startup
	log.Printf("Starting server...")
	log.Printf("Version: %s", Version)
	log.Printf("Build Date: %s", BuildDate)
	log.Printf("Git Commit: %s", VCSRef)
	log.Printf("Listening on port %s...", *port)

	// Use http.Server with timeouts
	srv := &http.Server{
		Addr:         ":" + *port,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed to start: %v", err)
	}
}
