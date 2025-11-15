package main

import (
	"log"
	"net/http"
	"os"
	"runtime"

	// Import an external dependency for SBOM demonstration
	"github.com/gorilla/mux"
)

// A simple HTTP handler that provides system information
func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	buildInfo := getBuildInfo()
	w.Write([]byte("Hello, secure world! This is the SLSA L3 test application.\n\n" + buildInfo))
}

// Health check endpoint
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"status\":\"healthy\",\"slsa_level\":3}"))
}

// Get build information
func getBuildInfo() string {
	version := os.Getenv("VERSION")
	if version == "" {
		version = "dev"
	}
	return "Version: " + version + "\n" +
		"Architecture: " + runtime.GOARCH + "\n" +
		"OS: " + runtime.GOOS + "\n" +
		"Go Version: " + runtime.Version()
}

func main() {
	// Create a new router
	r := mux.NewRouter()

	// Register handlers
	r.HandleFunc("/", helloHandler)
	r.HandleFunc("/health", healthHandler)

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("SLSA L3 Secure Server starting on port %s...", port)
	log.Printf("Architecture: %s, OS: %s", runtime.GOARCH, runtime.GOOS)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
