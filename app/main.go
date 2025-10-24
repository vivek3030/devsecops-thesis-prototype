package main

import (
	"log"
	"net/http"

	// Import an external dependency so Syft has something to find in the SBOM
	"github.com/gorilla/mux"
)

// A simple HTTP handler
func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello, secure world! This is the test application."))
}

func main() {
	// Create a new router
	r := mux.NewRouter()
	
	// Register the handler
	r.HandleFunc("/", helloHandler)

	// Start the server
	log.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", r))
}

