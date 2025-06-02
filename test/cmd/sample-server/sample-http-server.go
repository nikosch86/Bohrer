package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type Response struct {
	Message   string    `json:"message"`
	Server    string    `json:"server"`
	Timestamp time.Time `json:"timestamp"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		response := Response{
			Message:   "Hello from sample HTTP server!",
			Server:    "e2e-test-server",
			Timestamp: time.Now(),
			Path:      r.URL.Path,
			Method:    r.Method,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

		log.Printf("Served request: %s %s", r.Method, r.URL.Path)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"server": "e2e-test-server",
		})
	})

	log.Printf("Sample HTTP server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
