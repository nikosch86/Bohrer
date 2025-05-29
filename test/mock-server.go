package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	port := 3000
	if p := os.Getenv("PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			port = parsed
		}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		response := fmt.Sprintf(`{
  "message": "Hello from mock server!",
  "host": "%s",
  "path": "%s",
  "method": "%s",
  "headers": %v
}`, r.Host, r.URL.Path, r.Method, r.Header)
		
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, response)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status": "ok", "service": "mock-server"}`)
	})

	log.Printf("Mock server starting on port %d", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatalf("Mock server failed: %v", err)
	}
}