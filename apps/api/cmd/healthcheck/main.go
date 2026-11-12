// healthcheck is a minimal probe binary for the scratch runtime image:
// HTTP GET /health must answer 200. Used by the Docker HEALTHCHECK where
// wget/curl are unavailable (no shell in scratch).
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("HEALTHCHECK_PORT")
	if port == "" {
		port = "8080"
	}
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/health", port))
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}
