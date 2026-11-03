// Command enrolment runs the recasaos-relay enrolment service.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/ReCasaOS/recasaos-relay/internal/server"
)

func main() {
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	log.Printf("enrolment listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, server.New(cfg, server.Deps{})))
}
