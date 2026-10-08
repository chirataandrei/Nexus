// Command nexus-demo-upstream is a fake LLM endpoint for the demo: it
// answers every POST with an OpenAI-style body reporting 1000 tokens.
package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9101", "listen address")
	flag.Parse()
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"demo","choices":[{"message":{"role":"assistant","content":"hello from the fake model"}}],"usage":{"prompt_tokens":600,"completion_tokens":400,"total_tokens":1000}}`))
	})
	log.Fatal(http.ListenAndServe(*addr, nil))
}
