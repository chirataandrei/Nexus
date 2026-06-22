.PHONY: build run test test-all vet fmt agentctl

build:
	go build -o bin/nexus-gateway ./cmd/nexus-gateway

agentctl:
	go build -o bin/nexus-agentctl ./cmd/nexus-agentctl

run: build
	./bin/nexus-gateway -config configs/config.json

# test runs only the gateway (server) module's tests.
test:
	go test ./... -v

# test-all also runs the client SDK's tests (a separate Go module in
# sdk/), using go.work to resolve both from a single place.
test-all:
	go test ./... ./sdk/... -v

vet:
	go vet ./... ./sdk/...

fmt:
	gofmt -l .
