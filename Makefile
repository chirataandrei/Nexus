.PHONY: build run test test-all test-race bench demo vet fmt agentctl

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

# test-race runs everything under the Go race detector (what CI runs).
test-race:
	go test -race -count=1 ./... ./sdk/...

# bench measures the latency/throughput the gateway adds over a direct
# call to a local fake upstream.
bench:
	go run ./cmd/nexus-bench -c 50 -d 10s

# demo runs a ~60s end-to-end walkthrough against a fake upstream.
demo:
	DEMO_PAUSE=2 ./scripts/demo.sh
