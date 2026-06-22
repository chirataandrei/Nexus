.PHONY: build run test test-all vet fmt agentctl

build:
	go build -o bin/nexus-gateway ./cmd/nexus-gateway

agentctl:
	go build -o bin/nexus-agentctl ./cmd/nexus-agentctl

run: build
	./bin/nexus-gateway -config configs/config.json

# test rulează doar testele modulului gateway (server).
test:
	go test ./... -v

# test-all rulează și testele SDK-ului client (modul Go separat în sdk/),
# folosind go.work pentru a le rezolva pe ambele dintr-un singur loc.
test-all:
	go test ./... ./sdk/... -v

vet:
	go vet ./... ./sdk/...

fmt:
	gofmt -l .
