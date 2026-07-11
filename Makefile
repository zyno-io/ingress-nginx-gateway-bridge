IMG ?= ghcr.io/zyno-io/ingress-nginx-gateway-bridge:dev

.PHONY: build test lint fmt vet docker-build helm-lint

build:
	go build ./...

test:
	go test ./...

lint: fmt vet

fmt:
	test -z "$$(gofmt -l .)"

vet:
	go vet ./...

docker-build:
	docker build -t $(IMG) .

helm-lint:
	helm lint charts/ingress-nginx-gateway-bridge
