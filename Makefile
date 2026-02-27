.PHONY: test test-go test-python test-go-race test-go-cover lint clean setup-python-dev

test: test-go test-python

test-go:
	cd gateway && go test -count=1 ./...

test-go-race:
	cd gateway && go test -race -count=1 ./...

test-go-cover:
	cd gateway && go test -coverprofile=coverage.out ./... && \
		go tool cover -func=coverage.out && \
		echo "---" && \
		go tool cover -func=coverage.out | grep total

PYTHON ?= python3

setup-python-dev:
	cd sdk/python && $(PYTHON) -m pip install -e ".[dev]"

test-python:
	cd sdk/python && $(PYTHON) -m pytest tests/ -v

lint-go:
	cd gateway && go vet ./...

clean:
	rm -f gateway/coverage.out gateway/gateway gateway/godemo-gateway
