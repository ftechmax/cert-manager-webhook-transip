.PHONY: build test vet fmt clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o webhook .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -f webhook
