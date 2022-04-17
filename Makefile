.PHONY: build docker_image docker_run

build:
	CGO_ENABLED=0 go build ./cmd/tproxys
	CGO_ENABLED=0 go build ./cmd/tproxyc
	GOOS=linux GOARCH=arm GOARM=7 go build -o tproxys_armv7 ./cmd/tproxys
	GOOS=linux GOARCH=arm GOARM=7 go build -o tproxyc_armv7 ./cmd/tproxyc

transport.test: ./transport/*.go
	CGO_ENABLED=0 go test ./transport -c

docker_image:
	docker build ./docker -t tproxy

docker_run:
	docker run --rm -it --cap-add NET_ADMIN -v $(shell pwd):/app -w /app tproxy bash
