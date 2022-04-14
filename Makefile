.PHONY: build test docker_image docker_run

build:
	CGO_ENABLED=0 go build ./cmd/tproxys
	CGO_ENABLED=0 go build ./cmd/tproxyc
	CGO_ENABLED=0 go build ./cmd/tproxyt
	GOOS=linux GOARCH=arm GOARM=7 go build -o tproxys_armv7 ./cmd/tproxys
	GOOS=linux GOARCH=arm GOARM=7 go build -o tproxyc_armv7 ./cmd/tproxyc
	GOOS=linux GOARCH=arm GOARM=7 go build -o tproxyc_armv7 ./cmd/tproxyt

test:
	go test ./transport

docker_image:
	docker build ./docker -t tproxy

docker_run:
	docker run --rm -it --cap-add NET_ADMIN -v $(shell pwd):/app -w /app tproxy bash
