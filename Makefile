.PHONY: build docker_image docker_run client

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

server:
	./tproxys -logtostderr -cacert ssl/ca_cert.pem -cert ssl/server_cert.pem -key ssl/server_key.pem -secret milk -tunip 192.168.200.1/24

client:
	./tproxyc -logtostderr -cacert ssl/ca_cert.pem -raddr 172.17.0.2:443 -secret milk -sname www.example.com -tunip 192.168.200.2/24 -tunproxyport 12345
