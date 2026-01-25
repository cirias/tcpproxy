.PHONY: build docker_image test_tun_docker server client gdb_client

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/tproxyt
	GOOS=linux GOARCH=arm GOARM=7 go build -o tproxyt_armv7 ./cmd/tproxyt

transport.test: ./transport/*.go
	CGO_ENABLED=0 go test ./transport -c

test_tun:
	./transport.test -test.run TestTun -logtostderr

test_tun_docker: docker_image
	docker run --rm -it --cap-add NET_ADMIN -v $(shell pwd):/app -w /app tproxy go test -v -run TestTun ./transport

docker_image:
	docker build ./docker -t tproxy

server:
	./tproxyt -logtostderr -v 1 -mode server -cacert ssl/ca_cert.pem -cert ssl/server_cert.pem -key ssl/server_key.pem -secret milk -tunip 192.168.200.1/24
	ip addr add 192.168.200.1/24 dev tun0
	ip link set dev tun0 up
	iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

client:
	./tproxyt -logtostderr -v 1 -mode client -cacert ssl/ca_cert.pem -raddr 172.17.0.2:443 -secret milk -sname www.example.com -tunip 192.168.200.2/24 -tunmockip 192.168.200.128 -tunproxyport 12345
	ip addr add 192.168.200.2/24 dev tun0
	ip link set dev tun0 up
	ip rule add not fwmark 0x00100 table 400
	ip rule add lookup main suppress_prefixlength 0
	ip route add table 400 default dev tun0 scope link

# outdated
gdb_client:
	gdb --args ./tproxyc -logtostderr -v 1 -cacert ssl/ca_cert.pem -raddr 172.17.0.2:443 -secret milk -sname www.example.com -tunip 192.168.200.2/24 -tunproxyport 12345

docker_run_build:
	docker run --rm -it -v $(shell pwd):/app -w /app golang:1.18-bullseye bash

build-race:
	go build -race ./cmd/tproxyt
