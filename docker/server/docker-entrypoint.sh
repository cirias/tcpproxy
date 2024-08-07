#!/bin/bash

set -x
set -e

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

exec "$@" &
pid=$!

sleep 2

ip addr add 172.20.1.1/24 dev tun0
ip link set dev tun0 up
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

wait $pid
