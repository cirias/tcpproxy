#!/bin/bash

set -xe

# Create new chain
iptables -t nat -N TCPPROXY
# iptables -t nat -X TCPPROXY
# iptables -t mangle -N TCPPROXY

# Ignore your server's addresses
# It's very IMPORTANT, just be careful.
iptables -t nat -A TCPPROXY -d 123.123.123.123 -j RETURN

# Ignore LANs and any other addresses you'd like to bypass the proxy
# See Wikipedia and RFC5735 for full list of reserved networks.
# See ashi009/bestroutetb for a highly optimized CHN route list.
iptables -t nat -A TCPPROXY -d 0.0.0.0/8 -j RETURN
iptables -t nat -A TCPPROXY -d 10.0.0.0/8 -j RETURN
iptables -t nat -A TCPPROXY -d 127.0.0.0/8 -j RETURN
iptables -t nat -A TCPPROXY -d 169.254.0.0/16 -j RETURN
iptables -t nat -A TCPPROXY -d 172.16.0.0/12 -j RETURN
iptables -t nat -A TCPPROXY -d 192.168.0.0/16 -j RETURN
iptables -t nat -A TCPPROXY -d 224.0.0.0/4 -j RETURN
iptables -t nat -A TCPPROXY -d 240.0.0.0/4 -j RETURN

# Anything else should be redirected to shadowsocks's local port
iptables -t nat -A TCPPROXY -p tcp -j REDIRECT --to-ports 12345

# # Add any UDP rules
# ip route add local default dev lo table 100
# ip rule add fwmark 1 lookup 100
# iptables -t mangle -A TCPPROXY -p udp --dport 53 -j TPROXY --on-port 12345 --tproxy-mark 0x01/0x01

# Apply the rules
# iptables -t nat -A PREROUTING -p tcp -j TCPPROXY
iptables -t nat -A OUTPUT -p tcp -j TCPPROXY
# iptables -t nat -D OUTPUT -p tcp -j TCPPROXY
# iptables -t mangle -A PREROUTING -j TCPPROXY
