# TCP Proxy (tcpproxy)

## Overview
`tcpproxy` is a Go-based TCP proxy tool that establishes a secure tunnel between a client and a server. It utilizes a TUN device to intercept network traffic and tunnels it over TLS, effectively acting as a VPN-like solution for TCP connections.

## Architecture
The project operates in two primary modes:
*   **Client (`-mode client`):** Creates a TUN device, intercepts local traffic, wraps it in TLS, and forwards it to the server. It can also perform SNI-based routing.
*   **Server (`-mode server`):** Listens for incoming TLS connections from clients, unwraps the traffic, and forwards it to the destination. It creates a TUN device for routing return traffic.

The core communication logic resides in the `transport` package, which handles packet reading/writing, TLS encryption/decryption, and TCP connection management.

## Key Files & Directories

*   **`cmd/tproxyt/main.go`**: The entry point of the application. Handles command-line flags, TUN device creation, and process initialization (daemonization).
*   **`transport/`**: Contains the core networking logic.
    *   `tun.go`: Handling of TUN device input/output.
    *   `tls_tunnel.go`: Implementation of the TLS tunnel.
    *   `tcp.go`, `tcp_tunnel.go`: TCP connection handling.
    *   `hostmatcher.go`: Logic for matching hosts (e.g., for SNI).
*   **`tcpip/`**: Contains TCP/IP utility functions.
*   **`iptables.sh`**: A helper script to configure `iptables` rules for redirecting traffic to the proxy (transparent proxying).
*   **`Makefile`**: Automation for building, testing, and creating Docker images.
*   **`docker/`**: Docker configuration files for deploying the proxy and related services.

## Build & Run

### Prerequisites
*   Go 1.24+
*   Make (optional)
*   Docker (optional)

### Building
Use the provided `Makefile` to build the binary:
```bash
make build
```
This will create the `tproxyt` binary in the project root.

### Running
**Server:**
```bash
./tproxyt -mode server -cert ssl/server.crt -key ssl/server.key -tunip 192.168.200.1/24 -laddr 0.0.0.0:443 -secret <shared_secret>
```

**Client:**
```bash
./tproxyt -mode client -raddr <server_ip>:443 -tunip 192.168.200.2/24 -tunproxyport 12345 -secret <shared_secret>
```

**Note:** You may need to set up `iptables` rules and routing tables to properly direct traffic through the TUN interface. See `iptables.sh` and the `Makefile` `client`/`server` targets for examples.

## Configuration (Flags)
Key command-line flags (defined in `cmd/tproxyt/main.go`):

*   `-mode`: Operation mode (`server` or `client`).
*   `-secret`: Shared secret for authentication.
*   `-tun`: TUN device name (optional).
*   `-tunip`: IP address for the TUN device (CIDR format).
*   `-foreground`: Run in foreground (default is background/daemonized unless `TP_PROCESS_FOREGROUND` env var is set).
*   `-logtostderr`: Log to standard error (glog flag).

**Client Specific:**
*   `-raddr`: Remote server address.
*   `-sname`: TLS server name (SNI).
*   `-tunmockip`: Mock IP for TCP connections.
*   `-tunproxyport`: Local port to bind the transparent proxy.

**Server Specific:**
*   `-laddr`: Local listening address.
*   `-cert`, `-key`: Paths to TLS certificate and key.
*   `-cacert`: CA certificate for verifying client certs (optional).

## Development
*   **Tests:** Run unit tests with `make transport.test`.
*   **Docker:** Build a Docker image with `make docker_image` and run it with `make docker_run`.
