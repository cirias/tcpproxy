# Use an official Go runtime as a parent image
FROM golang:1.20-bookworm as builder

# Set the working directory in the builder container
WORKDIR /src

# Copy go.mod and go.sum files to the workspace
COPY go.mod go.sum ./

# Download all dependencies.
RUN go mod download

# Copy the source from the current directory to the working Directory in the builder container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o tproxyt ./cmd/tproxyt

FROM debian:bookworm

WORKDIR /root/

RUN apt update && apt install -y \
  iproute2 \
  iptables

COPY ./docker/server/docker-entrypoint.sh ./

COPY --from=builder /src/tproxyt /usr/bin/

ENTRYPOINT ["./docker-entrypoint.sh"]
