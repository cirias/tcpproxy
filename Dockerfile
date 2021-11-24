FROM debian:latest

RUN apt-get update && \
  apt-get install -y \
    iptables \
    iproute2 \
    curl \
    tcpdump \
    iperf3 \
    procps

CMD ["/bin/bash"]
