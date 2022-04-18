FROM debian:latest

RUN apt-get update && \
  apt-get install -y \
    iptables \
    iproute2 \
    iputils-ping \
    telnet \
    curl \
    tcpdump \
    iperf3 \
    procps \
    make \
    gdb \
    tmux

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]

CMD ["/bin/bash"]
