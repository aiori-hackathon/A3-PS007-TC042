FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV DISPLAY=:0

RUN apt-get update && apt-get install -y --no-install-recommends \
    openvswitch-switch \
    openvswitch-common \
    mininet \
    radvd \
    ethtool \
    iproute2 \
    iptables \
    net-tools \
    procps \
    psmisc \
    python3 \
    python3-pip \
    python3-scapy \
    python3-flask \
    xterm \
    x11-xserver-utils \
    xauth \
    iputils-ping \
    traceroute \
    tcpdump \
    ndisc6 \
    nano \
    less \
    socat \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG CACHEBUST=1
COPY . /app

RUN if [ -f /app/docker-entrypoint.sh ]; then chmod +x /app/docker-entrypoint.sh; elif [ -f /app/src/docker-entrypoint.sh ]; then chmod +x /app/src/docker-entrypoint.sh && cp /app/src/docker-entrypoint.sh /app/docker-entrypoint.sh; fi

EXPOSE 5000 8765

ENTRYPOINT ["/app/docker-entrypoint.sh"]
