FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TOR_CONTROL_PORT=9051
ENV TOR_SOCKS_PORT=9050

RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    build-essential cmake libssl-dev \
    git \
    tor \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    liboqs-python \
    cryptography \
    pysocks \
    stem \
    argon2-cffi

WORKDIR /hyperion
COPY . .

RUN pip3 install -e .

RUN mkdir -p /root/.hyperion

RUN chmod +x /hyperion/main.py

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9999

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]