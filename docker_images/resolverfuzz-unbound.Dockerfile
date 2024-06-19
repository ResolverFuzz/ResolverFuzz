# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y wget build-essential pkg-config tcpdump dnsutils

# install app dependencies
RUN apt-get install -y libssl-dev libexpat1-dev \
    libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler \
    golang-github-dnstap-golang-dnstap-cli

# download source code
RUN wget https://nlnetlabs.nl/downloads/unbound/unbound-1.16.0.tar.gz

# extract the source code
RUN tar -xf unbound-1.16.0.tar.gz

# build from source code
RUN cd unbound-1.16.0 && ./configure --sysconfdir=/etc/ --enable-dnstap && make -j4 && make install
