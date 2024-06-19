# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y wget build-essential pkg-config tcpdump dnsutils

# install app dependencies
RUN apt-get install -y libuv1-dev libnghttp2-dev libssl-dev libcap-dev \
    libfstrm-dev libprotobuf-dev libprotobuf-c-dev libidn2-dev \
    libkrb5-dev libmaxminddb-dev xz-utils socat \
    protobuf-c-compiler libjemalloc-dev tcpdump golang-github-dnstap-golang-dnstap-cli

# download source code
RUN wget https://downloads.isc.org/isc/bind9/9.18.0/bind-9.18.0.tar.xz

# extract the source code
RUN tar -xf bind-9.18.0.tar.xz

# build from source code
RUN cd bind-9.18.0 && ./configure --sysconfdir=/etc/bind/ --enable-dnstap && make -j4 && make install && ldconfig && rndc-confgen -a
