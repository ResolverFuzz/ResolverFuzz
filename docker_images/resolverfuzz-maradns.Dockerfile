# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y wget build-essential pkg-config tcpdump dnsutils

# install app dependencies
RUN apt-get install -y xz-utils

# download source code
RUN wget https://maradns.samiam.org/download/3.5/3.5.0022/maradns-3.5.0022.tar.xz

# extract the source code
RUN tar -xf maradns-3.5.0022.tar.xz

# build from source code
RUN cd maradns-3.5.0022 && FLAGS='-DIPV6' ./configure && make -j4 && make install
RUN mkdir -p /etc/deadwood/ && mkdir -p /etc/maradns_conf && mkdir -p /var/cache/maradns
