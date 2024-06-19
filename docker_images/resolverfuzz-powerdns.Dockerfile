# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y wget build-essential pkg-config tcpdump dnsutils

# install app dependencies
RUN apt-get install -y libboost-dev libboost-filesystem-dev libboost-serialization-dev \
    libboost-system-dev libboost-thread-dev libboost-context-dev libboost-test-dev \
    libluajit-5.1-dev libssl-dev libfstrm-dev

# download source code
RUN wget https://downloads.powerdns.com/releases/pdns-recursor-4.7.0.tar.bz2

# extract the source code
RUN tar -xf pdns-recursor-4.7.0.tar.bz2

# build from source code
RUN cd pdns-recursor-4.7.0 && ./configure --sysconfdir=/etc/powerdns/ --enable-dnstap && make -j4 && make install
RUN mkdir -p /var/run/powerdns && mkdir -p /var/run/pdns-recursor

# copy the start script
COPY --chown=root:root powerdns_recursor.sh /start.sh
