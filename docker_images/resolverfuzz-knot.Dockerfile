# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y wget build-essential pkg-config tcpdump dnsutils

# install app dependencies
RUN apt-get install -y xz-utils automake libtool gnutls-dev liburcu-dev liblmdb-dev libedit-dev meson ninja-build cmake libuv1-dev luajit libluajit-5.1-dev socat libfstrm-dev libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler

# download source code
RUN wget https://secure.nic.cz/files/knot-dns/knot-3.1.8.tar.xz & \
    wget https://secure.nic.cz/files/knot-resolver/knot-resolver-5.5.0.tar.xz

# extract the source code
RUN tar -xf knot-3.1.8.tar.xz & tar -xf knot-resolver-5.5.0.tar.xz

# build from source code
RUN cd knot-3.1.8 && autoreconf -i -f && ./configure && make -j4 && make install
RUN cd knot-resolver-5.5.0 && meson build_dir --prefix=/tmp/kr --default-library=static && ninja -C build_dir && ninja install -C build_dir
RUN mkdir -p /etc/knot-resolver/ && mkdir -p /var/cache/knot/
