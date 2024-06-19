# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y wget build-essential pkg-config tcpdump dnsutils

# install app dependencies
RUN apt-get install -y xz-utils curl git

# install ASP.NET Core 7 SDK and libmsquic
RUN curl https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb --output packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb && \
    apt-get update && apt-get install -y dotnet-sdk-7.0 libmsquic

# download source code
RUN wget https://download.technitium.com/dns/archive/10.0.1/DnsServerPortable.tar.gz

# extract the source code
RUN mkdir -p /technitium && tar -xf DnsServerPortable.tar.gz -C /technitium
RUN mkdir -p /var/cache/technitium

# copy the start script
COPY --chown=root:root technitium.sh /etc/technitium/start.sh
