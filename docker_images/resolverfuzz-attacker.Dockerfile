# syntax=docker/dockerfile:1
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y wget build-essential pkg-config tcpdump dnsutils

# install app dependencies
RUN apt-get install -y python3 python3-pip

# install python libraries
RUN pip3 install scapy
