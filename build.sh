#!/bin/bash

# Check if docker is installed
if ! [ -x "$(command -v docker)" ]; then
  echo "Error: Docker is not installed." >&2
  exit 1
fi

# Build docker images

cd docker_images
echo "Building docker images..."

# Bind 9 9.18.0
sudo docker build -f resolverfuzz-bind9.Dockerfile -t resolverfuzz-bind9:9.18.0 .
echo "[1/9] Building docker image resolverfuzz-bind9 finished..."

# Unbound 1.16.0
sudo docker build -f resolverfuzz-unbound.Dockerfile -t resolverfuzz-unbound:1.16.0 .
echo "[2/9] Building docker image resolverfuzz-unbound finished..."

# Knot Resolver 5.5.0
sudo docker build -f resolverfuzz-knot.Dockerfile -t resolverfuzz-knot:5.5.0 .
echo "[3/9] Building docker image resolverfuzz-knot finished..."

# PowerDNS Recursor 4.7.0
sudo docker build -f resolverfuzz-powerdns.Dockerfile -t resolverfuzz-powerdns:4.7.0 .
echo "[4/9] Building docker image resolverfuzz-powerdns finished..."

# MaraDNS 3.5.0022
sudo docker build -f resolverfuzz-maradns.Dockerfile -t resolverfuzz-maradns:3.5.0022 .
echo "[5/9] Building docker image resolverfuzz-maradns finished..."

# Technitium DNS 10.0.1
sudo docker build -f resolverfuzz-technitium.Dockerfile -t resolverfuzz-technitium:10.0.1 .
echo "[6/9] Building docker image resolverfuzz-technitium finished..."

# DNSTAP Listener
sudo docker build -f resolverfuzz-dnstap-listener.Dockerfile -t resolverfuzz-dnstap-listener:latest .
echo "[7/9] Building docker image resolverfuzz-dnstap-listener finished..."

# Attacker
sudo docker build -f resolverfuzz-attacker.Dockerfile -t resolverfuzz-attacker:latest .
echo "[8/9] Building docker image resolverfuzz-attacker finished..."

# Authoritative Server
sudo docker tag resolverfuzz-attacker:latest resolverfuzz-auth-srv:latest
echo "[9/9] Building docker image resolverfuzz-auth-srv finished..."
