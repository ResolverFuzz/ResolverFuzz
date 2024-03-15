# (Optional) 0.4: Local Nameserver 

We implemented a local nameserver in Go to avoid possible effects on other remote nameservers. Installation of this local nameserver is optional, and will not affect the performance of ResolverFuzz. 

## 0.4.1: Install Go

Install the Go compiler as [instructed](https://go.dev/doc/install). 

## 0.4.2: Check the Docker network interface

Same with [0.3: Docker Network Configuration](https://github.com/ResolverFuzz/ResolverFuzz/tree/main?tab=readme-ov-file#03-docker-network-configuration), the Docker network interface name is required here. It will be required as an argument during the execution of the local nameserver.

## 0.4.3: Compile the Local Nameserver

Change the terminal directory to the current folder: 

```bash
cd local_ns
```

Then, initialize the packet dependencies for the local nameserver, and compile it:

```bash
go mod init local_ns
go mod tidy
go build -o local_ns local_ns.go
```

The executable binary `local_ns` will be created.

## 0.4.4: Run the Local Nameserver

Finally, run the executable with two arguments. The first one is the network interface of the Docker network, and the second one is the zone file in JSON format:

```bash
sudo ./local_ns [network_interface] [zone_file]
```

For example, on our workstation, the command will be :

```bash
sudo ./local_ns br-35582c1d0a12 test-zone.json
```

Keep it running on the background during the execution of `ResolverFuzz` so that all the NS referral queries for root servers, `.com` TLDs and attacker-controlled domains (i.e., `qifanzhang.com` and its sub-domains) will be answered locally by this program.