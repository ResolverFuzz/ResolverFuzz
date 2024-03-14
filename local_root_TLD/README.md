# (Optional) 0.4: Local Root and TLD Nameserver

We implemented a local root and TLD server to avoid possible effects on other remote name servers in Go. Installation of this local root and TLD server is optional, and will not affect the performance of ResolverFuzz. 

## 0.4.1: Install Go

Install the Go compiler as [instructed](https://go.dev/doc/install). 

## 0.4.2: Check the Docker network interface

Same with [0.3: Docker Network Configuration](https://github.com/ResolverFuzz/ResolverFuzz/tree/main?tab=readme-ov-file#03-docker-network-configuration), the Docker network interface name is required here. After checking the Docker network interface name, it is required to fill it in the value assignment of `deviceL` in Line 30 of [local_root_TLD.go](https://github.com/ResolverFuzz/ResolverFuzz/blob/main/local_root_TLD/local_root_TLD.go):

```go
deviceL = "network_interface"
```

For example, on our workstation, the value of `deviceL` will be assigned as:

```go
deviceL = "br-35582c1d0a12"
```

## 0.4.3: Compile the Local Nameserver

Change to the current folder: 

```bash
cd local_root_TLD
```

Then, initialize the packet dependencies for the local nameserver, and compile it:

```bash
go mod init local_authority_server
go mod tidy
go build -o local_authority_server local_authority_server.go
```

The executable binary `local_authority_server` will be created.

## 0.4.4: Run the Local Nameserver

Finally, run the executable with the zone file [test-zone.json](https://github.com/ResolverFuzz/ResolverFuzz/blob/main/local_root_TLD/test-zone.json) as input:

```bash
sudo ./local_authority_server test-zone.json
```

Keep it running on the background during the execution of `ResolverFuzz` so that all the NS referral queries for root servers, `.com` TLDs and attacker-controlled domains (i.e., `qifanzhang.com` and its sub-domains) will be answered locally.