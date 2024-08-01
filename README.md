# ResolverFuzz
<p align="center">
	<img src="./figs/resolverfuzz_logo.webp" alt="resolverfuzz_logo" width="50%"/>
</p>	

This repository is the official repository for [ResolverFuzz](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-qifan) published on the 33rd USENIX Security Symposium (USENIX Security 2024). The extended version of this paper is available on [ArXiv](https://arxiv.org/abs/2310.03202). 

`ResolverFuzz` is a grammar-based blackbox fuzzing tool designed to detect non-crash vulnerabilities in DNS software automatically/semi-automatically via differential analysis among different DNS software. In total, we identified 23 vulnerabilities with 19 confirmed and 15 CVEs assigned. 

This artifact has been awarded with [USENIX Badge](https://secartifacts.github.io/usenixsec2024/badges) **Artifacts Available** and **Artifacts Functional** by [USENIX Security 2024 Artifact Evaluation Committee (AEC)](https://www.usenix.org/conference/usenixsecurity24/call-for-artifacts#evaluation-information).

<p align="center">   
  <img src="./figs/usenixbadges-available.png"/>   
  <img src="./figs/usenixbadges-functional.png"/>  
</p>

# Cite `ResolverFuzz`

```bibtex
@inproceedings{zhang2024resolverfuzz, 
    year = {2024}, 
    author = {Zhang, Qifan and Bai, Xuesong and Li, Xiang and Duan, Haixin and Li, Qi and Li, Zhou}, 
    title = {{ResolverFuzz: Automated Discovery of DNS Resolver Vulnerabilities with Query-Response Fuzzing}}, 
    booktitle = {Proceedings of the 33rd USENIX Security Symposium}, 
    series = {USENIX Security '24}
}
```

# List of DNS Software Tested

|    Software    | Version  |                         Docker Image                         | Dockerfile                                                   |
| :------------: | :------: | :----------------------------------------------------------: | ------------------------------------------------------------ |
|      BIND      |  9.18.0  | [qifanz/resolverfuzz-bind9:9.18.0](https://hub.docker.com/layers/qifanz/resolverfuzz-bind9/9.18.0/images/sha256-2db8dbdedcfbea53cd590318befb9602c50f36d5fe8f08a75803fa471dfb55ca?context=repo) | [resolverfuzz-bind9.Dockerfile](./docker_images/resolverfuzz-bind9.Dockerfile) |
|    Unbound     |  1.16.0  | [qifanz/resolverfuzz-unbound:1.16.0](https://hub.docker.com/layers/qifanz/resolverfuzz-unbound/1.16.0/images/sha256-fca2317edd6a53f8540b0dfeb39c6732f90392380c3fb33e669b2444ace1a016?context=repo) | [resolverfuzz-unbound.Dockerfile](./docker_images/resolverfuzz-unbound.Dockerfile) |
| Knot Resolver  |  5.5.0   | [qifanz/resolverfuzz-knot:5.5.0](https://hub.docker.com/layers/qifanz/resolverfuzz-knot/5.5.0/images/sha256-a2b309b579dff947073ca8a0a6ff4f6890948e75584afac5fd701baf0922d597?context=repo) | [resolverfuzz-knot.Dockerfile](./docker_images/resolverfuzz-knot.Dockerfile) |
|    PowerDNS    |  4.7.0   | [qifanz/resolverfuzz-powerdns:4.7.0](https://hub.docker.com/layers/qifanz/resolverfuzz-powerdns/4.7.0/images/sha256-071af598b8305e70d7fe932af2ef27e6d48f96b68405229bc35a1b0f4675377e?context=repo) | [resolverfuzz-powerdns.Dockerfile](./docker_images/resolverfuzz-powerdns.Dockerfile) |
|    MaraDNS     | 3.5.0022 | [qifanz/resolverfuzz-maradns:3.5.0022](https://hub.docker.com/layers/qifanz/resolverfuzz-maradns/3.5.0022/images/sha256-32d5d0d6ba521cdcc3a12f5ecf497f51353e151da1dc02b05f832dbfa0db6739?context=repo) | [resolverfuzz-maradns.Dockerfile](./docker_images/resolverfuzz-maradns.Dockerfile) |
| Technitium DNS |  10.0.1  | [qifanz/resolverfuzz-technitium:10.0.1](https://hub.docker.com/layers/qifanz/resolverfuzz-technitium/10.0.1/images/sha256-03fa54cc6827c3d908a7767e3c1c0eac575ad126970d17f23861e7a8bdba9468?context=repo) | [resolverfuzz-technitium.Dockerfile](./docker_images/resolverfuzz-technitium.Dockerfile) |

# 0. Environment and Dependencies

## Hardware Environment

The hardware specs of our workstation for `ResolverFuzz` development and testing are: 

- CPU: AMD Ryzen 5950X
- Memory: 128 GB
- Disk space: 1TB SSD (for OS) + 2TB SSD (for result storage) 

`ResolverFuzz` is configurable to fit workstations with different hard specs to boost the maximum performance. 

## 0.1: Software Dependencies

`ResolverFuzz` is developed and tested on Ubuntu 22.04 with Python 3.8  and Docker Engine. To set up the software dependencies, you first need to [install Docker Engine](https://docs.docker.com/engine/install/ubuntu/) and [install Anaconda](https://docs.anaconda.com/free/anaconda/install/linux/). 

**Note**: 

- After installation of Docker Engine, it's recommended to [manage Docker as a non-root use](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user). With this setting, `docker` commands don't have to be prefaced with `sudo`. Otherwise, all the `docker` commands are needed to be prefaced with `sudo` privilege.  

Then, the Python environment named `resolverfuzz` could be imported from [environment.yml](https://github.com/ResolverFuzz/ResolverFuzz/blob/main/environment.yml) via the command:

```bash
conda env create -n resolverfuzz --file environment.yml
```

## 0.2: Pulling Docker Images from Docker Hub

After installing the Docker Engine, Docker images ("images") are required to be pulled from the Docker hub. All the Docker containers ("containers") are created from those images.

First, we need to first pull images of 6 DNS software, and tag them for local use:

```bash
docker pull qifanz/resolverfuzz-bind9:9.18.0
docker pull qifanz/resolverfuzz-unbound:1.16.0
docker pull qifanz/resolverfuzz-knot:5.5.0
docker pull qifanz/resolverfuzz-powerdns:4.7.0
docker pull qifanz/resolverfuzz-maradns:3.5.0022
docker pull qifanz/resolverfuzz-technitium:10.0.1

docker tag qifanz/resolverfuzz-bind9:9.18.0 bind9:9.18.0
docker tag qifanz/resolverfuzz-unbound:1.16.0 unbound:1.16.0
docker tag qifanz/resolverfuzz-knot:5.5.0 knot:5.5.0
docker tag qifanz/resolverfuzz-powerdns:4.7.0 powerdns:4.7.0
docker tag qifanz/resolverfuzz-maradns:3.5.0022 maradns:3.5.0022
docker tag qifanz/resolverfuzz-technitium:10.0.1 technitium:10.0.1
```

Then, we need to pull the images of the attacker client, the authoritative server and DNSTap Listener:

```bash
docker pull qifanz/resolverfuzz-dnstap-listener
docker pull qifanz/resolverfuzz-attacker
docker pull qifanz/resolverfuzz-auth-srv

docker tag qifanz/resolverfuzz-dnstap-listener dnstap-listener
docker tag qifanz/resolverfuzz-attacker attacker
docker tag qifanz/resolverfuzz-auth-srv auth-srv
```

## 0.3: Docker Network Configuration

All the containers are connected to a Docker network named `test_net_batch`. All the queries and responses generated by ResolverFuzz are transmitted via the Docker network. To create a Docker network named `test_net_batch` with a subnet 172.22.0.0/16, run the command: 

```bash
docker network create --subnet "172.22.0.0/16" test_net_batch
```

Since the authoritative server is implemented to send response packets via monitoring network traffic, enabling ICMP will automatically send back ICMP packets before our generated DNS responses are sent back. In consequence, the resolvers will never receive the packets with generated DNS responses. Therefore, we need to drop all the ICMP packets on the network. 

To drop all the ICMP packets, We need to first check the interface of the Docker network via the command:

```bash
ip addr
```

Then, all the network interfaces will be displayed. We need to identify the interface with the IP range 172.22.0.1/16 assigned. For example, on our workstation, we could find:

```
6: br-0ed6b350123e: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:6e:e1:47:92 brd ff:ff:ff:ff:ff:ff
    inet 172.22.0.1/16 brd 172.22.255.255 scope global br-0ed6b350123e
       valid_lft forever preferred_lft forever
```

In this case, the network interface in the OS for the Docker network `test_net_batch` is `br-0ed6b350123e`. Then, we drop all the ICMP packets on the network interface with the command:

```bash
sudo iptables -I FORWARD -i [network_interface] -p icmp -j DROP
```

On our workstation, for example, the command will be:

```bash
sudo iptables -I FORWARD -i br-0ed6b350123e -p icmp -j DROP
```

## (Optional) 0.4: Local Nameserver

We implemented a local nameserver to avoid possible effects on other remote nameservers. Installation of this local nameserver is optional, and will not affect the performance of ResolverFuzz. See [README.md](./local_ns/README.md) for instructions. 

# 1: Testing Infrastructure

See [README.md](./test_infra/README.md) for instructions.

# 2: Differential Analysis

See [README.md](./data_process/README.md) for instructions.

# Related Documents

- [Pre-published paper](https://www.usenix.org/system/files/sec23winter-prepub-246-zhang-qifan.pdf)
- [Extended version](https://arxiv.org/pdf/2310.03202)
- [Poster](https://qifanz.com/posters/ndss24-poster-ResolverFuzz.pdf) presented on NDSS 2024
- [Artifact Appendix](./docs/ResolverFuzz_AE.pdf)

# License

The artifacts of ResolverFuzz, including this repository, are licensed under the MIT license. See [LICENSE](https://github.com/ResolverFuzz/ResolverFuzz/blob/main/LICENSE) for details.

