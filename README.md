# ResolverFuzz
This repository is the official repository for [ResolverFuzz](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-qifan) published on the 33rd USENIX Security Symposium (USENIX Security 2024). The extended version of this paper is available on [ArXiv](https://arxiv.org/abs/2310.03202). 

`ResolverFuzz` is a grammar-based blackbox fuzzing tool designed to detect non-crash vulnerabilities in DNS software automatically/semi-automatically via differential analysis among different DNS software. In total, we identified 23 vulnerabilities with 19 confirmed and 15 CVEs assigned.

# List of DNS Software Tested

| Software       | Version  | Docker Image                                                 |
| -------------- | -------- | ------------------------------------------------------------ |
| BIND           | 9.18.0   | [qifanz/resolverfuzz-bind9:9.18.0](https://hub.docker.com/layers/qifanz/resolverfuzz-bind9/9.18.0/images/sha256-2db8dbdedcfbea53cd590318befb9602c50f36d5fe8f08a75803fa471dfb55ca?context=repo) |
| Unbound        | 1.16.0   | [qifanz/resolverfuzz-unbound:1.16.0](https://hub.docker.com/layers/qifanz/resolverfuzz-unbound/1.16.0/images/sha256-fca2317edd6a53f8540b0dfeb39c6732f90392380c3fb33e669b2444ace1a016?context=repo) |
| Knot Resolver  | 5.5.0    | [qifanz/resolverfuzz-knot:5.5.0](https://hub.docker.com/layers/qifanz/resolverfuzz-knot/5.5.0/images/sha256-a2b309b579dff947073ca8a0a6ff4f6890948e75584afac5fd701baf0922d597?context=repo) |
| PowerDNS       | 4.7.0    | [qifanz/resolverfuzz-powerdns:4.7.0](https://hub.docker.com/layers/qifanz/resolverfuzz-powerdns/4.7.0/images/sha256-071af598b8305e70d7fe932af2ef27e6d48f96b68405229bc35a1b0f4675377e?context=repo) |
| MaraDNS        | 3.5.0022 | [qifanz/resolverfuzz-maradns:3.5.0022](https://hub.docker.com/layers/qifanz/resolverfuzz-maradns/3.5.0022/images/sha256-32d5d0d6ba521cdcc3a12f5ecf497f51353e151da1dc02b05f832dbfa0db6739?context=repo) |
| Technitium DNS | 10.0.1   | [qifanz/resolverfuzz-technitium:10.0.1](https://hub.docker.com/layers/qifanz/resolverfuzz-technitium/10.0.1/images/sha256-03fa54cc6827c3d908a7767e3c1c0eac575ad126970d17f23861e7a8bdba9468?context=repo) |

# Environment and Dependencies

## Hardware Environment

The hardware specs of our workstation for `ResolverFuzz` development and testing are: 

- CPU: AMD Ryzen 5950X
- Memory: 128 GB
- Disk space: 1TB SSD (for OS) + 2TB SSD (for result storage) 

`ResolverFuzz` is configurable to fit workstations with different hard specs to boost the maximum performance. 

## Software Dependencies

`ResolverFuzz` is developed and tested on Ubuntu 22.04 with Python 3.8  and Docker Engine. To set up the software dependencies, you first need to [install Docker Engine](https://docs.docker.com/engine/install/ubuntu/) and [install Anaconda](https://docs.anaconda.com/free/anaconda/install/linux/). 

**Note**: 

- After installation of Docker Engine, it's recommended to [manage Docker as a non-root use](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user). With this setting, `docker` commands don't have to be prefaced with `sudo`.

Then, the Python environment could be imported from [[environment.yml](https://github.com/ResolverFuzz/ResolverFuzz/blob/main/environment.yml)] via the command:

```bash
conda env create -n dns_docker --file environment.yml
```

## Docker Image

After installing the Docker Engine, docker images are required to be pulled from the Docker hub. 

First, we need to first pull Docker images of 6 DNS software, and tag them for local use:

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

Then, we need to pull Docker images of the attacker client, the authoritative server and DNSTap Listener:

```bash
docker pull qifanz/resolverfuzz-dnstap-listener
docker pull qifanz/resolverfuzz-attacker
docker pull qifanz/resolverfuzz-auth-srv

docker tag qifanz/resolverfuzz-dnstap-listener dnstap-listener
docker tag qifanz/resolverfuzz-attacker attacker
docker tag qifanz/resolverfuzz-auth-srv auth-srv
```



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

# License

The artifacts of ResolverFuzz, including this repository, are licensed under the MIT license. See [LICENSE](https://github.com/ResolverFuzz/ResolverFuzz/blob/main/LICENSE) for details.
