# 1. Testing Infrastructure

The testing infrastructure is implemented in Python based on Docker. As demonstrated in Section 4.1 of our [ResolverFuzz Paper](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-qifan) (and Figure 12 in the [extended version](https://arxiv.org/abs/2310.03202)), we tested the testing infrastructure under 4 modes.

- `main_cdns.py`: Conditional DNS (CDNS) without fallback mode 
- `main_cdns_fallback.py`: CDNS with fallback mode
- `main_fwd_global.py`: Forward-only mode
- `main_recursive.py`: Recursive-only mode

## 1.1: Switch conda environment

To run the scripts, we first need to switch to the conda environment named `resolverfuzz` set in Step [0.1](https://github.com/ResolverFuzz/ResolverFuzz/tree/main?tab=readme-ov-file#01-software-dependencies):

```bash
conda activate resolverfuzz
```

And then, get the path towards the Python interpreter of the `resolverfuzz` environment:

```bash
which python
```

## 1.2: Run the script

The scripts could be easily run without any arguments:

```bash
# This command has to be executed in `test_infra` folder. If you are at the root directory of the repo, use the following command to switch:
#   cd ./test_infra
sudo /path/to/resolverfuzz/bin/python main_[cdns, cdns_fallback, fwd_global, recursive].py 
```

`sudo` privilege is required here since we need to control the Docker and network infrastructure of the system. Replace `/path/to/resolverfuzz/bin/python` with the path we got from the command `which python` in Step [1.1](https://github.com/ResolverFuzz/ResolverFuzz/blob/main/test_infra/README.md#11-switch-conda-environment). 

## Script arguments

The scripts offer the following customized arguments during execution. You can check the options via `-h` option for each script:

```bash
sudo /path/to/resolverfuzz/bin/python main_[cdns, cdns_fallback, fwd_global, recursive].py -h
```

In detail: 

- `--disable_bind9`, `--disable_unbound`, `--disable_knot`, `--disable_powerdns`, `--disable_technitium` and `--disable_maradns`: Disable the testing of BIND 9, Unbound, Knot Resolver, PowerDNS, Techinitium DNS or MaraDNS during the execution.
  - `--disable_knot`, `--disable_powerdns`, `--disable_technitium` and `--disable_maradns` options are not available in `main_cdns_fallback.py` since Knot Resolver, PowerDNS, Techinitium DNS and MaraDNS do not support CDNS with fallback mode.
- `--debug`: enable the debug mode so that the program will be single-processed instead of multi-processed.
- `--unit_size`: # units deployed and tested during execution. It could set in the range between 1 and 50. 
  - default: `5`
- `--payload_num`: # payloads to be tested in each unit
  - suggested less than 1000 since the efficiency may decay when too many rounds have been executed.
  - default: `5`
- `--res_folder`: the folder to stare fuzzing results
  - Default: `./[cdns, cdns_fallback, fwd, recursive]_test_res/`

## IP address assignment

|            Role            |      IP address      |
| :------------------------: | :------------------: |
|           BIND 9           |  172.22.1.[unit_no]  |
|          Unbound           |  172.22.2.[unit_no]  |
|          PowerDNS          |  172.22.3.[unit_no]  |
|       Knot Resolver        |  172.22.4.[unit_no]  |
|          MaraDNS           |  172.22.5.[unit_no]  |
|       Technitium DNS       |  172.22.6.[unit_no]  |
|      DNSTap Listener       | 172.22.50.[unit_no]  |
|     Attacker's client      | 172.22.101.[unit_no] |
| Attacker-ctrl'd nameserver | 172.22.201.[unit_no] |

where `unit_no` refers to the number of the current unit.

## Result structure

Once the testing is finished, you will get the results of testing in the structure:

```
./[cdns, cdns_fallback, fwd, recursive]_test_res/[unit_no]/[round_no]/[dns_sw_name]/...
```

where `unit_no` refers to the number of a specific unit, `round_no` refers to the round number of a specific test, and `dns_sw_name` refers to the results of which DNS software (`bind9`, `unbound`, `powerdns`, `knot`, `maradns` or `technitium`) are stored in this folder. 

For example, suppose the execution of the following command is completed:

```bash
sudo /path/to/resolverfuzz/bin/python main_cdns.py --unit_size 2 --payload_num 2
```

Then, the results will be stored in `./cdns_test_res` in the following structure:

```
./cdns_test_res
├── 0
│   ├── 0
│   │   ├── auth_payload.txt
│   │   ├── bind9
│   │   │   ├── bind.log
│   │   │   ├── named_dump.db
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── dnstap
│   │   ├── knot
│   │   │   ├── knot.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── maradns
│   │   │   ├── maradns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── powerdns
│   │   │   ├── powerdns.cache.db
│   │   │   ├── powerdns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── query.txt
│   │   ├── stats_record.txt
│   │   ├── technitium
│   │   │   ├── cache.json
│   │   │   ├── log.txt
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   └── unbound
│   │       ├── response.txt
│   │       ├── tcpdump.pcap
│   │       ├── unbound.cache.db
│   │       └── unbound.log
│   ├── 1
│   │   ├── auth_payload.txt
│   │   ├── bind9
│   │   │   ├── bind.log
│   │   │   ├── named_dump.db
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── dnstap
│   │   ├── knot
│   │   │   ├── knot.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── maradns
│   │   │   ├── maradns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── powerdns
│   │   │   ├── powerdns.cache.db
│   │   │   ├── powerdns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── query.txt
│   │   ├── stats_record.txt
│   │   ├── technitium
│   │   │   ├── cache.json
│   │   │   ├── log.txt
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   └── unbound
│   │       ├── response.txt
│   │       ├── tcpdump.pcap
│   │       ├── unbound.cache.db
│   │       └── unbound.log
│   └── 2
│       ├── auth_payload.txt
│       ├── bind9
│       │   ├── bind.log
│       │   ├── named_dump.db
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── dnstap
│       ├── knot
│       │   ├── knot.log
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── maradns
│       │   ├── maradns.log
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── powerdns
│       │   ├── powerdns.cache.db
│       │   ├── powerdns.log
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── query.txt
│       ├── stats_record.txt
│       ├── technitium
│       │   ├── cache.json
│       │   ├── log.txt
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       └── unbound
│           ├── response.txt
│           ├── tcpdump.pcap
│           ├── unbound.cache.db
│           └── unbound.log
├── 1
│   ├── 0
│   │   ├── auth_payload.txt
│   │   ├── bind9
│   │   │   ├── bind.log
│   │   │   ├── named_dump.db
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── dnstap
│   │   ├── knot
│   │   │   ├── knot.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── maradns
│   │   │   ├── maradns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── powerdns
│   │   │   ├── powerdns.cache.db
│   │   │   ├── powerdns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── query.txt
│   │   ├── stats_record.txt
│   │   ├── technitium
│   │   │   ├── cache.json
│   │   │   ├── log.txt
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   └── unbound
│   │       ├── response.txt
│   │       ├── tcpdump.pcap
│   │       ├── unbound.cache.db
│   │       └── unbound.log
│   ├── 1
│   │   ├── auth_payload.txt
│   │   ├── bind9
│   │   │   ├── bind.log
│   │   │   ├── named_dump.db
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── dnstap
│   │   ├── knot
│   │   │   ├── knot.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── maradns
│   │   │   ├── maradns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── powerdns
│   │   │   ├── powerdns.cache.db
│   │   │   ├── powerdns.log
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   ├── query.txt
│   │   ├── stats_record.txt
│   │   ├── technitium
│   │   │   ├── cache.json
│   │   │   ├── log.txt
│   │   │   ├── response.txt
│   │   │   └── tcpdump.pcap
│   │   └── unbound
│   │       ├── response.txt
│   │       ├── tcpdump.pcap
│   │       ├── unbound.cache.db
│   │       └── unbound.log
│   └── 2
│       ├── auth_payload.txt
│       ├── bind9
│       │   ├── bind.log
│       │   ├── named_dump.db
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── dnstap
│       ├── knot
│       │   ├── knot.log
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── maradns
│       │   ├── maradns.log
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── powerdns
│       │   ├── powerdns.cache.db
│       │   ├── powerdns.log
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       ├── query.txt
│       ├── stats_record.txt
│       ├── technitium
│       │   ├── cache.json
│       │   ├── log.txt
│       │   ├── response.txt
│       │   └── tcpdump.pcap
│       └── unbound
│           ├── response.txt
│           ├── tcpdump.pcap
│           ├── unbound.cache.db
│           └── unbound.log
└── log.dnstap
```

### Explanation of results

In the given example of `./cdns_test_res` above:

- `auth_payload.txt` is the generated payload deployed on the nameserver, stored in both hexadecimal and JSON format.
- `query.txt` is the generated query payload to be sent on the client, stored in hexadecimal format.
- `stats_record.txt` is used to record the current testing status in the current unit, including:
  - total time consumed
  - total payloads tested
  - average testing latency 
  - average testing throughput
- `log.dnstap` stores the log from DNSTap listener.
- `[dns_sw_name]/response.txt` records the query result of the related DNS software
- `[dns_sw_name]/tcpdump.pcap` stores network traffic in the docker container of the related DNS software during the test
- Logs of DNS software are stored in:
  - `bind9/bind.log`
  - `knot/knot.log`
  - `maradns/maradns.log`
  - `powerdns/powerdns.log`
  - `technitium/log.txt`
  - `unbound/unbound.log`
- Cache dump of DNS software are stored in:
  - `bind9/named_dump.db`
  - `powerdns/powerdns.cache.db`
  - `technitium/cache.json`
  - `unbound/unbound.cache.db`
