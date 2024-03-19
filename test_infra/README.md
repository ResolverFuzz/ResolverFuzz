# 1. Testing Infrastructure

The testing infrastructure is implemented in Python based on Docker. As demonstrated in Section 4.1 of our [ResolverFuzz Paper](https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-qifan) (and Figure 12 in the [extended version](https://arxiv.org/abs/2310.03202)), we tested the testing infrastructure under 4 modes.

- `main_cdns.py`: Conditional DNS (CDNS) without fallback mode 
- `main_cdns_fallback.py`: CDNS with fallback mode
- `main_fwd_global.py`: Forward-only mode
- `main_recursive.py`: Recursive-only monde

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

where `unit_no` refers the number of the current unit.

