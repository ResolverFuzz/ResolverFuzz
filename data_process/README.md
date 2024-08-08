# Data Process

## Convert query & response in the results

All the seeds tested, along with the responses from the resolvers, are stored in a byte format, which is difficult for human to interpret. To address this, we have developed scripts that convert all query and response data into a format that is easily readable by humans.

```shell
# Activate conda environment
conda activate resolverfuzz

# Switch to the data_process folder if not
cd data_process

# Parse all queries
python parser_query.py --res_folder /path/to/results

# Parse all responses
python parser_response.py --res_folder /path/to/results
```

## Traffic Analysis

During the fuzzing process, we gather all network traffic within the Docker container. By examining this captured data, we can determine whether the resolver's network usage is within acceptable limits or if it is being exploited to initiate a traffic amplification attack.

```shell
cd traffic
conda activate resolverfuzz
python traffic_oracle.py
```

The script will save `packet number ratio` and `packet size ratio` in `csv` format.

## Cache Analysis

In each round of fuzzing, we saved the cache status instantly using software built-in methods. We implemented differential analysis on the cache dump to find inconsistencies. 

Firstly, we have the parser for `Bind 9`, `Unbound`, `PowerDNS` and `Technitium`. Then, we have the `cache_analyzer` to find the differences between those cache statuses. Finally, we have `clustering` and `filters` to implement the functions as described in the paper.

For `clustering.py`, it requires human intervention, so we have separate each code block with `#`. We recommend users to run each block in `IPython`, to grasp the process.
