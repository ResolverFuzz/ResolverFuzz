# Data Process

## Convert query & response in the results

All the seeds tested, along with the responses from the resolvers, are stored in a byte format, which is difficult for human to interpret. To address this, we have developed scripts that convert all query and response data into a format that is easily readable by humans.

```shell
# Activate conda environment
conda activate resolverfuzz

# Parse all queries
python parser_query.py --res_folder /path/to/results

# Parse all responses
python parser_response.py --res_folder /path/to/results
```
