# Squid Cache Extractor
Forensic artifact extraction from squid3 proxy cache and secondary log sources.

- Parse headers and metadata from cached files residing in a squid [`cache_dir`](data)  
- Parse metadata from binary cache index `cache_dir/swap.state`  
- Parse secondary log data from squid `store.log` file  

## Usage

### Dependencies

## Functions

### cache-extractor

### parse-swap-state

### parse-store-log

## Output
json and csv output is designed to be indexed by log aggregation storage & visualization utlities such as elasticseach/kibana. See [squid-cache-extractor-logstash](https://github.com/wjwoodson/squid-cache-extractor-logstash)
