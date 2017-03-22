# Squid Cache Extractor
Forensic artifact extraction from squid proxy cache and secondary log sources:

- [`cache_dir`](data) contents parsing 
- `cache_dir/swap.state` parsing
- `store.log` parsing

## Usage

### Dependencies

## Functions

### cache-extractor

### parse-swap-state

### parse-store-log

## Output
json and csv output is designed to be indexed by log aggregation storage & visualization utlities such as elasticseach/kibana. See [squid-cache-extractor-logstash](https://github.com/wjwoodson/squid-cache-extractor-logstash)
