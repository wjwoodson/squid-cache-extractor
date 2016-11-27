# parse-swap-state.py
#
import binascii
import json

# parse an individual 72 byte entry from swap.state
def parse_swap_state_entry(swap_state_entry):

	swap_state_parsed = {}
	
	swap_filen = swap_state_entry[4:8] # swap_filen (host endianness bytes)
	timestamp = swap_state_entry[8:15] # timestamp (host endianness bytes)
	lastref = swap_state_entry[16:23] # lastref (host endianness bytes)
	expires = swap_state_entry[24:31] # expires (host endianness bytes)
	lastmod = swap_state_entry[32:40] # lastmod (host endianness bytes)
	swap_file_sz = swap_state_entry[40:47] # swap_file_sz (host endianness bytes)
	refcount = swap_state_entry[48:49] # refcount (host endianness bytes)
	flags = swap_state_entry[50:52] # flags (host endianness bytes)
	cache_key = swap_state_entry[52:68] # md5 cache_key (hex string)
	
	swap_state_parsed['swap_filen'] = binascii.b2a_hex(swap_filen[::-1])
	swap_state_parsed['meta_cache_key'] = binascii.b2a_hex(cache_key)
	swap_state_parsed['meta_timestamp'] =  int(binascii.b2a_hex(timestamp[::-1]), 16)
	swap_state_parsed['meta_lastref'] =  int(binascii.b2a_hex(lastref[::-1]), 16)
	swap_state_parsed['meta_expires'] = int(binascii.b2a_hex(expires[::-1]), 16)
	swap_state_parsed['meta_lastmod'] = int(binascii.b2a_hex(lastmod[::-1]), 16)
	swap_state_parsed['swap_file_sz'] = int(binascii.b2a_hex(swap_file_sz[::-1]), 16)
	swap_state_parsed['meta_refcount'] = int(binascii.b2a_hex(refcount[::-1]), 16)
	swap_state_parsed['meta_flags'] = int(binascii.b2a_hex(flags[::-1]), 16)

	# return dictionary of fields parsed on ascii/decimal
	return swap_state_parsed

# set cache_dir from which to extract files
cache_dir = "./data/squid3"

# hex byte parse of squid_meta, headers, payload from a cache_file
# open the cache_file on disk and read one enry ata time
with open("%s/swap.state" % cache_dir, 'rb') as swap_state_raw:

                # parse url, headers, payload from cache_file
                swap_state_entry = swap_state_raw.read(72)

		output = open('parse-swap-state.json', 'w')
                # read all file bytes
                while swap_state_entry != "":
			output.write(json.dumps(parse_swap_state_entry(swap_state_entry))+"\n")
			swap_state_entry = swap_state_raw.read(72)
		output.close()
