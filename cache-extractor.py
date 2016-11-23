# cache-extractor.py
#

import os
import md5

# set cache_dir from which to extract files
cache_dir = "./data/squid3"


# hex byte parse of squid_meta, headers, payload from a cache_file
def parse_cache_file(cache_file):
	with open(cache_file, 'rb') as cache_file_raw:
		print(cache_file)
		
		byte = cache_file_raw.read(1)
		str_buff = byte
		payload = b""

		while byte != "":
			# check for \r\n (next header)
			# hex bytes 0d0a = \r\n
			if byte.encode('hex') == "0d":
				byte2 = cache_file_raw.read(1)
				if byte2.encode('hex') == "0a":
					# print buffer
					print(str_buff)
					str_buff = ""
					
					# check for double \r\n (payload)
					word2 = cache_file_raw.read(2)
					if word2.encode('hex') == "0d0a":
						# payload, read to EOF
						payload = cache_file_raw.read()
					else:
						# word2 starts next header
						byte = ""
						str_buff = word2
			
			# append byte to buffer and read another
			str_buff = str_buff + byte
			byte = cache_file_raw.read(1)

		# md5 response payload
		md5sum = md5.new()
		md5sum.update(payload)
		print("payload md5: "+md5sum.hexdigest())		

		# check for gzip file signatures
		# hex bytes 1f8b08 = gzip signature
		if payload.encode('hex')[:6] == "1f8b08":
			decompress_gzip(payload)
		
		# check for zip file signature
		# hex bytes 504b0304 = zip signature (PKZIP archive_1)
		if payload.encode('hex')[:6] == "504b0304":
			decompress_pk(payload)


		# return the parsed cache_file
		return "==== parsed_cache_file data structure"

# parse squid_meta in cache_file header
def parse_squid_meta(squid_meta):
	print("==== parsed squid meta ====")

# decompress a gzipped response payload
def decompress_gzip(response_payload):
	print("==== payload is gzip ====")

# decompress deflate/zip/PK response payload
def decompress_pk(response_payload):
	print("==== payload is zip ====")

# parse out references from response_payload
def parse_references(response_payload):
	print("==== parsed references in payload ====")

# insert record into database
def insert_record(parsed_cache_file):
	pass


##### TESTING #####
parse_cache_file('./data/squid3/00/5D/00005D34')

exit()

# print out the configured cache_dir
print("cache_dir: '%s'" % cache_dir)

# get list of all cache_files
cache_files = []
for path, dirs, files in os.walk(cache_dir):
#	if path != cache_dir:
	for cache_file in files:
		cache_files.append(("%s/%s" % (path, cache_file)))

# iterate through all cache_files to extract squid_meta, headers, and payload
for cache_file in cache_files:
	parse_cache_file(cache_file)
