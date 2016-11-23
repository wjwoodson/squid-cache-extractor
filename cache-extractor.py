# cache-extractor.py
#

import os
import md5
import binascii

# set cache_dir from which to extract files
cache_dir = "./data/squid3"

# hex byte parse of squid_meta, headers, payload from a cache_file
def parse_cache_file(cache_file):

	# open the cache_file on disk and read
	with open(cache_file, 'rb') as cache_file_raw:
		print(cache_file)

		# parse url, headers, payload from cache_file
		got_squid_meta = False
		payload = b""
		byte = cache_file_raw.read(1)
		str_buff = byte

		# read all file bytes
		while byte != "":
			# check for \r\n (next header)
			# hex bytes 0d0a = \r\n
			if byte.encode('hex') == "0d":
				byte2 = cache_file_raw.read(1)
				if byte2.encode('hex') == "0a":

					# if got_squid_meta this is a header
					if got_squid_meta:
						# print buffer
						print(str_buff)

					# parse_squid_meta from buffer
					else:
						parse_squid_meta(str_buff)
						got_squid_meta = True
					
					str_buff = ""
					
					# check for double \r\n (payload)
					word2 = cache_file_raw.read(2)
					if word2.encode('hex') == "0d0a":
						# payload, read to EOF
						payload = cache_file_raw.read()

					# word2 starts next header
					else:
						byte = ""
						str_buff = word2

				# not a new header, add bytes to buffer
				else:
					str_buff = str_buff + byte + byte2

			# not a new header, add byte to buffer
			else:
				str_buff = str_buff + byte

			# read another byte
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

	# parse squid_meta from cache_file
	cache_key = squid_meta[11:27] # md5 cache_key
	timestamp = squid_meta[32:39] # timestamp (host endianness bytes)
	lastref = squid_meta[40:47] # lastref (host endianness bytes)
	expires = squid_meta[48:55] # expires (host endianness bytes)
	lastmod = squid_meta[56:63] # lastmod (host endianness bytes)
	refcount = squid_meta[72:73] # refcount (host endianness bytes)
	flags = squid_meta[74:76] # flags (host endianness bytes)

	url_ver_code = binascii.b2a_hex(squid_meta[81:]) # remainder of string
	url = binascii.a2b_hex(
		url_ver_code[:url_ver_code.find("000a")]) # url string
	http_ver = binascii.a2b_hex(
		url_ver_code[url_ver_code.find("000a")+16:]
		).split()[0] # http_ver
	http_code = binascii.a2b_hex(
		url_ver_code[url_ver_code.find("000a")+16:]
		).split()[1] # http_code

	print binascii.b2a_hex(cache_key)
	print int(binascii.b2a_hex(timestamp[::-1]), 16)
	print int(binascii.b2a_hex(lastref[::-1]), 16)
	print int(binascii.b2a_hex(expires[::-1]), 16)
	print int(binascii.b2a_hex(lastmod[::-1]), 16)
	print int(binascii.b2a_hex(refcount[::-1]), 16)
	print int(binascii.b2a_hex(flags[::-1]), 16)
	print http_ver
	print http_code
	print("==== done parsing squid_meta ====")

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
#parse_cache_file('./data/squid3/00/13/00001317')
parse_cache_file('./data/squid3/00/5D/00005DA3')

exit()

# print out the configured cache_dir
print("cache_dir: '%s'" % cache_dir)

# get list of all cache_files
cache_files = []
for path, dirs, files in os.walk(cache_dir):
	if path != cache_dir:
		for cache_file in files:
			cache_files.append(("%s/%s" % (path, cache_file)))

# iterate through all cache_files to extract squid_meta, headers, and payload
for cache_file in cache_files:
	parse_cache_file(cache_file)
