# cache-extractor.py
#

import os
import md5
import binascii
import time
from datetime import datetime

# set cache_dir from which to extract files
cache_dir = "./data/squid3"

# hex byte parse of squid_meta, headers, payload from a cache_file
def parse_cache_file(cache_file):

	# open the cache_file on disk and read
	with open(cache_file, 'rb') as cache_file_raw:
		#print(cache_file)
		cache_file_parsed = {}
		cache_file_parsed['file_path'] = cache_file

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
						try:
							key = str_buff.split(":",1)[0].strip()
							value = str_buff.split(":",1)[1].strip()
							cache_file_parsed[key] = value
						except IndexError:
							print("Error: IndexError in parse_cache_file at cache_file: %s"
								% cache_file)

					# parse_squid_meta from buffer
					else:
						cache_file_parsed.update(
							parse_squid_meta(str_buff))
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
		cache_file_parsed['payload_md5'] = md5sum.hexdigest()

		# check for gzip file signatures
		# hex bytes 1f8b08 = gzip signature
		if payload.encode('hex')[:6] == "1f8b08":
			decompress_gzip(payload)
		
		# check for zip file signature
		# hex bytes 504b0304 = zip signature (PKZIP archive_1)
		if payload.encode('hex')[:6] == "504b0304":
			decompress_pk(payload)

		cache_file_parsed = convert_time_strings(cache_file_parsed)

		# return cache_file_parsed data structure
		return cache_file_parsed

# parse squid_meta in cache_file header
def parse_squid_meta(squid_meta):
	
	squid_meta_parsed = {}

	# parse squid_meta from cache_file
	cache_key = squid_meta[11:27] # md5 cache_key (hex string)
	timestamp = squid_meta[32:39] # timestamp (host endianness bytes)
	lastref = squid_meta[40:47] # lastref (host endianness bytes)
	expires = squid_meta[48:55] # expires (host endianness bytes)
	lastmod = squid_meta[56:63] # lastmod (host endianness bytes)
	refcount = squid_meta[72:73] # refcount (host endianness bytes)
	flags = squid_meta[74:76] # flags (host endianness bytes)

	url_ver_code = binascii.b2a_hex(squid_meta[81:]) # remainder of string
	url = ""
	http_ver = 0
	http_code = 0
	try:
		url = binascii.a2b_hex( # url (string)
			url_ver_code[:url_ver_code.find("000a")]) # 000a terminated
		http_ver = binascii.a2b_hex( # http_ver (string)
			url_ver_code[url_ver_code.find("48545450"):] # 48545450 = HTTP
			).split()[0]
		http_code = int(binascii.a2b_hex( # http_code (string)
			url_ver_code[url_ver_code.find("48545450"):] # 48545450 = HTTP
			).split()[1])

		squid_meta_parsed['meta_cache_key'] = binascii.b2a_hex(cache_key)
		squid_meta_parsed['meta_timestamp'] =  int(binascii.b2a_hex(timestamp[::-1]), 16)
		squid_meta_parsed['meta_lastref'] =  int(binascii.b2a_hex(lastref[::-1]), 16)
		squid_meta_parsed['meta_expires'] = int(binascii.b2a_hex(expires[::-1]), 16)
		squid_meta_parsed['meta_lastmod'] = int(binascii.b2a_hex(lastmod[::-1]), 16)
		squid_meta_parsed['meta_refcount'] = int(binascii.b2a_hex(refcount[::-1]), 16)
		squid_meta_parsed['meta_flags'] = int(binascii.b2a_hex(flags[::-1]), 16)
		squid_meta_parsed['http_ver'] = http_ver
		squid_meta_parsed['http_code'] = http_code

	except IndexError as e:
		print("Error: IndexError in parse_squid_meta at cache_key: %s"
			 % binascii.b2a_hex(cache_key))
	except ValueError as e:
		print("Error: ValueError in parse_squid_meta at cache_key: %s"
			% binascii.b2a_hex(cache_key))
	except TypeError as e:
		print("Error: TypeError in parse_squid_meta at cache_key: %s"
			% binascii.b2a_hex(cache_key))

	return squid_meta_parsed

# decompress a gzipped response payload
def decompress_gzip(response_payload):
	#print("==== payload is gzip ====")
	pass

# decompress deflate/zip/PK response payload
def decompress_pk(response_payload):
	#print("==== payload is zip ====")
	pass

# parse out references from response_payload
def parse_references(response_payload):
	#print("==== parsed references in payload ====")
	pass

# standardize time formats to unix time
def convert_time_strings(cache_file_parsed):
	
	# list of header values we want to convert
	time_headers = ["Expires", "Date"]

	for key in time_headers:
		if key in cache_file_parsed:
			try:
				timestring = cache_file_parsed[key]
				# try to parse datetime string and write as unix timm
				cache_file_parsed[key] = int(time.mktime(
					datetime.strptime(timestring, "%a, %d %b %Y %H:%M:%S GMT").timetuple()))
			except ValueError:
				print("Error: ValueError in convert_time_strings at cache_key: %s"
					% cache_file_parsed['meta_cache_key'])

	return cache_file_parsed

# insert record into database
def insert_record(parsed_cache_file):
	pass


##### TESTING #####
print parse_cache_file('./data/squid3/00/5D/00005DA3')

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
	print parse_cache_file(cache_file)
