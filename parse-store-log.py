# parse-store-log.py
#

import re
import csv
import sys
from urlparse import urlparse

# set input and output files
txt_file = "./data/store.log"
csv_file = "store.log.csv"

# open input and ouptut files
in_txt = open(txt_file, "r")
out_csv = csv.writer(open(csv_file, 'w'))

# create a list of lists for each row in in_txt file
file_list = []
file_string = in_txt.readlines()
for row in file_string:

	# split row to list
	log_list = ('\t'.join(row.split())).split('\t')

	log_list[4] = log_list[4].lower() # convert md5 to lower	
	log_list[0] = log_list[0].rpartition(".")[0] # convert timestamp to int
	
	url_parse = urlparse(log_list[12]) # parse url into components
	log_list.append(url_parse.netloc)
	log_list.append(url_parse.scheme)
	log_list.append(url_parse.path.rpartition("/")[0])
	log_list.append(url_parse.path.rpartition("/")[2])

	# split up expected size/actual size fields
	log_list = log_list + log_list.pop(10).split("/",1)

	# add the list to the list of lists
	file_list.append(log_list)

in_txt.close()

# write out to csv with headers
with open(csv_file, 'w+') as csv_file:
	#create fields
	writer = csv.DictWriter(csv_file, fieldnames = ['meta_timestamp',
		'meta_store_action','meta_store_dir','cache_filen','meta_cache_key',
		'http_code','Date','meta_lastmod','meta_expires',
		'Content-Type','http_method','url','url_host','url_scheme',
		'url_path','url_file','meta_expected_length','meta_real_length'])
	writer.writeheader()

	# write rows to csv
	w = csv.writer(csv_file, lineterminator='\n')
	w.writerows(file_list)
