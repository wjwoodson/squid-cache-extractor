# parse-store-log.py
#

import csv
import sys

# set input and output files
txt_file = ""
csv_file = ""

# open input and ouptut files
in_txt = open(txt_file, "r")
out_csv = csv.writer(open(csv_file, 'w'))

# create a list of lists for each row in in_txt file
file_list = []
file_string = in_txt.readlines()
for row in file_string:
	file_list.append(row.rstrip().split(' '))
	# we should probably be creating a list of dicts here

in_txt.close()

# write out to csv with headers
with open(csv_file, 'w+') as csv_file:
	#create fields
	writer = csv.DictWriter(csv_file, fieldnames = ['Time','Action','Status',
		'DateHdr','LastMod','Expires','Type','Expect-Length','Real-Length','Method',
		'Key'])
	writer.writeheader()

	# write rows to csv
	w = csv.writer(csv_file, lineterminator='\n')
	w.writerows(file_list)
