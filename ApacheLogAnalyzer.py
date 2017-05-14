import csv # This script save data to csv file as flat text file\
import re # For finding string what I need in line
from geolite2 import geolite2 # For getting country from IP address	/	pip install maxminddb-geolite2
import os # listdir, mkdir ...
from xml.etree.ElementTree import parse # parsing xml for filter regex
from tqdm import tqdm # progress bar
import sys

num = len(sys.argv)
if num!=2:
	print('input logfile path as an argument')
	exit()

log_file_name = sys.argv[1]
num_lines = sum(1 for line in open(log_file_name))

# for saving IP info
ip_info_reader = geolite2.reader()
ip_info_dict = {}

with open(log_file_name, 'r') as rfd:

	# files open
	csvfile1 = open('SimpleIPList.csv', 'w')
	writer1 = csv.writer(csvfile1)
	csvfile2 = open('DetailIPList.csv', 'w')
	writer2 = csv.writer(csvfile2)
	csvfile4 = open('sqli_list.csv', 'w')
	writer4 = csv.writer(csvfile4)
	csvfile5 = open('rfi_list.csv', 'w')
	writer5 = csv.writer(csvfile5)
	csvfile6 = open('webshell_list.csv', 'w')
	writer6 = csv.writer(csvfile6)
	exceptWriter = open('exception.txt', 'a')

	#filter open
	filter_path = './filters/'
	tree = parse(filter_path+'sqli_filter.xml')
	root = tree.getroot()
	sqli_filter = root.findall('filter')
	tree = parse(filter_path+'rfi_filter.xml')
	root = tree.getroot()
	rfi_filter = root.findall('filter')
	tree = parse(filter_path+'webshell_filter.xml')
	root = tree.getroot()
	webshell_filter = root.findall('filter')

	# make directory
	if not 'activity' in os.listdir('.'):
			os.mkdir('activity')

	# For handling case that line has '\n' character
	line_buffer = ''
	multiLineCheck = False

	# reading line by line
	for i in tqdm(range(num_lines)):
		line=rfd.readline()

		# except meta data
		p = re.compile('(^#Fields)|(^#Software)|(^#Version)|(^#Date)')
		m = p.match(line)
		if m:
			continue

		# separate fields
		p = re.compile('(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<s_ip>\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}) (?P<cs_method>\S+) (?P<cs_uri_stem>\S+) (?P<cs_uri_query>.+?) (?P<s_port>443|80) (?P<cs_username>.+?) (?P<c_ip>\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}) (?P<User_Agent>.+?) (?P<Referer>[-]|[<]a href.*|[(]?http.*|\S+) (?P<sc_status>\d+) (?P<sc_substatus>\d+) (?P<sc_win32_status>\d+) (?P<time_taken>\d+)')
		m = p.match(line)

		# line has '\n' character case
		if m and multiLineCheck:
			exceptWriter.write('{} '.format(i)+line_buffer+'\n')
			line_buffer = ''
			multiLineCheck = False
		elif not m:
			if not multiLineCheck:
				line_buffer = line
			else:
				line_buffer += line
				line_buffer = line_buffer.replace('\n', ' ')

			m = p.match(line_buffer)

			if not m:
				multiLineCheck = True
				continue
			else:
				multiLineCheck = False
				line_buffer = ''

		#get Info
		cs_uri_query = m.group('cs_uri_query')
		cs_uri_stem = m.group('cs_uri_stem')
		activity = list(m.groups())
		ip = m.group('c_ip')
		ip_info = ip_info_reader.get(ip)

		# activity write
		csvfile3 = open('activity/'+ip+'.csv', 'a')
		writer3 = csv.writer(csvfile3)
		writer3.writerow(activity)
		csvfile3.close()

		#add unique ID and ip's country, hits
		if(not ip in ip_info_dict):
			country=''
			if ip_info == None :
				country = 'NO INFO'
			elif 'country' in ip_info:
				country = ip_info['country']['names']['en']
			elif 'continent' in ip_info:
				country = ip_info['continent']['names']['en']
			else:
				country = 'NO INFO'
			ip_info_dict[ip] = [country, 1]
			writer1.writerow([ip])
		else :
			ip_info_dict[ip][1] += 1

		# detect sqli
		for element in sqli_filter :
			rule = element.findtext("rule")
			p = re.compile(rule)
			m = p.match(cs_uri_query)
			if m:
				description = element.findtext("description")
				writer4.writerow(activity + [description])
				break

		# detect remote file inclusion
		for element in rfi_filter :
			rule = element.findtext("rule")
			p = re.compile(rule)
			m = p.match(cs_uri_query)
			if m:
				description = element.findtext("description")
				writer5.writerow(activity + [description])
				break

		# detect webshell
		for element in webshell_filter :
			rule = element.findtext("rule")
			p = re.compile(rule)
			m = p.match(cs_uri_stem+cs_uri_query)
			if m :
				description = element.findtext("description")
				writer6.writerow(activity + [description])
				break

	# list of unique IP addresses with country and number of hits
	for ip in ip_info_dict:
		writer2.writerow([ip]+ip_info_dict[ip])

	csvfile1.close()
	csvfile2.close()
	csvfile4.close()
	csvfile5.close()
	exceptWriter.close()
