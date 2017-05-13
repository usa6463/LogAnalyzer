import csv # This script save data to csv file as flat text file\
import re # For finding string what I need in line
from geolite2 import geolite2 # For getting country from IP address	/	pip install maxminddb-geolite2
import os # listdir, mkdir ...
from xml.etree.ElementTree import parse # parsing xml for filter regex

with open('CTF2.log', 'r') as rfd:
	csvfile1 = open('SimpleIPList.csv', 'w', newline='')
	writer1 = csv.writer(csvfile1)
	csvfile2 = open('DetailIPList.csv', 'w', newline='')
	writer2 = csv.writer(csvfile2)
	exceptWriter = open('exception.txt', 'a')
	csvfile4 = open('sqli_list.csv', 'w', newline='')
	writer4 = csv.writer(csvfile4)
	csvfile5 = open('rfi_list.csv', 'w', newline='')
	writer5 = csv.writer(csvfile5)
	
	tree = parse('sqli_filter.xml')
	root = tree.getroot()
	sqli_filter = root.findall('filter')
	tree = parse('rfi_filter.xml')
	root = tree.getroot()
	rfi_filter = root.findall('filter')

	if not 'activity' in os.listdir():
			os.mkdir('activity')

	ip_info_reader = geolite2.reader()
	ip_info_dict = {}
	i = 0
	while(True):
		i+=1
		print(i)

		line=rfd.readline()
		if(not line):
			break

		try:
			line_list = line.split()
			# get date, time, serverIP, request, path
			activity = line_list[0:5]

			#get ip
			p = re.compile('[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}')
			ip = p.findall(line)[1]
			ip_info = ip_info_reader.get(ip)

			#get request, parameter, email
			p = re.compile(' (443|80) ')
			request = (p.findall(" ".join(line_list[5:-3]))[0])
			request_index = line_list.index(request)
			parameter = " ".join(line_list[5:request_index])
			email = (line_list[request_index+1:request_index+2])[0]

			#get redirect
			line_list = line_list[request_index+3:]  #from browser to end
			p = re.compile('[(]?http[s]?[:][^\s]*')
			redirect_start_str = p.findall(" ".join(line_list[:-4]))
			redirect_start_index = 0
			if len(redirect_start_str)==0:
				redirect_start_index = -5
			else:
				redirect_start_index = line_list[:-4].index(redirect_start_str[0])
			redirect = " ".join(line_list[redirect_start_index:-4])

			#get browser
			browser = " ".join(line_list[:redirect_start_index])

		except:
			exceptWriter.write('{} '.format(i)+line+'\n')

		# acitivity write
		activity = activity + [parameter, request, email, ip, browser, redirect] + line_list[-4:]
		csvfile3 = open('activity/'+ip+'.csv', 'a', newline='')
		writer3 = csv.writer(csvfile3)
		writer3.writerow(activity)
		csvfile3.close()

		#add unique ID
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
			m = p.match(parameter)
			if m:
				description = element.findtext("description")
				writer4.writerow(activity + [description])
				break

		# detect remote file inclusion
		for element in rfi_filter :
			rule = element.findtext("rule")
			p = re.compile(rule)
			m = p.match(parameter)
			if m:
				description = element.findtext("description")
				writer5.writerow(activity + [description])
				break
				
	for ip in ip_info_dict: # list of unique IP addresses with country and number of hits
		ip_info_dict[ip].insert(0, ip)
		writer2.writerow(ip_info_dict[ip])

	csvfile1.close()
	csvfile2.close()
	exceptWriter.close()