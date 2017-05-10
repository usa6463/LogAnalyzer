import csv # This script save data to csv file as flat text file\
import re # For finding string what I need in line
from geolite2 import geolite2 # For getting country from IP address	/	pip install maxminddb-geolite2

with open('sample.log', 'r') as rfd:
	csvfile1 = open('SimpleIPList.csv', 'w', newline='')
	writer1 = csv.writer(csvfile1)
	csvfile2 = open('DetailIPList.csv', 'w', newline='')
	writer2 = csv.writer(csvfile2)

	ip_info_reader = geolite2.reader()
	ip_list = {}
	i = 0
	while(True):
		i+=1
		print(i)
		line=rfd.readline()
		if(not line):
			break

		p = re.compile('[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+')
		discoverd_ip = p.findall(line)
		ip = ''
		if(len(discoverd_ip)<2):
			pass
		else:
			ip = discoverd_ip[1]
			match = ip_info_reader.get(ip)
			if(not ip in ip_list): #add unique ID
				country=''
				if match == None :
					country = 'NO INFO'
				elif 'country' in match:
					country = match['country']['names']['en']
				elif 'continent':
					country = match['continent']['names']['en']
				else:
					country = 'NO INFO'
					
				ip_list[ip] = [country, 1]
				writer1.writerow([ip])
			else :
				ip_list[ip][1] += 1

	for ip in ip_list: # list of unique IP addresses with country and number of hits
		ip_list[ip].insert(0, ip)
		writer2.writerow(ip_list[ip])

	csvfile1.close()
	csvfile2.close()