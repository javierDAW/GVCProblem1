#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import time, os
import apache_log_parser
from pprint import pprint
import json 

RULES_PATH = "owasp-modsecurity-crs-3.0-master/rules/"
RULES_CONFIG = "config.json"
RULES = {}

def loadRules():
	global RULES

	RULES = json.load(open('config.json'))["rules"]

	for config in RULES:
		
		words = []
		with open(RULES_PATH + RULES[config]["file"], "r") as f:
			for i in f:
				if len(i.strip()) > 0 and i.strip()[0] != "#":
					words.append(i.strip())

		RULES[config]["words"] = words


def storeLastIndex(i): 
	with open("lastIndex", "w+") as f:
		f.write(str(i))


def getLastIndex(): 
	l = 0

	try:
		with open("lastIndex", "r") as f:
			l = int(f.read())
	except Exception as e:
		pass

	return l

def analyzeEntry(entry):
	apacheParser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")
	
	try:
		logLine = apacheParser(entry)

		for rule in RULES:

			if RULES[rule]["field"] in logLine:

				for word in RULES[rule]["words"]:
					if word in logLine[RULES[rule]["field"]]: 

					# Malicious request found! Storing it
						with open("malicious.log", "a+") as f:
							f.write("Found %s (from the %s rule-set) in the %s field of the next log:\t%s" % (word, rule, RULES[rule]["field"], entry))
	except Exception as e:
		pass


def readFileFromIndex(f, lastIndex):

	# Skip lines until lastIndex
	i = 0
	while i < lastIndex: 
		# Items already analyzed
		f.readline()
		i+=1 

	# New lines stored since last execution

	entry = f.readline()

	# Store the index of the last analyzed item

	while entry: 
		i += 1
		analyzeEntry(entry)
		entry = f.readline()

	return i

def main():

	print "[*] Loading rules"

	loadRules()

	print "[*] Starting mini Apache IDS"

	# Read the apache log
	filename = 'security_log'
	file = open(filename,'r')

	print "[*] Reading log %s " % filename

	print "[*] Searching for new items stored..."
	# Skip until last index and read news 
	lastIndex = readFileFromIndex(file, getLastIndex())

	#Find the size of the file and move to the end
	st_results = os.stat(filename)
	st_size = st_results[6]
	file.seek(st_size)

	try:

		while 1:
			where = file.tell()
			line = file.readline()
			if not line:
				time.sleep(1)
				file.seek(where)
			else:
				lastIndex += 1
				analyzeEntry(line.strip())
				
	except KeyboardInterrupt:
		print "[*] Exiting program"
		storeLastIndex(lastIndex)
		return
		




if __name__ == "__main__":
	main()
