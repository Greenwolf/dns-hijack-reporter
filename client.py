import time
import datetime
import argparse
import requests
import sys
import socket
import dns.resolver

# DNS Hijack Reporter, written to counter: https://www.wired.com/story/sea-turtle-dns-hijacking/
# Written by Jacob Wilkin (Greenwolf)

parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='DNS Hijack Reporter client.py by Jacob Wilkin(Greenwolf)',
        usage='%(prog)s -t <timeBetweenChecks> -hn <HostnameOfClient> -si <serverIP> -p <port> -at <accesstoken>')

parser.add_argument('-v', '--version', action='version',version='%(prog)s 0.1.0 : DNS Hijack Reporter client.py by Greenwolf (Github Link Here)')
parser.add_argument('-vv', '--verbose', action='store_true',dest='vv',help='Verbose Mode')

parser.add_argument('-t', '--time',action='store', dest='time',required=True,help='Time in minutes between checks: 10,30,60')
parser.add_argument('-hn', '--hostname',action='store', dest='hostname',required=True,help='Hostname that should be pointing to this servers IP address: www.domain.com,mail.greenwolf.com')
parser.add_argument('-si', '--serverip',action='store', dest='serverip',required=True,help='IP address of verification server')
parser.add_argument('-p', '--port',action='store', dest='port',required=False,help='Port verficiation server is listening on')
parser.add_argument('-at', '--accesstoken',action='store', dest='accesstoken',required=True,help='accesstoken which verficiation server was configured with')
parser.add_argument('-db', '--debug',action='store_true', dest='debug',required=False,help='Skip initial hostname to current IP alignment check so you can test DNS Hijack Reporter runs against a failed match like \'--hostname google.com\'')
parser.add_argument('-c', '--cname',action='store_true', dest='cname',required=False,help='Force verification based on CNAME for servers using a CDN/Multiple IPs for the same hostname, will notify of initial DNS compromise (account/provider), but not of CDN provider compromise')

args = parser.parse_args()



# Check here to test that external IP matches dns IP for first run
# If args.debug is true, skip this inital alignment check
if args.cname != True:
	if args.debug != True:
		publicip = requests.get('https://api.ipify.org').text
		time.sleep(5)
		dnsip = str(socket.gethostbyname(args.hostname))
		if publicip != dnsip:
			print("Your current external IP (" + publicip + ") and dns IP (" + dnsip + ") for " + args.hostname + "are not aligned")
			print("Program exitting: to bypass this check for testing purposes, use: --debug/-db")
			sys.exit(0)

#Check if configuring client as IP or CNAME based checks
cname = ""
if args.cname == True:
	# Set up known good CNAME record
	try:
		answers = dns.resolver.query(args.hostname, 'CNAME')
		cname = str(answers[0].target)
		print("Initial CNAME record configured to: " + cname)
	except Exception as e:
		print(e)
		print("Failure configuring initial CNAME record")
		sys.exit(0)
	# Loop forever reporting to server.py
	while True:
		if args.vv == True:
			timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			print("%s - Reporting %s:%s to DNS Verification Server" % (timestamp,args.hostname,cname))
		port = 58008
		if args.port:
			port = int(args.port)
		reqbody = "2:" + args.hostname + ":" + cname
		verificationserver="https://" + args.serverip + ":" + str(port)
		cookies = {'accesstoken': args.accesstoken}
		try:
			requests.packages.urllib3.disable_warnings()
			r = requests.post(verificationserver, data=reqbody, cookies=cookies,verify=False)
		except Exception as e:
			print("Error:")
			print(e)
		time.sleep(int(args.time)*60)
# If CNAME flag is not set, use public IP lookups
else:
	while True:
		#Code to get current public IP address
		publicip = requests.get('https://api.ipify.org').text
		if args.vv == True:
			timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			print("%s - Reporting %s:%s to DNS Verification Server" % (timestamp,args.hostname,publicip))
		port = 58008
		if args.port:
			port = int(args.port)
		#Post args.hostname and publicip, on server this is then written to a file
		reqbody = "1:" + args.hostname + ":" + publicip
		#Connect to verification server with access token and server ip.
		verificationserver="https://" + args.serverip + ":" + str(port)
		cookies = {'accesstoken': args.accesstoken}
		try:
			requests.packages.urllib3.disable_warnings()
			r = requests.post(verificationserver, data=reqbody, cookies=cookies,verify=False)
		except Exception as e:
			print("Error:")
			print(e)
		time.sleep(int(args.time)*60)


