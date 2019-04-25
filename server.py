import time
import datetime
import argparse
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
import ssl
from io import BytesIO
import socket
import requests
import urllib
import sendgrid
from sendgrid.helpers.mail import *
import dns
import dns.name
import dns.query
import dns.resolver

# DNS Hijack Reporter, written to counter: https://www.wired.com/story/sea-turtle-dns-hijacking/
# Written by Jacob Wilkin (Greenwolf)

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

	#Supress logging messages
	def log_message(self, format, *args):
		return

	# Blank Get
	def do_GET(self):
		self.send_response(200)
		self.end_headers()
		self.wfile.write(b' ')

	def do_POST(self):
		#check request for valid accesstoken in cookies
		cookies = SimpleCookie(self.headers.get('Cookie'))
		accesstoken = cookies['accesstoken'].value
		if accesstoken == args.accesstoken:
			#If accesstoken is valid, send a request. 
			content_length = int(self.headers['Content-Length'])
			body = self.rfile.read(content_length).decode("utf-8")
			self.send_response(200)
			self.end_headers()
			response = BytesIO()
			response.write(b'Request Received')
			self.wfile.write(response.getvalue())
			timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
			if args.vv == True:
				print("%s - Recieved valid request to check: %s" % (timestamp,body))
			# use body to perform dns lookup on the hostname/fqdn and get the IP address that dns server is providing
			try:
				# Recieve hostname and external ip for verification
				hostname = str(body.split(':')[1])
				publicip = str(body.split(':')[2])
				check = str(body.split(':')[0])
				
				# Create a resolver object
				my_resolver = dns.resolver.Resolver()
				# Look up the authoritive dns server for the host, to avoid cached results which are delayed
				authority_ip_address = get_authoritative_nameserver(hostname, log)
				#print("Authority IP: " + authority_ip_address)
				# set an authoritive DNS server as the only nameserver
				my_resolver.nameservers = [authority_ip_address]

				if check == "1":
					# Resolve hostname to an IP using the authorative server
					dnsip = my_resolver.query(hostname)[0].address

					# old check
					#dnsip = str(socket.gethostbyname(hostname))

					# If IP does not match reported IP, flag a warning with print()
					if publicip != dnsip:
						print("%s - Possible DNS Hijack or DNS configuration change detected for %s:" % (timestamp,hostname))
						print("RealIP is %s while DNS is reporting %s\n" % (publicip,dnsip))
						# If email + sgu + sgp has been provided, send an email warning to the email address
						if args.email and args.sendgridapikey:
							#
							# If you want a different notification system, SMTP login or mobile text API
							# These lines in the block can be replaced
							subject = "Possible DNS Hijack or DNS configuration change detected"
							emailbody = "A mismatch between your real external IP and DNS public IP has been found for: " + hostname + "<br>Real External IP: " + publicip + "<br>DNS IP: " + dnsip + "<br><br>This could be due to a legitimate change to your DNS records, or an unauthorised DNS Hijacking attack.<br><br>"
							sg = sendgrid.SendGridAPIClient(api_key=args.sendgridapikey)
							mail = Mail(from_email=From('warning@dnshijack.com', 'DNS Hijack'),
								to_emails=To(args.email),
								subject=Subject(subject),
								plain_text_content=PlainTextContent(emailbody),
								html_content=HtmlContent(emailbody))
							response = sg.send(mail)
							#print(response.status_code)
							#print(response.body)
							#print(response.headers)
				elif check == "2":
					originalcname = publicip
					# try to get current cname record for comparison
					try:
						my_resolver = dns.resolver.Resolver()
						answers = my_resolver.query(hostname, 'CNAME')
						cname = str(answers[0].target)
					# If no CNAME, assumes cname was in place during client.py setup so something has changed, has DNS been hijacked and replaced with A record?
					except Exception as e:
						print(e)
						print("CNAME lookup failed, DNS record have changed.")
						cname = "No-CNAME-Record-Found"
					# If CNAMES are mismatched, a DNS change has taken place, so notify 
					if originalcname != cname:
						print("%s - Possible DNS Hijack or DNS configuration change detected for %s:" % (timestamp,hostname))
						print("Original CNAME when setup is %s while DNS is now reporting %s\n" % (originalcname,cname))
						# If email + sgu + sgp has been provided, send an email warning to the email address
						if args.email and args.sendgridapikey:
							#
							# If you want a different notification system, SMTP login or mobile text API
							# These lines in the block can be replaced
							subject = "Possible DNS Hijack or DNS configuration change detected"
							emailbody = "A mismatch between your original CNAME Record and current CNAME Record has been found for: " + hostname + "<br>Original CNAME: " + originalcname + "<br>Current CNAME: " + cname + "<br><br>This could be due to a legitimate change to your DNS records, or an unauthorised DNS Hijacking attack.<br>"
							if cname == "No-CNAME-Record-Found":
								emailbody = emailbody + "The lack of CNAME record could be due to a DNS Hijack, it is advised to check that it has not been replaced with an malicious A record<br><br>"
							sg = sendgrid.SendGridAPIClient(api_key=args.sendgridapikey)
							mail = Mail(from_email=From('warning@dnshijack.com', 'DNS Hijack'),
								to_emails=To(args.email),
								subject=Subject(subject),
								plain_text_content=PlainTextContent(emailbody),
								html_content=HtmlContent(emailbody))
							response = sg.send(mail)
					else:
						if args.vv == True:
							print("Original & Current CNAME Matched")
			except Exception as e:
				print(e)
				pass
		else:
			self.send_response(200)
			self.end_headers()
			self.wfile.write(b' ')

def get_authoritative_nameserver(domain, log=lambda msg: None):
    n = dns.name.from_text(domain)

    depth = 2
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]

    last = False
    while not last:
        s = n.split(depth)

        last = s[0].to_unicode() == u'@'
        sub = s[1]
        if args.vv == True:
            log('Looking up %s on %s' % (sub, nameserver))
        query = dns.message.make_query(sub, dns.rdatatype.NS)
        response = dns.query.udp(query, nameserver)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception('%s does not exist.' % sub)
            else:
                raise Exception('Error %s' % dns.rcode.to_text(rcode))

        rrset = None
        if len(response.authority) > 0:
            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            if args.vv == True:
                log('Same server is authoritative for %s' % sub)
        else:
            authority = rr.target
            if args.vv == True:
                log('%s is authoritative for %s' % (authority, sub))
            nameserver = default.query(authority).rrset[0].to_text()

        depth += 1
    if args.vv == True:
    	print("Authoritative IP: " + nameserver)
    return nameserver

def log(msg):
    print(msg)

parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='DNS Hijack Reporter server.py by Jacob Wilkin(Greenwolf)',
        usage='%(prog)s -at <accesstoken> -p <port> -e <emailToRecievenotifications> -sgu <sendgridUsername> -sgp <sendgridPassword>')

parser.add_argument('-v', '--version', action='version',version='%(prog)s 0.1.0 : DNS Hijack Reporter server.py by Greenwolf (Github Link Here)')
parser.add_argument('-vv', '--verbose', action='store_true',dest='vv',help='Verbose Mode')

parser.add_argument('-si', '--serverip',action='store', dest='serverip',required=True,help='IP address of this host')
parser.add_argument('-p', '--port',action='store', dest='port',required=False,help='Port verficiation server is listening on')
parser.add_argument('-at', '--accesstoken',action='store', dest='accesstoken',required=True,help='accesstoken to allow clients to access server')
parser.add_argument('-e', '--email',action='store', dest='email',required=False,help='Email Address to recieve hijack notifications')
parser.add_argument('-k', '--sendgridapikey',action='store', dest='sendgridapikey',required=False,help='Sendgrid API key for email notifications')

args = parser.parse_args()

if (args.email) and not (args.sendgridapikey):
	print("If you require email notifications, please provide a valid sendgrid api key")

port = 58008
if args.port:
	port = int(args.port)

httpd = HTTPServer((args.serverip,port), SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, 
        keyfile="cert.pem", 
        certfile='cert.pem', server_side=True)
httpd.serve_forever()

