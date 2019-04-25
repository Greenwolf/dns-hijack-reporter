# DNS Hijack Reporter

DNS Hijack Reporter is a lightweight client server program to report on DNS Hijacking ([A la Sea Turtle](https://www.wired.com/story/sea-turtle-dns-hijacking/)).

DNS Hijack reporter is aimed both at those running single servers, where you have one IP for one Domain/Subdomain and those who are using services such as Akamai or Cloudflare and your DNS is pointing to a 3rd party provider.

These scripts will continiously poll your DNS records for configured hostnames and detect any changes made to them. Allowing you to know when your DNS records have been hijacked. 

## Explaination

DNS Hijack Reporter functions in the following manner:

1) server.py is set up with an strong access token, an email to report DNS Hijacking too and a SendGrid API key
2) server.py listens by default on port 58008 or one of your choosing
3) client.py is configured on a public facing server with it's expected domain name, along with the IP of server.py and the access token.
4) client.py periodically queries a trusted external service to find what it's public IP address is, it then reports this along with its expected domain name to server.py. Alternativly it may use the CNAME record it had when configured. 
5) server.py then takes the reported domain name and performs a query the domains authoratative DNS server, which should all report back with a matching IP address or CNAME record. If any discrepancies are found, an email is generated with a warning that a DNS provider or your DNS account may have been hijacked.

## Installation

Install the python3 requirements
```
$ pip3 install -r requirements.txt
```
Generate an SSL certificate for the server
```
$ openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout cert.pem
```
## Usage

Configure the server
```
$ python3 server.py --serverip 127.0.0.1 --accesstoken mysecretservertoken --email "myemail@email.com" --sendgridapikey "SG.APIKEYxyz1234567890987654321"
```
Configure the client for a single IP (default) or multiple like a CDN (--cname)
```
$ python3 client.py --time 20 --hostname glokta.com --serverip 127.0.0.1 --accesstoken mysecretservertoken
$ python3 client.py --time 20 --hostname login.trustwave.com --serverip 127.0.0.1 --accesstoken mysecretservertoken --cname
```
## Options Breakdown (--help)
```
server.py
    --serverip : ip for server to listen on
    --accesstoken : strong token that is used for clients to authenticate to server
    --email : email address to send notifications to
    --sendgridapikey : Send Grid API Key for email notifications
    --port : optional port to run server on if don't want to use default
    --verbose : Verbose mode with additional dialog

client.py --time 30 --hostname subdomain.mydomain.com --serverip 192.168.0.1 --accesstoken myserveraccesstoken --port 443
    --time : time in minutes between checks
    --domainname : domain which should be pointing at this client
    --serverip : ip that checking server is running on
    --accesstoken : strong token that is used to authenticate to server
    --port : optional port to configure server on if not default
    --debug : skip check to compare initial IP, used for testing dependencies and email notifications using a hostname you dont control to trigger the mismatch
    --cname : Use verification based on CNAME records instead of A records, used when you have multiple IPs for one hostname and using a CDN like Akamai or a service like Cloudflare
    --verbose : Verbose mode with additional dialog
``` 
## Authors

* **Jacob Wilkin** - *Research and Development* - [Trustwave SpiderLabs](https://github.com/SpiderLabs)
* **Andreas Georgiou** - *Brainstorming and Features* - [Trustwave SpiderLabs](https://github.com/SpiderLabs)

## Donation
If this tool has been useful for you, feel free to thank me by buying me a coffee :)

[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/Greenwolf)

## Graphics

### Standard DNS Request

![Standard DNS Request](images/DNS-Hijacking-normal-request.png?raw=true "Standard DNS Request")

### Hijacked DNS Request

![Hijacked DNS Request](images/DNS-Hijacking-hijacked-request.png?raw=true "Hijacked DNS Request")

### Reporting Hijacked DNS (IP)

![Reporting Hijacked DNS IP](images/DNS-Hijacking-hijacked-request-reported.png?raw=true "Reporting Hijacked DNS (IP)")

### Reporting Hijacked DNS (CNAME)

![Reporting Hijacked DNS CNAME](images/DNS-Hijacking-hijacked-request-reported-cname.png?raw=true "Reporting Hijacked DNS (CNAME)")

## License

Dns Hijack Reporter
Created by Jacob Wilkin
Copyright (C) 2019 Greenwolf Security
 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

