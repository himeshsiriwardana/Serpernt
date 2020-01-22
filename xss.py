import argparse
import nmap
import requests
import whois
import securityheaders
from openvas_lib import VulnscanManager, VulnscanException

#parser = argparse.ArgumentParser()
#parser.add_argument("url", help="check for vulnerabilities in the given url")
#parser.add_argument("action", help="full, info-gather, xss, sql")
#parser.add_argument("checkPassword", help="f")
#args = parser.parse_args()
#print(args.echo)

'''Information gathering of the web server'''

#whois lookup of the target
def whois_lookup(url):
    print("Starting whois lookup")
    domain = whois.query(url)
    print('[+]name: ', domain.name)
    print('[+]registrar: ', domain.registrar)
    print('[+]creation date', domain.creation_date)
    print('[+]expiration date', domain.expiration_date)
    print('[+]last updated :', domain.last_updated)
    print('[+]name servers: ', domain.name_servers)

#Gaining http header information
def header_information(url):
    resp = requests.get(url)
    try:
        header = resp.headers['Strict-Transport-Security']
        print('[+] Strict-Transport-Security header set to ', header)

    except:
        print('[-] Strict-Transport-Security header not set')

    try:
        header = resp.headers['Content-Security-Policy'] 
        print('[+] Content-Security-Policy header is set to ', header)  
    
    except:
        print('[-] Content-Security-Policy header not set')
    
    try:
        header = resp.headers['X-XSS-Protection']
        print('[+] X-XSS-Protection header set to ', header)

    except:
        print('[-] X-XSS-Protection header not set')
    
    try:
        header = resp.headers['X-Frame-Options']
        print('[+] X-Frame-Options header set to ', header)

    except:
        print('[-] X-Frame-Options header not set')
    
    try:
        header = resp.headers['X-Content-Type-Options']
        print('[+] X-Content-Type-Options header set to ', header)

    except:
        print('[-] X-Content-Type-Options header not set')


#Port scanning and fingerprinting the target
def port_scan(url):
    nm = nmap.PortScanner()
    print(nm.command_line())


#def vulnerabilityScanner(target):

     





port_scan('https://www.google.com')

# def xss(url):



# def sql(url):


# def passwordProtect(url):
    


    









