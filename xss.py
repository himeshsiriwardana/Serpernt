import argparse
import nmap
import requests
import whois
import subprocess
from openvas_lib import VulnscanManager, VulnscanException
from threading import Semaphore
from functools import partial

'''Web Vulnerability Scanning'''
#whois lookup of the target
def whois_lookup(url):
    print("+++++++++++++++++++++Starting whois lookup++++++++++++++++++")
    time.sleep(2)
    domain = whois.query(url)
    print('[+]name: ', domain.name)
    print('[+]registrar: ', domain.registrar)
    print('[+]creation date', domain.creation_date)
    print('[+]expiration date', domain.expiration_date)
    print('[+]last updated :', domain.last_updated)
    print('[+]name servers: ', domain.name_servers)

#Gaining http header information
def header_information(url):
    print("++++++++++++++++++++Checking for security headers+++++++++++++++++++")
    time.sleep(2)
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


def web_vuln_scan(url):
    subprocess.run("clear")

    print("++++++++++++++++++++Running web vulnerability scanner++++++++++++++++++ ")
    scan = subprocess.run(["nikto +host %s"%url], stdout=subprocess.PIPE, shell=True)
    output = scan.stdout
    if scan.returncode:
        raise Exception(error)
    else:
        vulns = list(filter(bool, output.splitlines()))
        for vuln in vulns:
            print(vuln, '\n')
        

'''Network Vulnerability Scanning'''
#Port scanning and fingerprinting the target
#nmap --reason -n -Pn --packet-trace -g 80 -sO -p 6 <target ip>
#nmap --reason -n -Pn --packet-trace -g 80 -sA -p 80 <target ip>
def port_scan(target):
    print("+++++++++++++++++++++Portscanning has started++++++++++++++++++++++++++")
    nm = nmap.PortScanner()
    scan = nm.scan(target, '22-443', arguments='-sV --script=/usr/local/share/nmap/scripts/vulscan' )['scan']['192.168.0.126']['tcp']
    ports = scan.keys()

    for host in nm.all_hosts():
         print('---------------------------------')
         print('Host %s(%s)' % (host, nm[host].hostname()))
         print('State: %s' % nm[host].state())
         for port in ports:
            print('---------------------------------------------------------------')
            print('port number: ', port)
            print('name: ', scan[port]['name'], '/tcp')
            print('product: ', scan[port]['product'])
            print('version: ', scan[port]['version'])
            print('--------------------------------------------------------------------')
            vulns = list(filter(bool, scan[22]['script']['vulscan'].splitlines()))
            for vuln in vulns:
                print(vuln, '\n')

def net_vuln_scan(host, user, password, target):
    print("++++++++++++++++++++++++Running the network vulnerability scanner++++++++++++++++")
    sem = Semaphore(0)
    manager = VulnscanManager(host,user, password)
    manager.launch_scan(target, profile = "empty", callback_end = partial(lambda x: x.release(), sem), callback_progress = my_print_status)

    sem.acquire()
    print("finished")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="check for vulnerabilities in the given url or IP address")
    #parser.add_argument("action", help="full, info-gather, xss, sql")
    #parser.add_argument("checkPassword", help="f")
    args = parser.parse_args()
    target = args.target
    if "http" in args.target:
        print("Starting web vulnerability scanning on ", target)
        print("---------------------------------------------------")
        print("----------------Gathering information------------------")
        whois_lookup(target)
        header_information(target)
        web_vuln_scan(target)
    
    else:
        print("Starting network vulnerability scanning on ", target)
        port_scan(target)
        


    
#web_vuln_scan(args.target)

# def xss(url):



# def sql(url):


# def passwordProtect(url):
    


    









