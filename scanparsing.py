import xmltodict
import requests
import re
import json
import collections
import pandas as pd  
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
import mpld3
from mpld3._server import serve
from scanning import date, time

#------EXPORTING NMAP AND OPENVAS-----------------------

#openvas importing
def open_vas(file):
    cve_list_ovas = []
    openvas_cve_by_port = {}
    threat_levels = []
    threats = []
    with open('report-4dd0227c-bca8-4aad-8eaa-a4f04acf9f34.xml') as fd:
        doc = xmltodict.parse(fd.read())
        results = doc['report']['report']['results']['result']
        for result in results:
            threat = {}
            threat['name'] = result['name']
            threat['port'] = result['port']
            threat['cvss_base'] = result['nvt']['cvss_base']
            threat['cve'] = result['nvt']['cve']
            threat['tags'] = result['nvt']['tags']
            threat['threat'] = result['threat']
            threat['severity'] = result['severity']
            threat['description'] = result['description']
            threats.append(threat)
            cve = result['nvt']['cve'].split(", ")
            for item in cve:
                cve_list_ovas.append(item)
                threat_levels.append(result['threat'])
                if result['port'] in [*openvas_cve_by_port]:
                    openvas_cve_by_port[result['port']].append(item)
                else:
                    openvas_cve_by_port[result['port']] = []
        
    return cve_list_ovas, threat_levels, threats, openvas_cve_by_port

#nmap importing
def nmap():
    cve_list_nmap = []
    threats = []
    with open('nmap.xml') as fd:
        doc = xmltodict.parse(fd.read())
        results = doc['nmaprun']['host']['ports']['port']
        
        for port in results:

            threat = {'port': {}, 'service': {}, 'script': {}}
            threat['port']['port_number']=port['@portid']
            threat['port']['protocol']=port['@protocol']
    
            try:
                threat['service']['name']=port['service']['@name']
            except:
                pass
            
            try:
                threat['service']['product']=port['service']['@product']
            except:
                pass
            
            try:
                threat['service']['version']=port['service']['@version']
            except:
                pass
            
            try:
                threat['script'] = port['script']['@output']
            except:
                pass
            
            threats.append(threat)
            
    nmap_cve = []
    nmap_cve_by_port = {}

    for port in threats:
        try:            
            cves =re.findall(r"CVE-\d{4}-\d{4}", port['script'])
            cve_without_cve  = re.findall(r"\d{4}-\d{4}", port['script'])
            nmap_cve_by_port[port['port']['port_number']] = cves
            for item in cve_without_cve:
                nmap_cve.append("CVE-" + item)
                nmap_cve_by_port[port['port']['port_number']].append("CVE-" + item)
            
            for cve in cves:
                nmap_cve.append(cve)     
        except:
            pass

    return threats, nmap_cve, nmap_cve_by_port


#----------PARSING OPENVAS AND NMAP------------

#openvas parsing
openvas_cve, threat_levels, threats, openvas_cve_by_port = open_vas()
#print(openvas_cve_by_port)
openvas_ports = []
ports = []
threats_by_port_openvas = {}
for threat in threats:
    openvas_ports.append(threat['port'])
ports = list(set(ports))
for port in openvas_ports: 
    threat_items = []
    for item in threats:
        threat_item = {}
        if item['port'] == port:
            threat_item['name'] = item['name']
            threat_item['severity'] = float(item['severity'])
            threat_items.append(threat_item)
    threats_by_port_openvas[port] = threat_items


#nmap parsing
nmap_threats, nmap_cve,nmap_cve_by_port  = nmap()
print(nmap_cve_by_port)
nmap_ports = []
threats_by_port_nmap = {}
for item in nmap_threats:
    nmap_ports.append(int(item['port']['port_number']))

links = ['https://vuldb.com', 'https://cve.mitre.org', 'https://www.securityfocus.com/bid/', 'https://exchange.xforce.ibmcloud.com/', 'https://www.exploit-db.com', 'http://www.openvas.org', 'https://www.securitytracker.com', 'http://www.osvdb.org']
for port in nmap_ports:
    threats = []
    for item in nmap_threats:
        if(int(item['port']['port_number']) == port):
            if item['script']:
                strings = item['script'].split('\n')
                for string in strings:
                    for link in links:
                        if link in string :
                            strings.remove(string)
                threats = strings
                

#-------------------------------------Merging Openvas and Nmap CVEs-------------------------------------------------
number_of_vulns_by_port = {}
#----------------
cves_by_port = {}
#-----------------

cves_by_port = nmap_cve_by_port

for port in [*openvas_cve_by_port]:
    cve_ = []
    if port[:-4] in [*cves_by_port]:
        for item in openvas_cve_by_port[port]:
            cves_by_port[port[:-4]].append(item)
        else:
            cve_.append(item)
    else:
        cves_by_port[port[:-4]] = cve_

        
for port in cves_by_port:
    number_of_vulns_by_port[port] = len(cves_by_port[port])
print(number_of_vulns_by_port)

'''---------------------Merging Openvas and Nmap-----------------'''

#Removing duplicates from openvas and nmap

unique_openvas_cves = set(openvas_cve)
unique_nmap_cves = set(nmap_cve)

all_cves = list(unique_openvas_cves.union(unique_nmap_cves))
cve_severity = {}
cve_count_by_severity = {'Low':0, 'Moderate':0, 'Important':0, 'Unknown':0}
for cve in all_cves:
    try:
        severity = json.loads(requests.get("https://access.redhat.com/hydra/rest/securitydata/cve/" + cve + ".json").text)
        if severity["threat_severity"]=='Low':
            cve_severity[cve]=1
            cve_count_by_severity['Low'] += 1
            
        elif severity["threat_severity"]=='Moderate':
            cve_severity[cve]=2
            cve_count_by_severity['Moderate'] += 1
            
        elif severity["threat_severity"]=='Important':
            cve_severity[cve]=3
            cve_count_by_severity['Important'] += 1

    except:
        cve_severity[cve] = "0"
        cve_count_by_severity['Unknown'] += 1
        pass

#-------------------------------GRAPHS AND FINAL ILLUSTRATIONS----------------------------------------------

#total vulnerable CVEs
#--------------------------------------------------------------------------------------------------
total_vulns_keys = []
for key in [*number_of_vulns_by_port]:
    total_vulns_keys.append(key)
patches, texts = plt.pie([int(v) for v in number_of_vulns_by_port.values()], autopct=None)
labels=[k for k in total_vulns_keys]
sort_legend = True
if sort_legend:
    patches, labels, dummy =  zip(*sorted(zip(patches, labels, number_of_vulns_by_port.values()),
                                          key=lambda x: x[2],
                                          reverse=True))
plt.title("Percentage of vulnerabilities based on service")

plt.legend(patches, labels, loc='left center', bbox_to_anchor=(-0.1, 1.),
           fontsize=8)

plt.savefig('pie.png', dpi=300)

plt.show()
#------------------------------------------------------------------------------------------------------

# # #CVE graph by severity

# # # set width of bar
barWidth = 0.25
 
# # # set height of bar
bars1 = [cve_count_by_severity['Important'], cve_count_by_severity['Important']]
bars2 = [cve_count_by_severity['Moderate'], cve_count_by_severity['Moderate']]
bars3 = [cve_count_by_severity['Low'], cve_count_by_severity['Low']]
 
# # # Set position of bar on X axis
r1 = np.arange(len(bars1))
r2 = [x + barWidth for x in r1]
r3 = [x + barWidth for x in r2]
 
# # # Make the plot
fig2 = plt.figure()
plt.title("Overview of the scanning history of the target")
plt.bar(r1, bars1, color='#ff2d00', width=barWidth, edgecolor='white', label='Important')
plt.bar(r2, bars2, color='#fff300', width=barWidth, edgecolor='white', label='Moderate')
plt.bar(r3, bars3, color='#00ff5d', width=barWidth, edgecolor='white', label='Low')
 
# # # Add xticks on the middle of the group bars
plt.xlabel('Severity', fontweight='bold')
plt.ylabel('Number of CVEs', fontweight='bold')
plt.xticks([r + barWidth for r in range(len(bars1))], ['01/19/2020', '02/22/2020'])
 
# # # Create legend & Show graphic
plt.legend()
plt.savefig('history.png', dpi=300)
plt.show()


cves_port = cves_by_port

        

# # #Total CVEs detected and the list of CVEs
total_cves = 0
list_of_cves = []
cves_info_by_port = {}
for key in [*cves_port]:
    cves_info_by_port[key] = []
    
for port in [*cves_port]:
    
    for cve in cves_port[port]:
        cve_info = {}
        try:
            severity = json.loads(requests.get("https://access.redhat.com/hydra/rest/securitydata/cve/" + cve + ".json").text)
            cve_info["name"] = cve
            cve_info["description"] = severity["bugzilla"]["description"]
            
            if severity["threat_severity"]=='Low':
                
                cve_info["severity"]=1

            
            elif severity["threat_severity"]=='Moderate':
                cve_info["severity"]=2

            
            elif severity["threat_severity"]=='Important':
                cve_info["severity"]=3


        except:
                cve_info["name"] = cve
                cve_info["description"] = "unknonwn"
                cve_info["severity"]= 0

        cves_info_by_port[port].append(cve_info)


print(cves_info_by_port)


import plotly
import plotly.graph_objects as go
for key in [*cves_info_by_port]:
    name = []
    description = []
    severity = []
    severity_count = {'3':0, '2':0, '1':0}
    for cve in cves_info_by_port[key]:
        if cve['description'] == 'unknonwn':
            continue
        else:
            try:
                severity.append(cve['severity'])
                name.append(cve['name'])
                description.append(cve['description'])
            except:
                pass
    for item in severity:
        if item == 1:
            severity_count['1']+=1
        elif item == 2:
            severity_count['2']+=1
        elif item == 3:
            severity_count['3']+=1
    
    barlist = plt.bar(range(len(severity_count)), list(severity_count.values()),color=(0.2,0.4,0.6), align='center')
    plt.title("Severity of CVEs of port " + key)
    barlist[0].set_color('r')
    barlist[1].set_color('y')
    barlist[2].set_color('g')
    plt.savefig("bar" + key + ".png", dpi=300)
    plt.show()
