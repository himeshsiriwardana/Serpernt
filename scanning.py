import os
import re
import sys
import subprocess
import time
import nmap
import json
from datetime import datetime



'''Network Vulnerability Scanning'''

def nmap_scan(target,port_start,port_end,scan_type, script, time):
    nm = nmap.PortScanner()
    scan = nm.scan(target, port_start + "-" + port_end, arguments='-s' + scan_type + ' --script=' + script)
    output = open(str(time) + "-nmap.xml", "w")
    output.write(nm.get_nmap_last_output())


  
#openvas scanning
def create_target(target):
    #Creating a target
    cmd = "omp -u admin -w admin --xml='<create_target><name>"+target+"</name><hosts>"+target+"</hosts></create_target>' > tmp.resp"
    
    create_target = subprocess.call([cmd], shell=True)
    readResp = open('tmp.resp','r')
    lines = readResp.readlines()
    print(lines)
    find = re.compile(r'id=\"[a-zA-Z0-9\-]+"\>')
    for line in lines:
        found = find.findall(line)
        print(found)  
        if found:
            targetID = found[0][3:-1].strip('"').replace('>', '')
            print(str(targetID))
            return str(targetID)
        
        else: 
            print("The target was not created")


def prepare_scan(targetID):
    configID = "daba56c8-73ec-11df-a475-002264764cea"
    cmd = "omp -u admin -w admin --xml='<create_task><name>Full and fast</name><comment>Full and fast</comment><config id=\""+ configID + "\"/><target id=\""+targetID+"\"/></create_task>' > tmp.task"

    print('Preparing options for the scan')
    task = subprocess.call([cmd],shell=True)

    getTaskID = open('tmp.task', 'r')
    lines = getTaskID.readlines()
    find = re.compile(r'id=\"[a-zA-Z0-9\-]+"\>')
    
    for line in lines:
        found = find.findall(line)

        if found:
            taskID = found[0][3:-1].strip('"').replace('>','')
            return(taskID)



def start_scan(target,taskID,time):
    print("Running scan for " + str(target))

    cmd = "omp -u admin -w admin --xml='<start_task task_id=\""+taskID + "\"/>' > tmp.startID"
    scan = subprocess.call([cmd],shell=True)
    print("Scan started")
    time.sleep(3)
    
    cmd2 = "omp -u admin -w admin -G | grep %s > tmp.stat" % (taskID)
    status = subprocess.call([cmd2],shell=True)

    while 'Done' not in open('tmp.stat', 'r').read():

        runme = subprocess.call([cmd2],shell=True)
        print(runme)
        time.sleep(10)

    print("Scan looks to be done.")
    print("Target scanned. Finished task")

    getXml = "omp -u admin -w admin -X '<get_reports/> <report id><task id=\""+ str(taskID)+ "\"/>' >" + time + "openvas.xml"



date = datetime.now().date()
time = datetime.now().time()

try:
    os.makedirs(str(date))
except FileExistsError:
    # directory already exists
    pass

with open('config.json') as config_file:
    data = json.load(config_file)
target = data["target"]
start_of_scan = str(date) + "/" + str(time)

#nmap scanning
print("+++++++++++++++++++++Running nmap with script++++++++++++++++++++++++++")
nmap_scan(data["target"],str(data["nmap"]["port_start"]),str(data["nmap"]["port_end"]),data["nmap"]["scan_type"], data["nmap"]["script"], start_of_scan)
print("Port scanning has ended")


#openvas scanning
print("+++++++++++++++++++Running openvas++++++++++++++++++++++++++++++++++++++")
targetID = create_target(target)
taskID = prepare_scan(targetID)
start_scan(targetID,taskID, start_of_scan)
print("openvas scan has ended")

import scanparsing






    






    
        

    









