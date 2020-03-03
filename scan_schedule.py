import schedule
import time
import subprocess


def job():
	subprocess.call("nmap_update.sh")
	subprocess.call("openvas_update.sh")

#Task Scheduling
schedule.every(1).minutes.do(subprocess.call("nmap_update.sh"))


while True:
	schedule.run_pending()
	time.sleep(1)
