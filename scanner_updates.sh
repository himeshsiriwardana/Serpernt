#!/bin/bash
/usr/sbin/greenbone-nvt-sync
/usr/sbin/greenbone-cert-data-sync
/usr/sbin/greenbone-scapdata-sync
/usr/sbin/openvasmd --update --verbose --progress
/etc/init.d/openvas-manager restart
/ets/init.d/openvas-scanner restart

#!/bin/bash
wget -O /usr/local/share/nmap/scripts/vulscan/cve.csv https://www.computec.ch/projekte/vulscan/download/cve.csv

wget -O /usr/local/share/nmap/scripts/vulscan/exploitdb.csv https://www.computec.ch/projekte/vulscan/download/exploitdb.csv

wget -o /usr/local/share/nmap/scripts/vulscan/osvdb.csv https://www.computec.ch/projekte/vulscan/download/osvdb.csv