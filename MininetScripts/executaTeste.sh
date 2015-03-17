ntpServer="192.168.1.157"
if sudo ntpdate $ntpServer;  
then
	mv /var/log/snort/alert.fast /var/log/snort/alert.fast.cp
	./mataProcessos.sh
	sudo mn --custom /home/mininet/mininet/custom/cenarioTesteLAN-WAN.py
	sudo chown -R mininet /var/log/tcpdump/*
else
	echo "Remote clock adjust failed! verify if NTP server is available on $ntpServer... It's necessary to synchronize alerts messages between IDS and Of-IDPS."
fi
