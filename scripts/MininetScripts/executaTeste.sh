ntpServer="192.168.1.157"

echo "Starting Barnyard to log the Snort IDS alerts on database!"
sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort -f snort.log -w /var/log/barnyard2/bylog.waldo -C /etc/snort/classification.config -D

# Synchronize IDS and Of-IDPS controller dates.
if sudo ntpdate $ntpServer;
then 
	# Verify if Barnyard was realy started.
 	if pgrep barnyard2;  
	then
		mv /var/log/snort/alert.fast /var/log/snort/alert.fast.cp
		./mataProcessos.sh
		sudo mn --custom /home/mininet/mininet/custom/cenarioTesteLAN-WAN.py
		sudo chown -R mininet /var/log/tcpdump/*
		sudo killall -9 barnyard2
	else
		echo "Barnyard was not started and it is necessary to record the Snort IDS alerts in the database! Verify if the IP address on the Barnyard config file is correct..."
	fi
else
	echo "Remote clock adjust failed! verify if NTP server is available on $ntpServer... It's necessary to synchronize alerts messages between IDS and Of-IDPS."
fi
