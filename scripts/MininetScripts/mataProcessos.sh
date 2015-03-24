sudo killall -9 controller iperf idswakeup snort tcpdump nmap apache2
sudo killall -9 python /home/mininet/snort_fast_alert_processor_antigo.py
sudo rm -f /home/mininet/alertas/formatted_log.csv
