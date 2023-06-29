"""
	Am pornit de la codul primit ca referinta,
	iar mai apoi unde aveam nelamuriri am intrebat si ChatGPT

"""

import socket
import traceback
import ipaddress
import json
import requests
import struct


# Obtine date despre locatie in functie de ip-ul obtinut
def getTargetLoc(IP):
    url = f'https://ipapi.co/{IP}/json/'
    response = requests.get(url)
    data = response.json()

    try:
        lon = data['longitude']
        lat = data['latitude']
        city = data['city']
        country = data['country']
        region = data['region']
    except KeyError as a:
        return f'IP:{IP}, Not Found in Database'

    return (IP, (lon, lat), city, region, country)


def traceroute(dest_addr):
    # Creeaza un socket UDP
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # Creeaza un socket raw pentru a primi pachete ICMP
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_socket.settimeout(3)

    # Seteaza TTL la 1 și trimite un pachet UDP catre destinatie
    ttl = 1
    max_hops = 30
    udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    udp_socket.sendto(b'salut', (dest_addr, 33434))

    # Deschide fisierul în modul adaugare (append)
    with open("traceroute_output.txt", "a") as file:
        print(f"Destination address:{dest_addr}", file=file)
        # Parcurge 'max_hops' pasi pana se ajunge la destinatie
        while ttl <= max_hops:
            try:
                # Primeste un pachet ICMP
                data, addr = icmp_socket.recvfrom(1024)
                ip_addr = addr[0]

                # Obtine informatiile despre locatia IP-ului
                target_loc = getTargetLoc(ip_addr)

                # Afisam locatiile in fisier
                print(target_loc, file=file)

                # Daca pachetul ICMP are codul 3, iesim din bucla deoarece am ajuns la destinatie
                if data[20] == 3:
                    break

                # Incrementarea TTL și trimiterea unui alt pachet UDP
                ttl += 1
                udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                udp_socket.sendto(b'salut', (dest_addr, 33434))

            except socket.timeout:
                # Daca nu se primeste un pachet ICMP inainte de expirarea timeout-ului, se presupune că pachetul a fost pierdut si se incearca din nou
                print(f"ttl={ttl}", file=file)
                ttl += 1
                udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                udp_socket.sendto(b'salut', (dest_addr, 33434))

            except:
                # Daca apare o alta eroare, se afisează traceback-ul și se iese din bucla
                print(traceback.format_exc(), file=file)
                break

        if ttl > max_hops:
            print("Couldn't reach destination", file=file)
        print("--------------------------------------------------------------------------", file=file)

    # Inchide socket-urile
    udp_socket.close()
    icmp_socket.close()


traceroute('www.woolworths.co.za')
