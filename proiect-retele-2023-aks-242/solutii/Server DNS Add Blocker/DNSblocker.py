"""
ca sursa am folosit acest tutorial: 
	https://www.youtube.com/watch?v=wuo_nWN4YJU&list=PLBOh8f9FoHHhvO5e5HF_6mYvtZegobYX2&index=9
care are in descriere si github-ul cu codul folosit in prezentare:
	https://howco.de/how-dns
	
pentru unele neclaritati am folosit si ChatGPT 
"""

import socket

# Citirea listei de site-uri blocate din fisierul "block.txt"
with open("block.txt") as f:
    blocklist = [line.strip() for line in f]

# Functia pentru obtinerea flagurilor
def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    # Byte-ul 1

    rflags = ''
    QR = '1'  # Bitul QR indica daca mesajul este o intrebare (0) sau un raspuns (1)

    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1) & (1 << bit))  # Extrage bitii corespunzatori campului OPCODE

    AA = '1'  # Bitul AA indica daca serverul este autoritar pentru domeniul interogat
    TC = '0'  # Bitul TC indica daca mesajul a fost taiat datorita depasirii dimensiunii maxime
    RD = '0'  # Bitul RD indica daca serverul accepta recursivitatea

    # Byte-ul 2

    RA = '0'  # Bitul RA indica daca serverul accepta recursivitatea
    Z = '000'  # Bitii Z sunt rezervati si trebuie sa fie 0
    RCODE = '0000'  # Bitii RCODE indica codul de raspuns al serverului


    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

# Functia pentru obtinerea domeniului request-ului
def getquestiondomain(data, index):
    domain = ''
    i = index
    length = data[i]
    while length != 0 and i < len(data):
        if (length & 0xc0) == 0xc0:
            pointer = int.from_bytes(data[i:i+2], byteorder='big') & 0x3fff
            if pointer >= len(data):
                break  # Iesim din bucla daca pointerul depaseste lungimea datelor
            label, _ = getquestiondomain(data, pointer)
            domain += label
            i += 2
            break
        if i + length >= len(data):
            break  # Iesim din bucla daca lungimea etichetei depaseste lungimea datelor disponibile
        label = data[i+1:i+length+1].decode('latin-1')
        domain += label + '.'
        i += length + 1
        length = data[i]
    return domain, i+1

# Functia pentru obtinerea inregistrarilor DNS
def getrecs(data):
    if len(data) < 14:
        return ([], '', '')  # Returneaza valori goale daca datele sunt prea scurte

    domain, questiontype = getquestiondomain(data, 12)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'  # Tipul de inregistrare 'A' (adresa IPv4)

    return ([], qt, domain)

# Functia pentru construirea intrebarii DNS
def buildquestion(domainname, rectype):
    qbytes = b''

    for part in domainname.split('.'):
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

# Functia pentru convertirea inregistrarii in formatul de octeti
def rectobytes(domainname, rectype, recttl, recval):
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes = rbytes + bytes([0]) + bytes([1])

    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes

# Functia pentru construirea raspunsului DNS
def buildresponse(data):
    TransactionID = data[:2]     # ID-ul tranzactiei

    Flags = getflags(data[2:4])  # Obtine flagurile

    QDCOUNT = b'\x00\x01'        # Numarul de intrebari

    ANCOUNT = b'\x00\x00'        # Numarul de raspunsuri

    NSCOUNT = b'\x00\x00'        # Numarul de servere DNS

    ARCOUNT = b'\x00\x00'        # Numarul de inregistrari aditionale

    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    dnsbody = b''                # Creeaza corpul DNS

    # Obtine raspunsul pentru request
    _, rectype, domain = getrecs(data[12:])  # Extrage domeniul si tipul de inregistrare din rezultatul functiei getrecs

    response_ip = '0.0.0.0' if is_blocked(domain, blocklist) else '8.8.8.8'  # Utilizeaza 8.8.8.8 ca server DNS pentru domeniile neblocate

    records = [{"ttl": 330, "value": response_ip}]  # Furnizeaza un raspuns implicit cu adresa IP corespunzatoare

    if records:
        ANCOUNT = b'\x00\x01'

    dnsquestion = buildquestion(domain, rectype)
    dnsbody += rectobytes(domain, rectype, records[0]["ttl"], records[0]["value"])

    return dnsheader + dnsquestion + dnsbody

# Verificam daca un domeniu este blocat
def is_blocked(domain, blocklist):
    return any(element in domain for element in blocklist)

# Deschidem fisierul "blocked_sites.txt" pentru a adauga domeniile blocate
g = open("/app/blocked_sites.txt", 'a')

# Setam portul si adresa IP
port = 53
ip = '127.0.0.1'

# Creem un socket pentru comunicare folosind protocolul UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Legam socketul la adresa IP si portul specificate
sock.bind((ip, port))

while True: # bucla infinita pentru a primi si trata cereri DNS
  
    data, addr = sock.recvfrom(512) # Preluam datele si adresa de la care provin

    domain, _ = getquestiondomain(data, 12) # Obtinem domeniul din request-ul DNS

    # Verificam daca domeniul este blocat
    if is_blocked(domain, blocklist):
        # Daca domeniul este blocat, adaugam in fisierul "blocked_sites.txt" dimeniile
        print(f"{domain}", file=g)

        # Construim raspunsul DNS
        response = buildresponse(data)

        # Trimitem raspunsul inapoi la adresa sursa
        sock.sendto(response, addr)
    else:
        # Daca domeniul nu este blocat, redirectionam cererea catre serverul DNS 8.8.8.8
        forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_sock.sendto(data, ('8.8.8.8', port))

        # Primim raspunsul de la serverul DNS
        response_data, _ = forward_sock.recvfrom(512)

        # Trimitem raspunsul inapoi la adresa sursa
        sock.sendto(response_data, addr)

        # inchide socketul de redirectionare
        forward_sock.close()
