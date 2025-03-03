import socket
import glob
import json
import time
import base64

port = 53
ip = '192.168.1.155'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def to_fragments(filename, fragment_size=50):
    with open(filename, 'r') as file:
        data = file.read()
    fragments = [data[i:i+fragment_size] for i in range(0, len(data), fragment_size)]
    encoded_fragments = [base64.b64encode(fragment.encode()).decode() for fragment in fragments]
    return encoded_fragments

fragments = to_fragments('text.tunel.live')
print(fragments)

def load_zones():
    print("Loading zone files...")
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
            print(f"Loaded zone: {zonename}")
    return jsonzone

zonedata = load_zones()

def getflags(flags):
    byte1 = flags[0]
    byte2 = flags[1]

    QR = '1'
    OPCODE = ''.join(str((byte1 >> bit) & 1) for bit in range(1, 5))
    AA = '1'
    TC = '0'
    RD = '0'
    RA = '0'
    Z = '000'
    RCODE = '0000'

    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    print("Parsing domain...")
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        y += 1

    questiontype = data[y:y + 2]
    print(f"Domain parts: {domainparts}, Question type: {questiontype}")
    return (domainparts, questiontype)

def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain)
    print(f"Looking up zone for domain: {zone_name}")
    if zone_name in zonedata:
        print(f"Found zone: {zone_name}")
        return zonedata[zone_name]

    for zone in zonedata.values():
        print(f"Checking zone: {zone}")
        if "a" in zone:
            for record in zone['a']:
                if record["name"] == zone_name:
                    return zone
        if "ns" in zone:
            for record in zone['ns']:
                if record["name"] == zone_name:
                    return zone
        if "cname" in zone:
            for record in zone['cname']:
                if record["name"] == zone_name:
                    return zone

    print(f"No zone found for domain: {zone_name}")
    return None

def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'
    elif questiontype == b'\x00\x02':
        qt = 'ns'
    elif questiontype == b'\x00\x05':
        qt = 'cname'

    if '.'.join(domain) == "text.tunel.live":
        return (fragments, qt, domain)

    zone = getzone(domain)
    if not zone:
        return ([], qt, domain)

    records = [record for record in zone.get(qt, []) if record["name"] == '.'.join(domain)]
    print(f"Records found for {'.'.join(domain)} [{qt}]: {records}")
    return (records, qt, domain)

def buildquestion(domainname, rectype):
    qbytes = b''

    for part in domainname:
        length = len(part)
        qbytes += bytes([length])
        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')
    elif rectype == 'ns':
        qbytes += (2).to_bytes(2, byteorder='big')
    elif rectype == 'cname':
        qbytes += (5).to_bytes(2, byteorder='big')

    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    #print(f"Building bytes for record: {domainname} [{rectype}] TTL: {recttl}, Value: {recval}")
    rbytes = b'\xc0\x0c'  

    if rectype == 'a':
        rbytes += bytes([0]) + bytes([1])
    elif rectype == 'ns':
        rbytes += bytes([0]) + bytes([2])
    elif rectype == 'cname':
        rbytes += bytes([0]) + bytes([5])
    elif rectype == 'txt':
        rbytes += bytes([0]) + bytes([16])  

    rbytes += bytes([0]) + bytes([1])
    rbytes += int(recttl).to_bytes(4, byteorder='big')
    if rectype == 'a':
        rbytes += bytes([0]) + bytes([4])
        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    elif rectype == 'txt':
        txt_length = len(recval)
        rbytes += (txt_length + 1).to_bytes(2, byteorder='big')
        rbytes += bytes([txt_length])
        rbytes += recval.encode('utf-8')
    else:
        rbytes += (len(recval) + 1).to_bytes(2, byteorder='big')
        for part in recval.split('.'):
            rbytes += bytes([len(part)])
            for char in part:
                rbytes += ord(char).to_bytes(1, byteorder='big')
        rbytes += bytes([0])

    return rbytes

def buildresponse(data):
    TransactionID = data[:2]
    Flags = getflags(data[2:4])
    domainname, questiontype = getquestiondomain(data[12:])
    QDCOUNT = b'\x00\x01'  #one question per query
    records, rectype, domainname = getrecs(data[12:])
    ANCOUNT = len(records).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    dnsbody = b''
    dnsquestion = buildquestion(domainname, rectype)

    if '.'.join(domainname) == "text.tunel.live":
        for idx, record in enumerate(records):
            ttl = 300  # You can adjust the TTL value
            recval = f"{idx}/{len(records)} {record}"
            dnsbody += rectobytes(domainname, rectype, ttl, recval)
    else:
        for record in records:
            dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    response = dnsheader + dnsquestion + dnsbody
    print(f"Sending response: {response}")
    return response

def send_file(data, addr):
    print(f"Sending file fragments to {addr}")
    TransactionID = data[:2]
    Flags = getflags(data[2:4])
    domainname, questiontype = getquestiondomain(data[12:])
    QDCOUNT = b'\x00\x01'
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    for idx, fragment in enumerate(fragments):
        dnsheader = TransactionID + Flags + QDCOUNT + (1).to_bytes(2, byteorder='big') + NSCOUNT + ARCOUNT
        dnsquestion = buildquestion(domainname, 'txt')

        ttl = 60
        recval = f"{idx + 1}/{len(fragments)} {fragment}"
        dnsbody = rectobytes(domainname, 'txt', ttl, recval)

        response = dnsheader + dnsquestion + dnsbody
        sock.sendto(response, addr)
        print(f"Sent fragment {idx + 1} of {len(fragments)}: {recval}")

        # wait...
        while True:
            try:
                sock.settimeout(2) 
                data, _ = sock.recvfrom(512)
                domain, _ = getquestiondomain(data[12:])
                print(domain)
                if f"OK-{idx+1}" in domain:
                    print(f"OK-{idx + 1} received")
                    break
                else:
                    print("What is that?")
            except socket.timeout:
                print(f"No OK-{idx + 1}, retrying...")
                print(addr)
                sock.sendto(response, addr)
while True:
    data, addr = sock.recvfrom(512)
    domain, _ = getquestiondomain(data[12:])
    if "tunel" in domain:
        send_file(data, addr)
    else:
        r = buildresponse(data)
        sock.sendto(r, addr)
    print("+++++++++++++++++++++++++++++++++")