# am folosit ca model https://github.com/howCodeORG/howDNS


import socket
import glob
import json

port = 53
ip = '192.168.1.155'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zones():
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
    print("...1...")
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
    return (domainparts, questiontype)

def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain)
    if zone_name in zonedata:
        return zonedata[zone_name]

    for zone in zonedata.values():
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
    print(f"Building bytes for record: {domainname} [{rectype}] TTL: {recttl}, Value: {recval}")
    rbytes = b'\xc0\x0c'

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])
    elif rectype == 'ns':
        rbytes = rbytes + bytes([0]) + bytes([2])
    elif rectype == 'cname':
        rbytes = rbytes + bytes([0]) + bytes([5])
    
    rbytes = rbytes + bytes([0]) + bytes([1])
    rbytes += int(recttl).to_bytes(4, byteorder='big')

    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])
        for part in recval.split('.'):
            rbytes += bytes([int(part)])
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
    QDCOUNT = b'\x00\x01'
    records, rectype, domainname = getrecs(data[12:])
    ANCOUNT = len(records).to_bytes(2, byteorder='big')
    NSCOUNT = (0).to_bytes(2, byteorder='big')
    ARCOUNT = (0).to_bytes(2, byteorder='big')
    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    dnsbody = b''
    dnsquestion = buildquestion(domainname, rectype)

    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    response = dnsheader + dnsquestion + dnsbody
    print(f"Sending response: {response}")
    return response

while True:
    data, addr = sock.recvfrom(512)
    print(f"Received request from {addr}: {data}")
    r = buildresponse(data)
    sock.sendto(r, addr)