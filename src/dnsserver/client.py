import base64
from scapy.sendrecv import sr1
from scapy.all import IP, UDP, DNS, DNSQR

def send_dns_query(dst_ip, query_name, query_type):
    network_layer = IP(dst=dst_ip)
    transport_layer = UDP(dport=53)
    
    dns = DNS(rd=1)
    dns_query = DNSQR(qname=query_name, qtype=query_type)
    dns.qd = dns_query
    
    packet = network_layer / transport_layer / dns
    
    answer = sr1(packet, timeout=5)  
    
    if answer:
        print(answer[DNS].summary())
        return answer
    else:
        print("No response received.")
        return None

def extract_fragment_index(data):
    fragment_info = data.split(' ')[0]
    fragment_index = int(fragment_info.split('/')[0])
    return fragment_index

def decode_fragment(data):
    fragment = data.split(' ')[1]  
    decoded_fragment = base64.b64decode(fragment).decode('utf-8')
    return decoded_fragment

if __name__ == "__main__":
    dst_ip = '192.168.1.155'
    query_name = 'text.tunel.live'
    query_type = 'TXT'
    fragments = []

    if query_type.upper() == "A":
        qtype = 1
    elif query_type.upper() == "NS":
        qtype = 2
    elif query_type.upper() == "CNAME":
        qtype = 5
    elif query_type.upper() == "TXT":
        qtype = 16
    
    while True:
        answer = send_dns_query(dst_ip, query_name, qtype)
        if not answer:
            break
        data = answer[DNS].an.rdata.decode()
        fragment_index = extract_fragment_index(data)
        decoded_fragment = decode_fragment(data)
        fragments.append((fragment_index, decoded_fragment))
        print(f"Received fragment {fragment_index}: {decoded_fragment}")
        query_name = f"OK-{fragment_index}.text.tunel.live"

    fragments.sort()
    complete_message = ''.join(fragment for _, fragment in fragments)
    print(f"Complete message: {complete_message}")

    with open('output.txt', 'w') as f:
        f.write(complete_message)