import socket
import traceback
import random
import json
import requests
import folium


def create_map(coordinates, html_file):
    start_coords = (coordinates[0][0], coordinates[0][1])
    line_coords = []
    m = folium.Map(location = start_coords, zoom_start = 25)

    for lat, lon, label in coordinates:
        folium.Marker(location=[lat, lon], popup=label, tooltip=label).add_to(m)
        line_coords.append((lat, lon))

    folium.PolyLine(locations = line_coords, color = 'red').add_to(m)

    m.save(html_file)

def geo_location(ip_list):
    coords = []
    countries = []
    regions = []
    cities = []
    orgs = []
    ip_infos_dict = {}
    url = "http://ip-api.com/batch"
    fake_HTTP_header = {
                    'referer': 'http://ip-api.com/batch/',
                    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36'
                        }
    payload = json.dumps(ip_list)
    
    try:
        response = requests.post(url, data = payload, headers = fake_HTTP_header)
        response.raise_for_status()
        
        ip_details = response.json()
        for ip_info in ip_details:
            print(f"IP: {ip_info.get('query')}")
            if ip_info.get('status') == 'success':
                print(f"  Country: {ip_info.get('country')}")
                print(f"  Region: {ip_info.get('regionName')}")
                print(f"  City: {ip_info.get('city')}")
                print(f"  Org: {ip_info.get('org')}")
                ip_infos_dict[ip_info.get('query')] = [ip_info.get('country'), ip_info.get('regionName'), ip_info.get('city'), ip_info.get('org'), ip_info.get('lat'), ip_info.get('lon')]
            else:
                print("  Eroare: Nu s-au putut obține detalii pentru acest IP")
            print() 
    except requests.exceptions.RequestException as e:
        print(f"Eroare la cererea către ip-api: {e}")
    return ip_infos_dict


def traceroute(dest_name, max_hops = 30):
    traceroute_addresses = []
    ICMP = socket.getprotobyname('icmp')
    UDP = socket.getprotobyname('udp')

    dest_addr = socket.gethostbyname(dest_name)
    udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP)
    icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP)
    
    print(f"Traceroute la {dest_name}, ip ({dest_addr}), {max_hops} max hops")

    for ttl in range(1, max_hops + 1):
        udp_send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        icmp_recv_socket.settimeout(3)
        
        port = random.randint(33434, 33534)
        udp_send_sock.sendto(b'', (dest_addr, port))
        
        tries = 3
        success = False
        found = False
        
        while (tries > 0) and (not success) and (not found):
            try:
                data, addr = icmp_recv_socket.recvfrom(512)
                success = True
            except socket.timeout:
                tries -= 1
            if addr[0] == dest_addr:
                found = True 
                break
            
        if success:
            traceroute_addresses.append(addr[0])
            try:
                name = socket.gethostbyaddr(addr[0])[0]
                print(f"TTL: {ttl}\tIP: {addr[0]}\tNAME: {name}")
            except:
                print(f"TTL: {ttl}\tIP: {addr[0]}")
        else:
            print(f"TTL: {ttl}\t*  *  *")
            
        if found:
            udp_send_sock.close()
            icmp_recv_socket.close()
            print("Traceroute terminat.")
            return True, traceroute_addresses
            break
    udp_send_sock.close()
    icmp_recv_socket.close()
    print("Incercare esuata")
    return False, traceroute_addresses


                




def procesare(file_name, tests):
    with open(file_name, 'w') as f:
        for test in tests:
            for addr_name in test:
                result, traceroute_addresses = traceroute(addr_name)
                if result:
                    ip_infos = geo_location(traceroute_addresses)
                    coords = []
                    i = 1
                    f.write("Adresa: " + addr_name + '\n')
                    f.write("Traceroute:\n")
                    for addr in traceroute_addresses:
                        if addr in ip_infos:
                            f.write("\t->IP: " + addr + "\tTara: " + ip_infos[addr][0] + ", Regiunea: " + ip_infos[addr][1] + ", Orasul: " + ip_infos[addr][2] + ", Organizatie: " + ip_infos[addr][3] + '\n')
                            coords.append((ip_infos[addr][4], ip_infos[addr][5], str(i) + ": " + addr))
                            i += 1
                        else:
                            f.write("\t->IP: " + addr + "\tDetalii indisponibile!\n")
                    f.write('\n\n')
                    
                    if coords:
                        html_file = 'traceroute_maps/traceroute_' + addr_name + '_map.html'
                        create_map(coords, html_file)
                else:
                    if traceroute_addresses:
                        traceroute_failed = "->".join(failed_addr for failed_addr in traceroute_addresses)
                        f.write("Adresa: " + addr_name + '\t' + traceroute_failed + '\n\n') 
                    else:
                        f.write("Adresa: " + addr_name + '\t' + "" + '\n\n') 
        

ip_asia = ["www.cnnic.com.cn", "m.weibo.cn", "alibaba.cn"]
ip_africa = ["Google.co.za", "Iol.co.za", "Uct.ac.za"]
ip_australia = ["Abc.net.au", "Smh.com.au", "Vic.gov.au"]
ip_basic = ["google.com", "youtube.com", "github.com"]

tests = [ip_basic, ip_asia, ip_africa, ip_australia]

procesare("test_acasa.txt", tests)


