# Networking-Fundamentals

This project contains Python scripts that demonstrate key network security concepts, including **ARP Spoofing**, **TCP Hijacking**, and **Traceroute**. These scripts are educational and aim to show how certain attacks can be executed and what security risks exist in modern networks. 

## Features

### 1. ARP Spoofing
The ARP Spoofing script is designed to perform a man-in-the-middle (MITM) attack by poisoning the ARP tables of two devices. It allows an attacker to intercept traffic between the victim and the gateway (or router) by associating the attacker’s MAC address with the IP address of the gateway, making the victim send traffic to the attacker.

### 2. TCP Hijacking
This script extends the ARP Spoofing attack by performing **TCP Hijacking**. The script allows an attacker to intercept, alter, and inject malicious content into an ongoing TCP session. It starts with an ARP spoofing attack to position the attacker between the client and server and then hijacks TCP packets in transit.

### 3. Traceroute
This script implements a custom traceroute tool that traces the path packets take to reach a specified destination. It utilizes ICMP and UDP protocols to send packets with incrementally increasing Time-To-Live (TTL) values, allowing it to identify each hop along the route. For each hop, the script attempts to resolve the IP addresses to hostnames and gathers geographical information such as country, region, and city using the IP-API service. Additionally, the script visualizes the traceroute results on an interactive map, enabling users to see the journey taken by the packets visually.

### Docker Testing

For testing the ARP spoofing and TCP hijacking, I used a Docker environment consisting of four containers: `client`, `server`, `middle`, and `router`. This configuration simulates a real-world attack scenario, where the `client` and `middle` containers are connected to the same network via the `router`. The `docker-compose.yml` file defines the services and their relationships, specifying IP addresses and enabling necessary privileges for network operations. To generate traffic between the `client` and `server`, I utilized `tcp_client.py` and `tcp_server.py` scripts, facilitating the monitoring and manipulation of packets as they traverse the network.
