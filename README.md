# Networking-Fundamentals

This project contains Python scripts that demonstrate key network security concepts, including ARP Spoofing, TCP Hijacking, Traceroute, DNS Server, and DNS Tunnel. These scripts are educational and aim to show how certain attacks can be executed and what security risks exist in modern networks.

## Features

1. **ARP Spoofing**  
   The ARP Spoofing script is designed to perform a man-in-the-middle (MITM) attack by poisoning the ARP tables of two devices. It allows an attacker to intercept traffic between a victim and a gateway by associating the attacker’s MAC address with the gateway's IP address.

2. **TCP Hijacking**  
   Extending the ARP Spoofing attack, the TCP Hijacking script enables interception, alteration, and injection of malicious content into an active TCP session. It positions the attacker between the client and server to hijack TCP packets in transit.

3. **Traceroute**  
   This custom traceroute tool uses ICMP and UDP protocols to send packets with incrementally increasing Time-To-Live (TTL) values, tracing the path packets take to a destination. For each hop, it resolves IP addresses to hostnames and gathers geographical data (country, region, city) using the IP-API service, with an interactive map visualization of the route.

4. **DNS Server**  
   This component implements a minimal DNS server application inspired by course materials and online tutorials. It is configured to handle a custom domain and subdomain, allowing you to test DNS entries using tools like dig or nslookup.

5. **DNS Tunnel**  
   The DNS Tunnel script demonstrates how to create a covert data channel by utilizing malformed DNS packets. It implements a client-server model for file transfer over DNS, featuring mechanisms (such as stop-and-wait or sliding window) to handle UDP packet loss and ensure complete file transmission verified by an MD5 checksum.

## Docker Testing

For testing the ARP spoofing and TCP hijacking functionalities, a Docker environment was set up with four containers: client, server, middle, and router. This configuration simulates a real-world attack scenario, where the client and middle containers share a network via the router. The `docker-compose.yml` file defines the services, their relationships, IP addresses, and necessary network privileges. Additionally, the `tcp_client.py` and `tcp_server.py` scripts are used to generate traffic between the client and server, facilitating packet monitoring and manipulation as they traverse the network.