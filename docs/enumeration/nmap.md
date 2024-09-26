1. Host discovery: `sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5`
2. Scanning from IP list file: `sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5`
3. Scan Multiple IPs: `sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5`
4. Scan Single IP: `sudo nmap 10.129.2.18 -sn -oA host`
5. Discovering Open UDP Ports: `sudo nmap 10.129.2.28 -F -sU`
6. Banner Grabbing: `sudo nmap 10.129.2.28 -p- -sV`
7. Specifying Scripts: `sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands`
8. Vuln Category: `sudo nmap 10.129.2.28 -p 80 -sV --script vuln`
9. Optimized RTT: `sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms`
10. Decoy: `sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5`