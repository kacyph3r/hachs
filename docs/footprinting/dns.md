1. DIG
    1. NS Query `dig ns inlanefreight.htb @10.129.14.128`
    2. Version Query `dig CH TXT version.bind 10.129.120.85`
    3. ANY Query `dig any inlanefreight.htb @10.129.14.128`
    4. DIG - AXFR Zone Transfer `dig axfr inlanefreight.htb @10.129.14.128`
    5. DIG - AXFR Zone Transfer - Internal `dig axfr internal.inlanefreight.htb @10.129.14.128`
2. Subdomain Brute Forcing
```for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done```
3. [DNSenum](https://github.com/fwaeytens/dnsenum)
```dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb```
4. Tools like Fierce can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer: `fierce --domain zonetransfer.me`
5. Subdomain Enumeration: `./subfinder -d inlanefreight.com -v `
6. Subbrute:
    1. `git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1`
    2. `cd subbrute`
    3. `echo "ns1.inlanefreight.com" > ./resolvers.txt`
    4. `./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt`
7. Enumerate the CNAME records for those subdomains: `host support.inlanefreight.com`
### **Local DNS Cache Poisoning**
1. edit the /etc/ettercap/etter.dns file to map the target domain name (e.g., inlanefreight.com) that they want to spoof and the attacker's IP address (e.g., 192.168.225.110) that they want to redirect a user to: `cat /etc/ettercap/etter.dns`
2. Start the Ettercap tool and scan for live hosts within the network by navigating to Hosts > Scan for Hosts. 
3. Add the target IP address (e.g., 192.168.152.129) to Target1 and add a default gateway IP (e.g., 192.168.152.2) to Target2.
4. Activate dns_spoof attack by navigating to Plugins > Manage Plugins. This sends the target machine with fake DNS responses that will resolve inlanefreight.com to IP address 192.168.225.110.
5. After a successful DNS spoof attack, if a victim user coming from the target machine 192.168.152.129 visits the inlanefreight.com domain on a web browser, they will be redirected to a Fake page that is hosted on IP address 192.168.225.110. In addition, a ping coming from the target IP address 192.168.152.129 to inlanefreight.com should be resolved to 192.168.225.110 as well:
