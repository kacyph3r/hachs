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
