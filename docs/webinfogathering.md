## Whois
`whois inlanefreight.com`

## Dig
1. Performs a default A record lookup for the domain: `dig domain.com `
2. Retrieves the IPv4 address (A record) associated with the domain: `dig domain.com A `
3. Retrieves the IPv6 address (AAAA record) associated with the domain: `dig domain.com AAAA`
4. Finds the mail servers (MX records) responsible for the domain: `dig domain.com MX`
5. Identifies the authoritative name servers for the domain: `dig domain.com NS`
6. Retrieves any TXT records associated with the domain: `dig domain.com TXT `
7. Retrieves the canonical name (CNAME) record for the domain: `dig domain.com CNAME `
8. Retrieves the start of authority (SOA) record for the domain: `dig domain.com SOA`
9. pecifies a specific name server to query; in this case 1.1.1.1: `dig @1.1.1.1 domain.com`
10. Shows the full path of DNS resolution: `dig +trace domain.com`
11. Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server: `dig -x 192.168.1.1 `
12. Provides a short, concise answer to the query: `dig +short domain.com`
13. Displays only the answer section of the query output: `dig +noall +answer domain.com `
14. Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)): `dig domain.com ANY`

## **Subdomain enumeration**
### Dnsenum
`dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r`

## **DNS Zone Transfers**
`dig axfr @nsztm1.digi.ninja zonetransfer.me`

## Virtual hosts
`gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain`

## crt.sh
`curl -s "[https://crt.sh/?q=facebook.com&output=json](https://crt.sh/?q=facebook.com&output=json)" | jq -r '.[]
| select(.name_value | contains("dev")) | .name_value' | sort -u`

## Banner grabbing
`curl -I inlanefreight.com`

## WAF detection
### wafw00f
1. `pip3 install git+https://github.com/EnableSecurity/wafw00f`
2. `wafw00f inlanefreight.com`

## Crawling
### ReconSpider
1. `wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip`
2. `unzip ReconSpider.zip`
3. `python3 ReconSpider.py http://inlanefreight.com` 

## **Reconnaissance Frameworks**
1. FinalRecon
2. Recon-ng
3. theHarvester
4. SpiderFoot
5. OSINT Framework
#### **FinalRecon**
1. `git clone https://github.com/thewhiteh4t/FinalRecon.git`
2. `cd FinalRecon`
3. `pip3 install -r requirements.txt`
4. `chmod +x ./finalrecon.py`
5. `./finalrecon.py --help`
6. `./finalrecon.py --headers --whois --url http://inlanefreight.com`