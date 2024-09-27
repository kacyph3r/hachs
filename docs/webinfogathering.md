## Whois
`whois inlanefreight.com`

## Dig
```bash
dig domain.com` #Performs a default A record lookup for the domain.
dig domain.com A #Retrieves the IPv4 address (A record) associated with the domain.
dig domain.com AAAA #Retrieves the IPv6 address (AAAA record) associated with the domain.
dig domain.com MX #Finds the mail servers (MX records) responsible for the domain.
dig domain.com NS #Identifies the authoritative name servers for the domain.
dig domain.com TXT #Retrieves any TXT records associated with the domain.
dig domain.com CNAME #Retrieves the canonical name (CNAME) record for the domain.
dig domain.com SOA #Retrieves the start of authority (SOA) record for the domain.
dig @1.1.1.1 domain.com #Specifies a specific name server to query; in this case 1.1.1.1
dig +trace domain.com #Shows the full path of DNS resolution. |
dig -x 192.168.1.1 #Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.
dig +short domain.com #Provides a short, concise answer to the query.
dig +noall +answer domain.com #Displays only the answer section of the query output.
dig domain.com ANY #Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)).
```
## Subdomain enumeration
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
