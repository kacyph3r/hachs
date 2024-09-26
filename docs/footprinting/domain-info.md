1. Certificate Transparency: `curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .`
2. Filtered by the unique subdomains: `curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep`
3. Identify the hosts directly accessible from the Internet and not hosted by third-party providers: `for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done`
4. Shodan: 
    1. `for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done`
    2. `for i in $(cat ip-addresses.txt);do shodan host $i;done`
5. Display all the available DNS records where we might find more hosts: `dig any inlanefreight.com`

### Cloud Resources
1. Company Hosted Servers: `for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done`
2. Google Search for AWS: `intext:sometexthere inurl:amazonaws.com`
3. Google Search for Azure: `intext:sometexthere inurl:blob.core.windows.net`
