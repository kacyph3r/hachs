1. Nmap: `sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local`
2. Metasploit Version Scan: `msf6 > use auxiliary/scanner/ipmi/ipmi_version`
3. Metasploit dump hashes: `msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes`