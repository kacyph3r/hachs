1. Nmap: `nmap -sV -sC 10.129.201.248 -p3389 --script rdp*`
2. [rdp-sec-check](https://github.com/CiscoCXSecurity/rdp-sec-check)
    1. `git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check`
    2. `./rdp-sec-check.pl 10.129.201.24` 
3. Initiate an RDP Session
    1. `xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248`
    2. `xfreerdp /u:username /p:password /v:10.129.75.180 /cert-ignore /bpp:8 /network:modem /compression -themes -wallpaper /clipboard /audio-mode:1 /auto-reconnect -glyph-cache /dynamic-resolution /drive:linux,/`