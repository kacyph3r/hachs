## **Microsoft Remote Server Administration Tools (RSAT)**
1. PowerShell - Available RSAT Tools: `Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property Name, State`
2. PowerShell - Install All Available RSAT Tools: `Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability –Online`
3. PowerShell - Install an RSAT Tool: `Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0  –Online`
### **Enumeration with RSAT**
1. CMD - MMC Runas Domain User: `runas /netonly /user:Domain_Name\Domain_USER mmc`
## **LDAP Query - User Related Search**
1. LDAP Query - User Related Search: `Get-ADObject -LDAPFilter '(objectClass=group)' | select name`
2. LDAP Query - Detailed Search: `Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol`
### **PowerShell Filters**
1. PowerShell - Filter Installed Software: `get-ciminstance win32_product | fl`
2. PowerShell - Filter Out Microsoft Software: `get-ciminstance win32_product -Filter "NOT Vendor like '%Microsoft%'" | fl`
3. PowerShell - Filter Examples: 
    - `Get-ADUser -Filter "name -eq 'sally jones'"`
    - `Get-ADUser -Filter {name -eq 'sally jones'}`
    - `Get-ADUser -Filter 'name -eq "sally jones"'`
4. PowerShell - Filter For SQL: `Get-ADComputer  -Filter "DNSHostName -like 'SQL*'"`
5. PowerShell - Filter Administrative Groups: `Get-ADGroup -Filter "adminCount -eq 1" | select Name`
6. PowerShell - Filter Administrative Users: `Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}`
7. PowerShell - Find Administrative Users with the ServicePrincipalName: `Get-ADUser -Filter "adminCount -eq '1'" -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl`
8. PowerShell - Members Of Security Operations: `Get-ADGroupMember -Identity "Security Operations"`
9. PowerShell - User's Group Membership: `Get-ADUser -Identity harry.jones -Properties * | select memberof | ft -Wrap`
10. PowerShell - All Groups of User: `Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name`
11. PowerShell - Count of All AD Users: `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count`
12. PowerShell - SearchScope Base: `Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *`
13. PowerShell - SearchScope Base OU Object: `Get-ADObject -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Base -Filter *`
14. PowerShell - Searchscope OneLevel: `Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope OneLevel -Filter *`
15. PowerShell - Searchscope 1: `Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope 1 -Filter *`
16. PowerShell - Searchscope Subtree: `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Subtree -Filter *).count`
### **LDAP Search Filters**
1. LDAP Query - Filter Disabled User Accounts: `Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name`
2. LDAP Query - Find All Groups: `Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name`
3. LDAP Query - Description Field: `Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description`
4. LDAP Query - Find Trusted Users: `Get-ADUser -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select Name,memberof, servicePrincipalName,TrustedForDelegation | fl`
5. LDAP Query - Find Trusted Computers: ` Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl`
6. LDAP Query - Users With Blank Password: `Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl`
7. LDAP Query - All Groups of User: `Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' |select Name`
### **Enumerating Active Directory with Built-in Tools**
1. List users with admin's rights: `Get-ADUser -Filter {adminCount -gt 0} -Properties admincount,useraccountcontrol | select Name,useraccountcontrol`
2. PowerView list users with admin's rights: `Get-DomainUser * -AdminCount | select samaccountname,useraccountcontrol`
3. List all users from OU with SAM and passwordneverxpired=yes: `dsquery user "OU=Employees,DC=inlanefreight,DC=local" -name * -scope subtree -limit 0 | dsget user -samid - pwdneverexpires | findstr /V no`
4. Get all groups with Get-Wmi: `Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'" | Select Caption,Name`
5. Get all objects `([adsisearcher]"(&(objectClass=Computer))").FindAll() | select Path`
## **LDAP Anonymous Bind**
Use Python to quickly check if we can interact with LDAP without credentials:
```python
from ldap3 import *
s = Server('10.129.1.207',get_info = ALL)
c =  Connection(s, '', '')
c.bind()
s.info
```
1. Using Ldapsearch: ` ldapsearch -H ldap://10.129.1.207 -x -b "dc=inlanefreight,dc=local"`
2. Using Windapsearch: `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality`
3. Pull a listing of all domain users to use in a password spraying attack: `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U`
4. Obtain information about all domain computers: `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C`
5. [ldapsearch-ad.py](https://github.com/yaap7/ldapsearch-ad) s similar to windapsearch: `python3 ldapsearch-ad.py -l 10.129.1.207 -t info`
### **Credentialed LDAP Enumeration**
1. Windapsearch: `python3 windapsearch.py --dc-ip 10.129.1.207 -u inlanefreight\\james.cross --da`
2. Some additional useful options, including pulling users and computers with unconstrained delegation: `python3 windapsearch.py --dc-ip 10.129.1.207 -d inlanefreight.local -u inlanefreight\\james.cross --unconstrained-users`
3. Ldapsearch-ad - uickly obtain the password policy: `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t pass-pols`
4. Ldapsearch-ad - look for users who may be subject to a Kerberoasting attack: `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t kerberoast | grep servicePrincipalName:`
4. Ldapsearch-ad - retrieves users that can be ASREPRoasted: `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t asreproast`
