## **Powershell**
1. Find the member of the some group on given host: `Get-LocalGroupMember -Group "GROUP NAME"`
2. Look at the ACL for a single domain user: `(Get-ACL "AD:$((Get-ADUser USER.NAME).distinguishedname)").access  | ? {$_.IdentityReference -eq "INLANEFREIGHT\cliff.moore"}`
3. Drill down further on this user to find all users with WriteProperty or GenericAll rights over the target user: `(Get-ACL "AD:$((Get-ADUser daniel.carter).distinguishedname)").access  | ? {$_.ActiveDirectoryRights -match "WriteProperty" -or $_.ActiveDirectoryRights -match "GenericAll"} | Select IdentityReference,ActiveDirectoryRights -Unique | ft -W`
4. Get GPO using GUID: `Get-GPO -Guid 831DE3ED-40B1-4703-ABA7-8EA13B2EB118`
5. What is the passwordhistorysize of the domain? `Get-ADDefaultDomainPasswordPolicy | Select-Object PasswordHistorySize`
6. Who is the group manager of the Citrix Admins group? `Get-ADUser -Identity "<DistinguishedName of Manager>" | Select-Object Name`

## **CMD**
1. Built-in tool that determines GPOs that have been applied to a given user or computer and their settings:
    1. `gpresult /r /user:harry.jones`
    2. `gpresult /r /S WS01`
2. What is the passwordhistorysize of the domain? `net accounts`

## **PowerView/ SharpView useful command**
1. Convert a username to the corresponding SID `.\SharpView.exe ConvertTo-SID -Name sally.jones`
2. Convert SID to a username: `.\SharpView.exe Convert-ADName -ObjectName S-1-5-21-2974783224-3764228556-2640795941-1724`
3. Get Domain Info: `.\SharpView.exe Get-Domain`
4. Get all OUs: `.\SharpView.exe Get-DomainOU | findstr /b "name"`
5. Get users with PreauthNotRequired: `.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired`
6. Gathering information about individual hosts: `Get-DomainComputer | select dnshostname, useraccountcontrol`
7. Return all Group Policy Objects (GPOs) names: `.\SharpView.exe Get-DomainGPO | findstr displayname`
8. Determine which GPOs map back to which hosts: `Get-DomainGPO -ComputerIdentity WS01 | select displayname`
9. Check if our current user has local admin rights on any remote hosts: `Test-AdminAccess -ComputerName SQL01`
10. Eenumerate open shares on a remote computer: `.\SharpView.exe Get-NetShare -ComputerName DC01`
11. Find domain machines that users are logged into: `Find-DomainUserLocation`
12. All domain trusts for our current domain: `Get-DomainTrust`

### **Enumerating AD users**
1. Users number: `(Get-DomainUser).count`
2. Get user with properties: `Get-DomainUser -Identity USER-NAME -Domain DOMAIN-NAME | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol`
3. Enumerate these properties for ALL domain users and export them to a CSV file: `Get-DomainUser * -Domain DOMAIN-NAME | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol | Export-Csv .\inlanefreight_users.csv -NoTypeInformation`
4. Obtaining a list of users that do not require Kerberos pre-authentication and can be subjected to an **ASREPRoast attack**: `.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired -Properties samaccountname,useraccountcontrol,memberof`
5. Gather information about users with Kerberos constrained delegation: `.\SharpView.exe Get-DomainUser -TrustedToAuth -Properties samaccountname,useraccountcontrol,memberof`
6. Users that allow unconstrained delegation: `.\SharpView.exe Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"`
7. Any domain users with sensitive data such as a password stored in the description field: `Get-DomainUser -Properties samaccountname,description | Where {$_.description -ne $null}`
8. Enumerate any users with Service Principal Names (SPNs) that could be subjected to a **Kerberoasting attack**: `.\SharpView.exe Get-DomainUser -SPN -Properties samaccountname,memberof,serviceprincipalname`
9. Enumerate any users from other (foreign) domains with group membership within any groups in our current domain: `Find-ForeignGroup`
10. Checking for users with Service Principal Names (SPNs) set in other domains that we can authenticate into via inbound or bi-directional trust relationships with forest-wide authentication allowing all users to authenticate across a trust or selective-authentication set up which allows specific users to authenticate: `Get-DomainUser -SPN -Domain freightlogistics.local | select samaccountname,memberof,serviceprincipalname | fl`
11. Display all password set times: `Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon -Domain InlaneFreight.local | select samaccountname, pwdlastset, lastlogon | Sort-Object -Property pwdlastset`
12. If you want only to show passwords set before a certain date: `Get-DomainUser -Properties samaccountname,pwdlastset,lastlogon -Domain InlaneFreight.local | select samaccountname, pwdlastset, lastlogon | where { $_.pwdlastset -lt (Get-Date).addDays(-90) }`
### **Enumerating AD Groups**
1. Get Domain's Groups: `Get-DomainGroup -Properties Name`
2. Use Get-DomainGroupMember to examine group membership in any given group: `.\SharpView.exe Get-DomainGroupMember -Identity 'Help Desk'`
3. Look for all AD groups with the AdminCount attribute set to 1, signifying that this is a protected group: `.\SharpView.exe Get-DomainGroup -AdminCount`
4. Look for any managed security groups: `Find-ManagedSecurityGroups | select GroupName`
5. Look at the Security Operations group and see if the group has a manager set: `Get-DomainManagedSecurityGroup`
6. Enumerating the ACLs set on this group: 
    1. `$sid = ConvertTo-SID user-name`
    2. `Get-DomainObjectAcl -Identity 'Security Operations' | ?{ $_.SecurityIdentifier -eq $sid}`
7. Check local group membership: `Get-NetLocalGroup -ComputerName WS01 | select GroupName`
8. Enumerate the local group members on any given host: `.\SharpView.exe Get-NetLocalGroupMember -ComputerName WS01`
9. Same function to check all the hosts that a given user has local admin access:
    1. `$sid = Convert-NameToSid USER-NAME`
    2. `$computers = Get-DomainComputer -Properties dnshostname | select -ExpandProperty dnshostname`
    3. `foreach ($line in $computers) {Get-NetLocalGroupMember -ComputerName $line | ? {$_.SID -eq $sid}}`
### **Enumerating AD Computers**
1. Get hostname, operating system, and User Account Control (UAC) attributes and save to file: `.\SharpView.exe Get-DomainComputer -Properties dnshostname,operatingsystem,lastlogontimestamp,useraccountcontrol | Export-Csv .\inlanefreight_computers.csv -NoTypeInformation`
2. Find to any computers in the domain are configured to allow unconstrained delegation and find one, the domain controller, which is standard: `.\SharpView.exe Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol`
3. Check for any hosts set up to allow for constrained delegation: `Get-DomainComputer -TrustedToAuth | select -Property dnshostname,useraccountcontrol`
### **Enumerating Domain ACLs**
1. Look at the ACL for a single domain user: `Get-DomainObjectAcl -Identity USER.NAME -Domain inlanefreight.local -ResolveGUIDs`
2. Seek out ACLs on specific users and filter out results using the various AD filters: `Find-InterestingDomainAcl -Domain inlanefreight.local -ResolveGUIDs`
3. Look at the ACLs set on file shares: 
    1. `Get-NetShare -ComputerName SQL01`
    2.  `Get-PathAcl "\\SQL01\DB_backups"`
4. Use the Get-ObjectACL function to search for all users that have these rights: `Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object SecurityIdentifier | Sort-Object -Property SecurityIdentifier -Unique`
5. Convert the SID back to the user: `convertfrom-sid S-1-5-21-2974783224-3764228556-2640795941-1883`
6. Point 5 and 6 can be done:
    1. `$dcsync = Get-ObjectACL "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ObjectAceType -match 'Replication-Get')} | Select-Object -ExpandProperty SecurityIdentifier | Select -ExpandProperty value`
    2. `Convert-SidToName $dcsync`
### **Enumerating Group Policy Objects (GPOs)**
1. Gathering GPO names: `Get-DomainGPO | select displayname`
2. Check which GPOs apply to a specific computer: `Get-DomainGPO -ComputerName WS01 | select displayname`
3. We can use the Get-DomainGPO and Get-ObjectAcl using the SID for the Domain Users group to see if this group has any permissions assigned to any GPOs: `Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq 'S-1-5-21-2974783224-3764228556-2640795941-513'}`
### **Enumerating AD Trusts**
1. Get Domain Trust: `Get-DomainTrust`
2. Use the function Get-DomainTrustMapping to enumerate all trusts for our current domain and other reachable domains: `Get-DomainTrustMapping`
### **Various**
1. Test Admin Access: `Test-AdminAccess -ComputerName ACADEMY-EA-MS01`
2. Finding Users With SPN Set: `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName`
3. 

#### **Links**
1. [https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2022_11.svg)
2. [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) is an excellent tool that can be used to take advantage of GPO misconfigurations.