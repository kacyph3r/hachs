**PowerShell Execution Policy - how to bypass:** 
1. `powershell -ExecutionPolicy bypass` 
2. `powershell -c <cmd>` 
3. `powershell -encodedcommand` 
4. `$env:PSExecutionPolicyPreference="bypass"`
# **Domain Enumeration**
## **Built-in tools**
1. $ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
2. $ADClass::GetCurentDomain()
To speed up things use PowerView.ps1 or ActiveDirectory PowerShell module
**Enumerate following for given domain:**
1. Users
2. Computers
3. Domain Administrators
4. Enterprase Administrators
5. Shares
## **PowerView** 
1. Enumerate Domain: `Get-NetDoamin` 
2. Get object of another domain: `Get-NetDomain -Domain domain-name`
3. Get Domain SID: `Get-DoaminSID` 
4. Get Domain Policy: `Get-DomainPolicy`
5. Get default Domain Policy for machines: `(Get-DomainPolicy)."system access"`
6. Get Kerberos policy : `(Get-DomainPolicy)."Kerberos Policy"`
7. Get info about DC: `Get-NetDomainController`
8. Get info about DC from another doamin: `Get-NetDomainController -Domain domain-name` 
9. List all users: `Get-NetUser` 
10. List all users and select property: `Get-NetUser | select cn` 
11. Get particular user: `Get-NetUser -UserName user-name` 
12. Checking description property for find passwords: `Find-UserField -SearchField Description -SearchTerm password`
13. Get computers from current domain: `Get-NetComputer`
14. Get all groups in current domain: `Get-NetGroup`
15. Get all members of the group: `Get-NetGroupMember -GroupName "Domain Admins" -Recurse`
16. Get group membership for a user: `Get-NetGroup -UserName "user-name"`
17. Get local groups: `Get-NetLocalGroup -ComputerName computer-name -ListGroups`
18. Get actively logged users: `Get-NetLoggedon -ComputerName computer-name`
19. Find shares on host in current domain: `Invoke-ShareFInder -Verbose`
20. Find sensitive files on computer in current domain: `Invoke-FileFinder -Verbose`
21. Get all fileservers of the domain: `Get-NetFileServer`

## **ActiveDirectory Module**
1. Import AD module:
     1. `Import-Module .\Microsoft.ActiveDirectory.Management.dll`
     2. `Import-Module .\ActiveDirectory\ActiveDirectory.psdl`
2. Enumerate Domain: `Get-ADDomain`
3. Get object of another domain: `Get-ADDomain -Identity domain-name`
4. Get Domain SID: `(Get-ADDomain).DomainSID`
5. Get Domain Policy: ` `
6. Get info about DC: `Get-ADDomainController` 
7. Get info about DC from another domain: `Get-ADDomainController -Identity domain-name` 
8. Get all users: `Get-ADUser -Filter *` 
9. Get all users and select property: `Get-ADUser -Filter * - Properties name` 
10. Get particular user with all properties: `Get-ADUser -Identity user-name -Properties *` 
11. Get password last set for all users: `Get-UserProperty -Properties pwdlastset` 
12. Checking description property for find passwords: `Get-ADUser -Filter 'Description -like "password"' -Properties Description | select Name,Description`
13. Get Computer from current domain: `Get-ADComputer -Filter *`
14. Get all groups in current domain: `Get-ADGroup -Filter *`
15. Get all members of the group: `Get-ADGroupMember -Identity "Domain Admins" -Recursive`
16. Get group membership for a user: `Get-ADPrincipalGroupMembership -Identity user-name`
17. Get local groups: `