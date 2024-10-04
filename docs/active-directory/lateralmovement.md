## **Kerberos "Double Hop" Problem**
#### **Workaround #1: PSCredential Object**
1. Try to execute a command: `*Evil-WinRM* PS C:\Users\backupadm\Documents> import-module .\PowerView.ps1`
2. Check with klist: `*Evil-WinRM* PS C:\Users\backupadm\Documents> klist`
3. Set up a PSCredential object and try again to execute a command: 
    1. `*Evil-WinRM* PS C:\Users\backupadm\Documents> $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force`
    2. `$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)`
    3. `*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname`
#### **Workaround #2: Register PSSession Configuration**
1. Establishing a WinRM session on the remote host: `Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm`
2. Check tickets with klist: `klist`
3. One trick we can use here is registering a new session configuration using the Register-PSSessionConfiguration cmdlet: `Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm`
4. Restart the WinRM service by typing `Restart-Service WinRM` in current PSSession.
5. Check again with `klist` and the double hop problem has been eliminated.
