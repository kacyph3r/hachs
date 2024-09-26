1. Anonymous Login: `ftp 10.129.14.136` 
2. Download file: `get filename`
3. Download All Available Files: `wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136`
4. Upload a File: `put testupload.txt`
5. Nmap:
    1. `find / -type f -name ftp* 2>/dev/null | grep scripts`
    2. `sudo nmap -sV -p21 -sC -A 10.129.14.136` `—scripts —script-trace`