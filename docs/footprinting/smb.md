####Nmap 
`sudo nmap 10.129.14.128 -sV -sC -p139,445`

####SMBclient
```bash
smbclient -N -L //10.129.14.128 # no logon
smbclient //10.129.14.128/notes # connecting to share
```
####Download Files
`get file_name`

####Brute Forcing User RIDs
######Bash
```bash
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
######Python
Script from [Impacket](https://github.com/SecureAuthCorp/impacket) called [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py).
    `samrdump.py 10.129.14.128`
####Crackmapexec
`crackmapexec smb 10.129.14.128 --shares -u '' -p ''`
####RPCclient:
`rpcclient -U "" 10.129.14.128`
```bash
srvinfo
enumdomains
querydominfo
netshareenumall
netsharegetinfo notes
enumdomusers
queryuser 0x3e9
querygroup 0x201
```
####SMBMap
`smbmap -H 10.129.14.128`

####Enum4Linux:
```bash
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt
./enum4linux-ng.py 10.129.14.128 -A
```

#### HYDRA
`hydra -L user.list -P password.list smb://10.129.42.197`