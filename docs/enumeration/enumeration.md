### Host discovery
**Powershell**
```powershell
1..254 | % { $ip="172.30.0.$_"; if (ping -n 1 -w 100 $ip | Select-String "TTL=") { "$ip is up" } }
```

**Bash**
```bash
for ip in 172.30.0.{1..254}; do ping -c 1 -W 1 $ip >/dev/null 2>&1 && echo "$ip is up"; done
```
**NC port scanner**
`nc -w 1 -v ip-address 1-100 2>&1 | grep -v refused`
### Rustscan
```bash
sudo apt install cargo
cargo install rustscan
export PATH=$PATH:/path/to/rustscan
chmod +x /path/to/rustscan
echo 'export PATH=$PATH:/root/.cargo/bin' >> ~/.bashrc
source ~/.bashrc
rustscan --version
rustscan -a 172.20.0.52 -r 1-1000 //r - port range
rustscan -a 172.20.0.52 -r 1-1000 -u -- -Pn //no ping

```