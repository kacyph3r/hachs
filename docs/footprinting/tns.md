1. Nmap
    1. `sudo nmap -p1521 -sV 10.129.204.235 --open`
    2. `sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute`
2. [odat.py](http://odat.py/) 
`./odat.py all -s 10.129.204.235`
3. SQLplus - for log In: `sqlplus scott/tiger@10.129.204.235/XE`
4. [SQLplus commands](https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985)