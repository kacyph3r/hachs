1. Nmap: `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248`
2. MSSQL Ping in Metasploit: `msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248`
3. Connecting with Mssqlclient.py
    1. connect `python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth`
    2. Interact with: `select name from sys.databases`