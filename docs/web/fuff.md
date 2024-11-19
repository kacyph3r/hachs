1. ffuf help: `ffuf -h`
2. Directory Fuzzing: `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`
3. Extension Fuzzing: `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`
4. Page Fuzzing: `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`
5. Recursive Fuzzing: `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`
6. Sub-domain Fuzzing: `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`
7. VHost Fuzzing: `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H `Host: FUZZ.academy.htb` -fs xxx`
8. Parameter Fuzzing - GET: `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`
9. Parameter Fuzzing - POST: `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d "FUZZ=key" -H "Content-Type: application/x-www-form-urlencoded" -fs xxx`
10. Value Fuzzing: `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d "id=FUZZ" -H Content-Type: application/x-www-form-urlencoded" -fs xxx`
