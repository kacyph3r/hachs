1. Nmap
    1. `sudo nmap 10.129.14.128 -sC -sV -p25`
    2. `sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`
2. Commands
```bash
AUTH PLAIN AUTH #is a service extension used to authenticate the client.                                   |
HELO #The client logs in with its computer name and thus starts the session.                         |
MAIL FROM #The client names the email sender.                                                             |
RCPT TO #The client names the email recipient.                                                          |
DATA #The client initiates the transmission of the email.                                            |
RSET #The client aborts the initiated transmission but keeps the connection between client and server.|
VRFY #The client checks if a mailbox is available for message transfer.                              |
EXPN #The client also checks if a mailbox is available for messaging with this command.              |
NOOP #The client requests a response from the server to prevent disconnection due to time-out.       |
QUIT #The client terminates the session. 
```
