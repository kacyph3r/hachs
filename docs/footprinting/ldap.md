1. LDAP Anonymous Bind
    1. Confirmation that anonymous bind can be done with Python:
```python
from ldap3 import*
s = Server('10.10.10.161',get_info = ALL)
c = Connection(s,'','')
c.bind()
True
```     
3. We can confirm anonymous LDAP bind with `ldapsearch` and retrieve all AD objects from LDA: `ldapsearch -H ldap://10.129.1.207 -x -b "dc=inlanefreight,dc=local"`
2. Windapsearch
    1. `python3 [windapsearch.py](http://windapsearch.py/) --dc-ip 10.10.10.161 -u "" -U`
    2. `python3 [windapsearch.py](http://windapsearch.py/) --dc-ip 10.10.10.161 -d htb.local --custom "objectClass=*"`