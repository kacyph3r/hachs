1. SNMPwalk: `snmpwalk -v2c -c public 10.129.14.128`
2. OneSixtyOne: 
    1. `sudo apt install onesixtyone`
    2. `onesixtyone -c /opt/useful/SecLists/Discovery/SNMP/snmp.txt 10.129.14.128`
3. Braa:
    1. `sudo apt install braa`
    2. `braa <community string>@<IP>:.1.3.6.*   # Syntax`
    3. `braa public@10.129.14.128:.1.3.6.* # example`
    