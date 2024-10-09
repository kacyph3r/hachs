## **Installation**
**For Windows**
1. Install Java Silently: `.\jdk-11.0.17_windows-x64_bin.exe /s`
2. Unzip Neo4j: ` Expand-Archive .\neo4j-community-4.4.16-windows.zip .`
3. Install Neo4j Service: `.\neo4j-community-4.4.16\bin\neo4j.bat install-service`
4. Start Service: `net start neo4j`
5. Configure Neo4j Database:
    1. Navigate to the Neo4j web console at http://localhost:7474/
    2. Authenticate to Neo4j in the web console with username neo4j and password neo4j
6. Download BloodHound GUI:
    1. Get last version from https://github.com/BloodHoundAD/BloodHound/releases.
    2. Unzip the folder and double-click BloodHound.exe.
    3. Authenticate with the credentials you set up for neo4j
**For Linux**
1. Updating APT sources to install Java:
    1. `echo "deb http://httpredir.debian.org/debian stretch-backports main" | sudo tee -a /etc/apt/sources.list.d/stretch-backports.list`
    2. `sudo apt-get update`
2. Updating APT sources to install Neo4j:
    1. `wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -`
    2. `echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee -a /etc/apt/sources.list.d/neo4j.list`
    3. `sudo apt-get update`
3. Installing required packages: `sudo apt-get install apt-transport-https`
4. Installing Neo4j: `sudo apt list -a neo4j `
5. Installing Neo4j 4.4.X: `sudo apt install neo4j=1:4.4.16 -y`
6. Change Java version to 11: `sudo update-alternatives --config java`
7. Running Neo4j as console:
    1. `cd /usr/bin`
    2. `sudo ./neo4j console`
8. Start Neo4j: `sudo systemctl start neo4j`
9. Download and uzip BloodHound
10. Execute BloodHound:
    1. `cd BloodHound-linux-x64/`
    2. `./BloodHound --no-sandbox`
## **SharpHound - Data Collection from Windows**
1. Running SharpHound without any option: `SharpHound.exe`
2. Importing Data into BloodHound:
    1. Start service: `net start neo4j`
    2. Launch C:\Tools\BloodHound\BloodHound.exe and log in with the following credentials
    3. Click the upload button on the far right, browse to the zip file, and upload it. You will see a status showing upload % completion.
    4. Once the upload is complete, we can analyze the data. If we want to view information about the domain, we can type Domain:INLANEFREIGHT.HTB into the search box. This will show an icon with the domain name. If you click the icon, it will display information about the node (the domain), how many users, groups, computers, OUs, etc.