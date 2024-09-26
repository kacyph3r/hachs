1. Nmap:
    1. `sudo nmap 10.129.14.128 -p111,2049 -sV -sC`
    2. `sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049`
2. Show Available NFS Shares: `showmount -e 10.129.14.128`
3. Mounting NFS Share:
```bash
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .
```
4. List Contents with Usernames & Group Names: `ls -l mnt/nfs/`
5. List Contents with UIDs & GUIDs: `ls -n mnt/nfs/`
6. Unmounting:
    1. `cd ..`
    2. `sudo umount ./target-NFS`