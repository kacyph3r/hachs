1. Find all IPs in file: `grep -oP '(\d{1,3}\.){3}\d{1,3}' 80.txt > ips.txt`
2. (Get-Content "80.txt")[0..10] | ForEach-Object { Start-Process "http://$_" }
