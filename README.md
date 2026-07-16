# SMB-Scanner
A Python tool that connects to SMB shares and scans for exposed credentials, API keys, tokens, and other sensitive information in files.

## Disclaimer
This software uses the Impacket library (https://github.com/SecureAuthCorp/impacket), which is licensed under the Apache License, Version 2.0.

## Features
- **Automated SMB Share Discovery** - Enumerate available SMB shares on the target system
- **Comprehensive File Scanning** - Recursively scan directories for sensitive data patterns
- **Custom Regex Patterns** - Pre-configured and customizable regex for common sensitive data types
- **Credential Support** - Authenticated scanning with domain/user credentials (password or Pass-The-Hash authentication)

The tool scans for:
- Passwords, API Keys, Tokens, Database Credentials, Private Keys, email addresses, URLs, Usernames etc.

## Installation
### Pre-requisites
- Impacket

### Quick Install
1. Install via pipx
```
pipx install git+https://github.com/0xyngtg/SMB-Scanner
```
## Usage
### Basic Usage
```sh
$ smbscanner -h
smbscanner -h                                                                                                
usage: smbscanner.py [-h] -t TARGET [-u USER] [-p PASSWORD] [-d DOMAIN] [-H HASHES] [-s SHARE] [-v] [--path PATH] [--scan] [--recursive] [--regex REGEX] [--log LOG] [--port PORT]
                     [--read READ] [--write WRITE WRITE] [--download DOWNLOAD DOWNLOAD] [--map MAP]

A simple tool that connects to a SMB server and magically finds credentials!

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target IP address or hostname
  -u, --user USER       Username
  -p, --password PASSWORD
                        Password
  -d, --domain DOMAIN   Domain
  -H, --hashes HASHES   LM:NT hashes
  -s, --share SHARE     (Case-sensitive!) Share to connect to
  -v, --verbose         Adds verbosity level
  --path PATH           Base Path relative to the given share! SPECIFY THE TARGET SHARE WITH '-s <SHARE>'
  --scan                Turns on the scan mode, which will read all files on the Share and find patterns that potentially represent sensitive information
  --recursive           Turns on recursive mode! RECOMMENDED TO SPECIFY THE TARGET SHARE WITH '-s <SHARE>'
  --regex REGEX         Uses a custom regex pattern to scan for secrets (ONLY ONE REGEX PATTERN)
  --log LOG             Log File Name
  --port PORT           Port to connect to
  --read READ           Reads a specific file. Required to provide the -s <SHARE> option.
  --write WRITE WRITE   Writes to a specific file. Requires 2 arguments: <LOCAL-FILE> <REMOTE-FILE>. Required to provide the -s <SHARE> option.
  --download DOWNLOAD DOWNLOAD
                        Downloads a remote file. Requires 2 arguments: <REMOTE-FILE> <LOCAL-FILE>. Required to provide the -s <SHARE> option.
  --map MAP             After the first run the script will output a JSON file containing the share map. This file can be loaded to avoid remapping the share once again.
```

### Example Output
- Enumerating shares
Obs: The script will create a file "map.json" in the current directory containing the map of all readable shares. This file can be provided using `--map <FILE>` to reduce the number of requests in future runs.
```sh
$ smbscanner -t 192.168.57.8 -u smbuser -p password                                                            
09:44:56 | WARNING | Server info:
OS: Windows 11 / Server 2025 Build 26100
Domain: 
09:44:56 | WARNING | Listed shares:
ADMIN$  |  Permissions: {'READ': False, 'WRITE': False}  |  Description: Remote Admin
C$  |  Permissions: {'READ': False, 'WRITE': False}  |  Description: Default share
IPC$  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: Remote IPC
SHARE1  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: 
SHARE2  |  Permissions: {'READ': True, 'WRITE': True}  |  Description: 
SHARE3  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: 
```
- Scanning the specified share with a custom regex pattern
```sh
$ smbscanner -t 192.168.57.8 -u smbuser -p password --log test.log -s SHARE3 --scan --regex '://([^:]+):[^@]+@' --recursive
09:46:09 | WARNING | Server info:
OS: Windows 11 / Server 2025 Build 26100
Domain: 
09:46:09 | WARNING | Listed shares:
ADMIN$  |  Permissions: {'READ': False, 'WRITE': False}  |  Description: Remote Admin
C$  |  Permissions: {'READ': False, 'WRITE': False}  |  Description: Default share
IPC$  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: Remote IPC
SHARE1  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: 
SHARE2  |  Permissions: {'READ': True, 'WRITE': True}  |  Description: 
SHARE3  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: 
Scanning: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████ | 1/1 items | 00:00
09:46:10 | CRITICAL | File Path: secrets_test.txt
Type: Custom regex
Secret: user
Context: MONGO_URI="mongodb://user:pass123@cluster0.mongodb.net:27017/mydb"
Line: 42

09:46:10 | CRITICAL | File Path: secrets_test.txt
Type: Custom regex
Secret: admin
Context: MONGODB_SRV="mongodb+srv://admin:secret123@cluster0.abcde.mongodb.net/mydb"
Line: 43

09:46:10 | CRITICAL | File Path: secrets_test.txt
Type: Custom regex
Secret: user
Context: POSTGRES_URI="postgresql://user:pass123@localhost:5432/mydb"
Line: 46

09:46:10 | CRITICAL | File Path: secrets_test.txt
Type: Custom regex
Secret: admin
Context: MYSQL_URI="mysql://admin:pass123@localhost:3306/mydb"
Line: 49
```
- Scanning the Share recursively
```sh
$ smbscanner -t 192.168.57.8 -u smbuser -p password --log test.log -s SHARE3 --scan --recursive
09:47:26 | WARNING | Server info:
OS: Windows 11 / Server 2025 Build 26100
Domain: 
09:47:26 | WARNING | Listed shares:
ADMIN$  |  Permissions: {'READ': False, 'WRITE': False}  |  Description: Remote Admin
C$  |  Permissions: {'READ': False, 'WRITE': False}  |  Description: Default share
IPC$  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: Remote IPC
SHARE1  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: 
SHARE2  |  Permissions: {'READ': True, 'WRITE': True}  |  Description: 
SHARE3  |  Permissions: {'READ': True, 'WRITE': False}  |  Description: 
Scanning: 100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████ | 1/1 items | 00:00
09:47:27 | CRITICAL | File Path: secrets_test.txt
Type: Google API Key
Secret: AIzaSyD1234567890AbCdEfGhIjKlMnOpQrStUvWxYz
Context: GOOGLE_API_KEY="AIzaSyD1234567890AbCdEfGhIjKlMnOpQrStUvWxYz"
Line: 5

09:47:27 | CRITICAL | File Path: secrets_test.txt
Type: API Key Assigned
Secret: AIzaSyD1234567890AbCdEfGhIjKlMnOpQrStUvWxYz
Context: GOOGLE_API_KEY="AIzaSyD1234567890AbCdEfGhIjKlMnOpQrStUvWxYz"
Line: 5

09:47:27 | CRITICAL | File Path: secrets_test.txt
Type: Google OAuth Token
Secret: ya29.a0AfH6SMC1234567890AbCdEfGhIjKlMnOpQrStUvWxYz
Context: GMAIL_OAUTH="ya29.a0AfH6SMC1234567890AbCdEfGhIjKlMnOpQrStUvWxYz"
Line: 11
```

## Future Features
- Kerberos Authentication
- Pattern Filtering by Category - Users can select specific categories of sensitive data to scan

## Ethical Usage
This tool is intended for:
- Security research with proper permissions
- Educational purposes

Always ensure you have explicit written permission before scanning any systems you don't own or explicitly have authorization to test.

## Support
For bugs, feature requests, or questions:
- Email: cralmeida.contato@gmail.com

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
