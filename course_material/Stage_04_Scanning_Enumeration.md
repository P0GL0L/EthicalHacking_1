# Stage 04 — Scanning and Enumeration
## Discovering What's Running and How to Reach It

**Certified Ethical Hacking I Learning Path**  
**Audience:** Learners who have completed Stages 00-03

Welcome to Stage 04. After reconnaissance, you know your target exists. Now you need to discover what services are running, what ports are open, and what versions are deployed. **Nmap is the cornerstone tool of this stage**—arguably the most important tool in any penetration tester's toolkit.

---

## Prerequisites

- [ ] Lab environment configured
- [ ] Understand TCP/IP, ports, and protocols (Stage 02)
- [ ] Completed reconnaissance fundamentals (Stage 03)
- [ ] Metasploitable 2 running and accessible

---

## What You Will Learn

- Perform host discovery using multiple techniques
- Master Nmap for comprehensive port scanning
- Understand and use different scan types
- Detect service versions accurately
- Fingerprint operating systems
- Use the Nmap Scripting Engine (NSE)
- Enumerate common services (SMB, SNMP, NFS, etc.)

---

## Part 1 — Host Discovery (Milestone 1)

### Host Discovery Methods

```
┌─────────────────────────────────────────────────────────────────┐
│                 Host Discovery Methods                           │
├─────────────────────────────────────────────────────────────────┤
│  ICMP-BASED: Echo Request (Ping) - often blocked               │
│  TCP-BASED: SYN to 443, ACK to 80 - bypasses some firewalls    │
│  ARP-BASED: Cannot be blocked on local network                  │
└─────────────────────────────────────────────────────────────────┘
```

### Nmap Host Discovery

```bash
# Default discovery
nmap -sn 192.168.1.0/24

# ARP only (local network)
nmap -sn -PR 192.168.1.0/24

# TCP SYN discovery
nmap -sn -PS22,80,443 192.168.1.0/24

# Skip discovery (treat all as online)
nmap -Pn 192.168.1.0/24
```

---

## Part 2 — Nmap Fundamentals (Milestone 2)

### Command Structure

```
nmap [Scan Type] [Options] [Target]
```

### Target Specification

```bash
nmap 192.168.1.1              # Single IP
nmap 192.168.1.0/24           # CIDR
nmap 192.168.1.1-254          # Range
nmap -iL targets.txt          # From file
```

### Port Specification

```bash
nmap -p 22,80,443 target      # Specific ports
nmap -p 1-1000 target         # Range
nmap -p- target               # All 65535 ports
nmap -F target                # Fast (100 ports)
nmap --top-ports 100 target   # Top X ports
```

### Output Formats

```bash
nmap target -oN scan.txt      # Normal
nmap target -oG scan.gnmap    # Grepable
nmap target -oX scan.xml      # XML
nmap target -oA basename      # All formats
```

### Port States

| State | Meaning |
|-------|---------|
| open | Service accepting connections |
| closed | Reachable, no service |
| filtered | Firewall blocking |

---

## Part 3 — Scan Types (Milestone 3)

### TCP Scan Types

```
┌─────────────────────────────────────────────────────────────────┐
│  -sS  TCP SYN (Stealth) - Default as root, half-open           │
│  -sT  TCP Connect - Full handshake, easily logged              │
│  -sA  TCP ACK - Firewall mapping                                │
│  -sF  TCP FIN - Evade simple firewalls                         │
│  -sX  TCP XMAS - FIN/PSH/URG flags                             │
│  -sN  TCP NULL - No flags                                       │
└─────────────────────────────────────────────────────────────────┘
```

### UDP Scanning

```bash
nmap -sU target                    # UDP scan
nmap -sU -p 53,161 target          # Specific UDP ports
nmap -sS -sU target                # Combined TCP/UDP
```

### Timing Templates

```bash
nmap -T0 target   # Paranoid (IDS evasion)
nmap -T1 target   # Sneaky
nmap -T2 target   # Polite
nmap -T3 target   # Normal (default)
nmap -T4 target   # Aggressive
nmap -T5 target   # Insane
```

---

## Part 4 — Service and Version Detection (Milestone 4)

```bash
nmap -sV target                      # Version detection
nmap -sV --version-intensity 5 target # Increased intensity
nmap -sV --version-all target        # Try all probes
```

### Manual Banner Grabbing

```bash
nc -v target 22                      # SSH banner
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc target 80  # HTTP
```

---

## Part 5 — OS Fingerprinting (Milestone 5)

```bash
nmap -O target                       # OS detection
nmap -O --osscan-guess target        # Aggressive guess
nmap -A target                       # OS + version + scripts + traceroute
```

---

## Part 6 — Nmap Scripting Engine (Milestone 6)

### Script Categories

| Category | Purpose |
|----------|---------|
| auth | Authentication |
| brute | Brute force |
| default | Safe, useful (-sC) |
| discovery | Discovery |
| exploit | Exploitation |
| safe | Non-intrusive |
| vuln | Vulnerabilities |

### Using Scripts

```bash
nmap -sC target                           # Default scripts
nmap --script=vuln target                 # Vulnerability scan
nmap --script=smb-* -p 445 target         # SMB scripts
nmap --script=http-enum -p 80 target      # HTTP enumeration
nmap --script=ssl-enum-ciphers -p 443 target # SSL analysis

# Find scripts
ls /usr/share/nmap/scripts/ | grep smb
nmap --script-help=script-name
```

### Essential Scripts

```bash
# SMB vulnerabilities
nmap --script=smb-vuln* -p 445 target

# FTP anonymous
nmap --script=ftp-anon -p 21 target

# HTTP directories
nmap --script=http-enum -p 80 target
```

---

## Part 7 — Service Enumeration (Milestone 7)

### SMB Enumeration

```bash
enum4linux -a target                 # Comprehensive
smbclient -L //target -N             # List shares
smbmap -H target                     # Map permissions
nmap --script=smb-enum-shares,smb-enum-users -p 445 target
```

### SNMP Enumeration

```bash
snmpwalk -v2c -c public target       # Walk MIB
snmp-check target                    # Detailed check
onesixtyone -c community.txt target  # Brute force community
```

### NFS Enumeration

```bash
showmount -e target                  # List exports
nmap --script=nfs-* -p 111,2049 target
mount -t nfs target:/share /mnt     # Mount share
```

### Web Enumeration

```bash
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target -w wordlist.txt -x php,html,txt
nikto -h http://target
whatweb http://target
```

### SMTP Enumeration

```bash
smtp-user-enum -M VRFY -U users.txt -t target
nmap --script=smtp-* -p 25 target
```

---

## Part 8 — Comprehensive Workflow (Milestone 8)

### Scanning Methodology

```
1. HOST DISCOVERY    → nmap -sn -PR <network>
2. QUICK PORT SCAN   → nmap -F -T4 <target>
3. FULL PORT SCAN    → nmap -p- -T4 <target>
4. SERVICE DETECTION → nmap -sV -sC -p <ports> <target>
5. VULN SCAN         → nmap --script=vuln -p <ports> <target>
6. ENUMERATION       → Service-specific tools
```

### Master Scanning Script

```bash
cat << 'EOF' > ~/security-lab/scripts/full_scan.sh
#!/bin/bash

TARGET=$1
OUTPUT=~/security-lab/evidence/scan_${TARGET}_$(date +%Y%m%d)
mkdir -p "$OUTPUT"

echo "[*] Phase 1: Quick scan..."
nmap -F -T4 $TARGET -oA "$OUTPUT/01_quick"

echo "[*] Phase 2: Full port scan..."
nmap -p- -T4 $TARGET -oA "$OUTPUT/02_full"

PORTS=$(grep "open" "$OUTPUT/02_full.nmap" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

echo "[*] Phase 3: Service detection on ports: $PORTS"
nmap -sV -sC -p $PORTS $TARGET -oA "$OUTPUT/03_services"

echo "[*] Phase 4: Vulnerability scan..."
nmap --script=vuln -p $PORTS $TARGET -oA "$OUTPUT/04_vuln"

echo "[*] Complete! Results in $OUTPUT"
EOF
chmod +x ~/security-lab/scripts/full_scan.sh
```

### Nmap Quick Reference

```bash
# Quick comprehensive scan
nmap -sV -sC -O -T4 target

# Full stealth scan
sudo nmap -sS -sV -O -p- -T4 target

# Vulnerability assessment
nmap --script=vuln -sV target

# UDP top ports
sudo nmap -sU --top-ports 20 target
```

---

## Stage 04 Assessment

### Written Questions

1. Difference between TCP SYN and TCP Connect scans?
2. Why is UDP scanning slower?
3. What does -A enable in Nmap?
4. How do you use NSE scripts?
5. What are the port states in Nmap?

### Practical Assessment

1. Complete scan of Metasploitable 2
2. Enumerate all SMB shares
3. Identify all web directories
4. Document all services with versions
5. Run vulnerability scripts and document findings

---

## Completion Checklist

- [ ] Master host discovery
- [ ] Know all scan types
- [ ] Perform version detection
- [ ] Use OS fingerprinting
- [ ] Leverage NSE scripts
- [ ] Enumerate SMB, SNMP, NFS, HTTP
- [ ] Complete Metasploitable scan
- [ ] Create scanning scripts

---

**Next: Stage 05 — Vulnerability Analysis**

```bash
git add . && git commit -m "Complete Stage 04 - Scanning and Enumeration"
```
