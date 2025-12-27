# Stage 02 — Networking for Penetration Testers
## Understanding How Data Travels to Know What to Attack

**Certified Ethical Hacking I Learning Path**  
**Audience:** Complete beginners with limited networking knowledge

Welcome to Stage 02. This stage is essential—you cannot effectively attack networks you don't understand. Every tool you'll use in penetration testing operates at the network level. Without understanding networking, you're just pushing buttons without comprehension.

This stage assumes NO prior networking knowledge. We build from first principles.

---

## Prerequisites

Before starting Stage 02, you must have completed Stage 01:

- [ ] Understand legal and ethical framework
- [ ] Created authorization and scope templates
- [ ] Know the penetration testing methodology phases
- [ ] Have documentation system set up
- [ ] Lab environment functional (Kali + Metasploitable)

---

## Why This Stage Matters

Every scanning tool works with network protocols. Every exploit travels over a network. Every defense operates at network layers.

Without networking knowledge, you can't interpret scan results, understand what attacks do, troubleshoot when things don't work, or explain findings to clients.

---

## What You Will Learn

By the end of this stage, you will be able to:

- Explain the OSI and TCP/IP models
- Understand how data travels from source to destination
- Describe IP addressing and subnetting
- Identify common network protocols and their purposes
- Understand TCP and UDP communication
- Use Wireshark to capture and analyze packets
- Explain how common network services work
- Apply this knowledge to penetration testing context

---

## Part 1 — Networking Basics and Models (Milestone 1)

### What Is a Network?

A **network** is a group of computers and devices connected together to share resources and communicate.

**Simple Analogy:** Think of a network like a postal system:
- **Addresses** — So you know where to send things (IP addresses)
- **Packages** — The data you're sending (packets)
- **Post Offices** — Sorting and forwarding (routers)
- **Delivery Rules** — How to handle packages (protocols)

### Types of Networks

| Type | Description | Example |
|------|-------------|---------|
| **LAN** | Local Area Network - single location | Office network, home network |
| **WAN** | Wide Area Network - spans geography | Internet, corporate WAN |
| **WLAN** | Wireless LAN | WiFi network |
| **MAN** | Metropolitan Area Network | City-wide network |

### The OSI Model

The **Open Systems Interconnection (OSI)** model describes how data travels through a network in 7 layers.

```
┌─────────────────────────────────────────────────────────────────┐
│                    The OSI Model (7 Layers)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Layer 7: APPLICATION                                           │
│  ├── What users interact with                                   │
│  ├── Examples: HTTP, HTTPS, FTP, SSH, DNS, SMTP                │
│  └── Security: Application-level attacks (XSS, SQLi)           │
│                                                                  │
│  Layer 6: PRESENTATION                                          │
│  ├── Data formatting and encryption                            │
│  ├── Examples: SSL/TLS, JPEG, ASCII                            │
│  └── Security: Encryption attacks, format vulnerabilities      │
│                                                                  │
│  Layer 5: SESSION                                               │
│  ├── Manages connections between applications                  │
│  ├── Examples: NetBIOS, RPC                                    │
│  └── Security: Session hijacking                               │
│                                                                  │
│  Layer 4: TRANSPORT                                             │
│  ├── End-to-end communication                                  │
│  ├── Examples: TCP, UDP                                         │
│  └── Security: Port scanning, DoS                              │
│                                                                  │
│  Layer 3: NETWORK                                               │
│  ├── Routing between networks                                  │
│  ├── Examples: IP, ICMP, routers                               │
│  └── Security: IP spoofing, routing attacks                    │
│                                                                  │
│  Layer 2: DATA LINK                                             │
│  ├── Local network communication                               │
│  ├── Examples: Ethernet, MAC addresses, switches               │
│  └── Security: ARP spoofing, MAC flooding                      │
│                                                                  │
│  Layer 1: PHYSICAL                                              │
│  ├── Physical transmission                                     │
│  ├── Examples: Cables, radio waves, hubs                       │
│  └── Security: Physical access, wiretapping                    │
│                                                                  │
│  Mnemonic: "All People Seem To Need Data Processing"           │
│  (Application → Physical)                                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### The TCP/IP Model

The **TCP/IP model** is what the Internet actually uses. It has 4 layers that map to the OSI model:

```
┌─────────────────────────────────────────────────────────────────┐
│                   TCP/IP vs OSI Model                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│     TCP/IP Model          │        OSI Model                    │
│  ─────────────────────────┼─────────────────────────            │
│                           │                                      │
│  APPLICATION              │  Application (7)                     │
│  (HTTP, FTP, SSH,        │  Presentation (6)                    │
│   DNS, SMTP)             │  Session (5)                         │
│                           │                                      │
│  TRANSPORT                │  Transport (4)                       │
│  (TCP, UDP)              │                                      │
│                           │                                      │
│  INTERNET                 │  Network (3)                         │
│  (IP, ICMP)              │                                      │
│                           │                                      │
│  NETWORK ACCESS           │  Data Link (2)                       │
│  (Ethernet, WiFi)        │  Physical (1)                        │
│                           │                                      │
└─────────────────────────────────────────────────────────────────┘
```

### How Data Travels

When you send data across a network, it goes through a process called **encapsulation**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Data Encapsulation                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Application Layer: Creates DATA                                │
│        │                                                        │
│        ▼                                                        │
│  Transport Layer: Adds TCP/UDP header → SEGMENT                 │
│        │                                                        │
│        ▼                                                        │
│  Network Layer: Adds IP header → PACKET                         │
│        │                                                        │
│        ▼                                                        │
│  Data Link Layer: Adds MAC header + trailer → FRAME            │
│        │                                                        │
│        ▼                                                        │
│  Physical Layer: Converts to BITS for transmission             │
│                                                                  │
│  At destination, this process reverses (de-encapsulation)      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Security Relevance

Understanding layers helps you:
- Know where different attacks operate
- Understand what security tools do
- Choose appropriate defenses
- Interpret packet captures

| Layer | Attack Type | Tool Example |
|-------|------------|--------------|
| 7-Application | SQL Injection, XSS | SQLMap, Burp Suite |
| 4-Transport | Port scanning | Nmap |
| 3-Network | IP spoofing | hping3 |
| 2-Data Link | ARP spoofing | arpspoof |

---

## Part 2 — IP Addressing and Subnetting (Milestone 2)

### What Is an IP Address?

An **IP address** is a unique identifier for a device on a network. Think of it like a street address for computers.

### IPv4 Addresses

IPv4 addresses are 32 bits, written as four octets (8-bit numbers) separated by dots.

```
Example: 192.168.1.100

Binary:   11000000.10101000.00000001.01100100
Decimal:     192   .   168  .    1   .   100

Each octet ranges from 0 to 255
```

### IP Address Classes (Historical)

```
┌─────────────────────────────────────────────────────────────────┐
│                    IP Address Classes                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CLASS A: 1.0.0.0 - 126.255.255.255                            │
│  ├── First octet: 1-126                                        │
│  ├── Default mask: 255.0.0.0 (/8)                              │
│  └── Large networks (16 million hosts)                         │
│                                                                  │
│  CLASS B: 128.0.0.0 - 191.255.255.255                          │
│  ├── First octet: 128-191                                      │
│  ├── Default mask: 255.255.0.0 (/16)                           │
│  └── Medium networks (65,534 hosts)                            │
│                                                                  │
│  CLASS C: 192.0.0.0 - 223.255.255.255                          │
│  ├── First octet: 192-223                                      │
│  ├── Default mask: 255.255.255.0 (/24)                         │
│  └── Small networks (254 hosts)                                │
│                                                                  │
│  CLASS D: 224.0.0.0 - 239.255.255.255 (Multicast)              │
│  CLASS E: 240.0.0.0 - 255.255.255.255 (Reserved)               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Private IP Addresses

These addresses are reserved for private networks and are NOT routable on the Internet:

| Class | Range | Common Use |
|-------|-------|------------|
| A | 10.0.0.0 - 10.255.255.255 | Large organizations |
| B | 172.16.0.0 - 172.31.255.255 | Medium networks |
| C | 192.168.0.0 - 192.168.255.255 | Home/small office |

**Security Note:** Seeing private IPs in scan results tells you about internal network structure.

### Special Addresses

| Address | Purpose |
|---------|---------|
| 127.0.0.1 | Loopback (localhost) - refers to yourself |
| 0.0.0.0 | All interfaces / any address |
| 255.255.255.255 | Broadcast to all hosts |
| 169.254.x.x | Link-local (DHCP failed) |

### Subnet Masks

A **subnet mask** divides an IP address into network and host portions.

```
IP Address:    192.168.1.100
Subnet Mask:   255.255.255.0

Network:       192.168.1.0     (identifies the network)
Host:          .100            (identifies the device)
Broadcast:     192.168.1.255   (all hosts on network)

In CIDR notation: 192.168.1.100/24
The /24 means 24 bits for network, 8 bits for hosts
```

### Subnetting Basics

Subnetting divides a network into smaller networks.

**Common Subnet Masks:**

| CIDR | Subnet Mask | Hosts | Use |
|------|-------------|-------|-----|
| /8 | 255.0.0.0 | 16,777,214 | Large enterprise |
| /16 | 255.255.0.0 | 65,534 | Medium organization |
| /24 | 255.255.255.0 | 254 | Small network |
| /25 | 255.255.255.128 | 126 | Subnet |
| /26 | 255.255.255.192 | 62 | Smaller subnet |
| /27 | 255.255.255.224 | 30 | Very small subnet |
| /28 | 255.255.255.240 | 14 | Tiny subnet |
| /30 | 255.255.255.252 | 2 | Point-to-point |
| /32 | 255.255.255.255 | 1 | Single host |

**Formula:** Hosts = 2^(32 - CIDR) - 2

The -2 is for network address and broadcast address.

### Hands-On Exercise 2.1: IP Address Analysis

```bash
# Create notes file
mkdir -p ~/security-lab/notes/stage02
cat << 'EOF' > ~/security-lab/notes/stage02/ip_exercises.md
# IP Address Exercises

## Exercise 1: Identify Your Network
Run: ip addr show
My IP: ________________
My Subnet: ________________
Network Address: ________________
Broadcast: ________________

## Exercise 2: Analyze These IPs
For each IP, identify:
- Class
- Public or Private
- Network portion
- Host portion

1. 10.0.0.50/8
2. 172.20.15.100/16
3. 192.168.1.1/24
4. 8.8.8.8/32
5. 192.168.100.200/26

## Exercise 3: Subnet Calculation
Calculate for 192.168.1.0/26:
- Subnet mask: ________________
- Number of hosts: ________________
- First usable IP: ________________
- Last usable IP: ________________
- Broadcast: ________________
EOF

# Get your actual network information
echo "Your Network Information:"
ip addr show | grep "inet "
ip route show
```

---

## Part 3 — TCP and UDP (Milestone 3)

### Transport Layer Overview

The transport layer provides end-to-end communication. The two main protocols are:

- **TCP** (Transmission Control Protocol) - Reliable, connection-oriented
- **UDP** (User Datagram Protocol) - Fast, connectionless

### TCP Explained

**TCP is like a phone call:**
- You establish a connection first
- You confirm messages were received
- You close the connection when done

#### The TCP Three-Way Handshake

This is how TCP connections are established:

```
┌─────────────────────────────────────────────────────────────────┐
│                   TCP Three-Way Handshake                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│    Client                               Server                  │
│       │                                    │                    │
│       │ ──────── SYN (seq=100) ──────────► │  1. Client sends  │
│       │     "I want to connect"            │     SYN            │
│       │                                    │                    │
│       │ ◄──── SYN-ACK (seq=300,ack=101)─── │  2. Server sends  │
│       │     "OK, I acknowledge"            │     SYN-ACK        │
│       │                                    │                    │
│       │ ──────── ACK (ack=301) ───────────►│  3. Client sends  │
│       │     "Got it, connection open"      │     ACK            │
│       │                                    │                    │
│       │ ◄────── DATA EXCHANGE ────────────►│  Connection        │
│       │                                    │  established       │
│       │                                    │                    │
│                                                                  │
│  SECURITY RELEVANCE:                                            │
│  • SYN scan - send SYN, analyze response                        │
│  • SYN flood - overwhelm with SYN packets                       │
│  • State tracking - firewalls track this                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### TCP Flags

TCP uses flags to control the connection:

| Flag | Name | Purpose |
|------|------|---------|
| SYN | Synchronize | Initiate connection |
| ACK | Acknowledge | Confirm receipt |
| FIN | Finish | Close connection |
| RST | Reset | Abort connection |
| PSH | Push | Send data immediately |
| URG | Urgent | Priority data |

**Security Use:** Different flag combinations reveal information during scanning.

#### TCP Connection Termination

```
Client                          Server
   │ ────── FIN ──────────────► │  "I'm done sending"
   │ ◄───── ACK ─────────────── │  "OK"
   │ ◄───── FIN ─────────────── │  "I'm done too"
   │ ────── ACK ──────────────► │  "Connection closed"
```

### UDP Explained

**UDP is like sending a postcard:**
- No confirmation of delivery
- No connection establishment
- Faster but less reliable

```
┌─────────────────────────────────────────────────────────────────┐
│                    TCP vs UDP Comparison                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TCP                          │  UDP                            │
│  ─────────────────────────────┼─────────────────────────        │
│  Connection-oriented          │  Connectionless                 │
│  Reliable delivery            │  Best-effort delivery           │
│  Acknowledges packets         │  No acknowledgment              │
│  Ordered delivery             │  No ordering                    │
│  Flow control                 │  No flow control                │
│  Slower (overhead)            │  Faster (no overhead)           │
│                               │                                 │
│  Used for:                    │  Used for:                      │
│  • Web (HTTP/HTTPS)          │  • DNS queries                  │
│  • Email (SMTP)              │  • Streaming video              │
│  • File transfer (FTP)       │  • VoIP                         │
│  • SSH, Telnet               │  • DHCP                         │
│                               │  • Online gaming               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Ports

Ports are like apartment numbers in a building. The IP is the building address; the port is the specific unit.

**Port ranges:**
- 0-1023: Well-known ports (require root/admin)
- 1024-49151: Registered ports
- 49152-65535: Dynamic/private ports

**Essential Ports for Penetration Testing:**

| Port | Protocol | Service | Security Notes |
|------|----------|---------|----------------|
| 20/21 | TCP | FTP | Often allows anonymous, clear text |
| 22 | TCP | SSH | Target for brute force |
| 23 | TCP | Telnet | Clear text, never use |
| 25 | TCP | SMTP | Email, open relay issues |
| 53 | TCP/UDP | DNS | Zone transfers, tunneling |
| 80 | TCP | HTTP | Web, lots of vulnerabilities |
| 110 | TCP | POP3 | Email, clear text |
| 135 | TCP | MS-RPC | Windows, many exploits |
| 139 | TCP | NetBIOS | Windows, shares |
| 143 | TCP | IMAP | Email, clear text |
| 443 | TCP | HTTPS | Encrypted web |
| 445 | TCP | SMB | Windows shares, EternalBlue |
| 3306 | TCP | MySQL | Database |
| 3389 | TCP | RDP | Windows Remote Desktop |
| 5432 | TCP | PostgreSQL | Database |
| 5900 | TCP | VNC | Remote desktop |
| 8080 | TCP | HTTP Proxy | Alternate web |

### Hands-On Exercise 2.2: TCP Analysis

```bash
# Use netcat to observe TCP behavior
# Terminal 1: Start a listener
nc -lvp 4444

# Terminal 2: Connect
nc localhost 4444

# Type messages back and forth
# Press Ctrl+C to close

# Observe port states
ss -tuln

# See established connections
ss -tun

# Document in notes
cat << 'EOF' >> ~/security-lab/notes/stage02/tcp_notes.md
# TCP Observations

## Connection Test Results
- Port used: 4444
- Connection established: Yes/No
- Data transmitted: Yes/No

## Port States Observed
(paste ss output here)
EOF
```

---

## Part 4 — Common Network Protocols (Milestone 4)

### DNS (Domain Name System)

**Port:** 53 (UDP for queries, TCP for zone transfers)

DNS translates human-readable names to IP addresses.

```
You type: www.example.com
DNS returns: 93.184.216.34
```

**DNS Record Types:**

| Type | Purpose | Example |
|------|---------|---------|
| A | IPv4 address | www → 192.168.1.1 |
| AAAA | IPv6 address | www → 2001:db8::1 |
| MX | Mail server | mail.example.com |
| NS | Name server | ns1.example.com |
| TXT | Text record | SPF, verification |
| CNAME | Alias | www → server1 |
| PTR | Reverse lookup | IP → hostname |
| SOA | Zone authority | Primary NS info |

**Security Relevance:**
- DNS enumeration reveals infrastructure
- Zone transfers can leak all records
- DNS can be used for tunneling

**Commands:**
```bash
# Basic lookup
nslookup www.example.com
host www.example.com
dig www.example.com

# Specific record types
dig MX example.com
dig NS example.com
dig ANY example.com

# Zone transfer attempt (usually blocked)
dig axfr @ns1.example.com example.com
```

### HTTP/HTTPS

**Ports:** 80 (HTTP), 443 (HTTPS)

**HTTP Methods:**

| Method | Purpose | Security |
|--------|---------|----------|
| GET | Retrieve data | Parameters in URL |
| POST | Submit data | Data in body |
| PUT | Update resource | Often restricted |
| DELETE | Remove resource | Should be protected |
| HEAD | Get headers only | Reconnaissance |
| OPTIONS | Get allowed methods | Information disclosure |

**HTTP Response Codes:**

| Code | Meaning | Security Note |
|------|---------|---------------|
| 200 | OK | Request succeeded |
| 301/302 | Redirect | Follow carefully |
| 400 | Bad Request | Input validation |
| 401 | Unauthorized | Need credentials |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Resource missing |
| 500 | Server Error | Possible vulnerability |
| 503 | Service Unavailable | Overloaded/down |

### DHCP

**Ports:** 67 (server), 68 (client) - UDP

DHCP automatically assigns IP addresses to devices.

**DHCP Process (DORA):**
1. **Discover** - Client broadcasts "I need an IP"
2. **Offer** - Server offers an IP address
3. **Request** - Client requests the offered IP
4. **Acknowledge** - Server confirms

**Security Relevance:**
- Rogue DHCP servers can redirect traffic
- DHCP starvation attacks
- Reveals network configuration

### ARP (Address Resolution Protocol)

ARP maps IP addresses to MAC addresses on local networks.

```
"Who has 192.168.1.1?"
"192.168.1.1 is at AA:BB:CC:DD:EE:FF"
```

**Security Relevance:**
- ARP spoofing/poisoning allows MITM
- ARP is not authenticated
- Fundamental attack vector on LANs

**Commands:**
```bash
# View ARP cache
arp -a
ip neigh show

# Clear ARP cache
sudo ip neigh flush all
```

### ICMP

ICMP is used for network diagnostics and error messages.

**Common ICMP Types:**

| Type | Name | Purpose |
|------|------|---------|
| 0 | Echo Reply | Ping response |
| 3 | Destination Unreachable | Can't reach target |
| 5 | Redirect | Use different route |
| 8 | Echo Request | Ping |
| 11 | Time Exceeded | TTL expired |

**Commands:**
```bash
# Basic ping
ping -c 4 192.168.1.1

# Traceroute (uses ICMP or UDP)
traceroute 8.8.8.8
```

### Hands-On Exercise 2.3: Protocol Analysis

```bash
# DNS enumeration on Metasploitable
dig @[METASPLOITABLE_IP] any localhost

# HTTP header analysis
curl -I http://[METASPLOITABLE_IP]

# View ARP table after communicating
arp -a

# Ping and observe
ping -c 4 [METASPLOITABLE_IP]

# Document findings
cat << 'EOF' >> ~/security-lab/notes/stage02/protocol_analysis.md
# Protocol Analysis Results

## DNS Findings
(paste dig output)

## HTTP Headers
(paste curl -I output)

## ARP Observations
(paste arp -a output)

## What I Learned
- 
- 
EOF
```

---

## Part 5 — Wireshark Fundamentals (Milestone 5)

### What Is Wireshark?

Wireshark is a network protocol analyzer that captures and displays network traffic.

**Why It Matters:**
- See exactly what's on the network
- Understand how protocols work
- Analyze attacks and traffic
- Verify what tools are doing

### Installing and Starting Wireshark

```bash
# Wireshark is pre-installed on Kali
# Start it
sudo wireshark

# Or from terminal
wireshark &
```

### Capture Basics

1. **Select Interface** - Choose which network interface to capture
2. **Start Capture** - Click the blue shark fin
3. **Stop Capture** - Click the red square
4. **Analyze** - Review captured packets

### Understanding the Interface

```
┌─────────────────────────────────────────────────────────────────┐
│                    Wireshark Interface                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PACKET LIST (top pane)                                         │
│  ├── One row per packet                                         │
│  ├── Time, Source, Destination, Protocol, Info                 │
│  └── Click to select a packet                                   │
│                                                                  │
│  PACKET DETAILS (middle pane)                                   │
│  ├── Expandable tree of packet contents                        │
│  ├── Shows all headers layer by layer                          │
│  └── Click to expand sections                                   │
│                                                                  │
│  PACKET BYTES (bottom pane)                                     │
│  ├── Raw hexadecimal view                                       │
│  └── ASCII representation on right                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Display Filters

Filters help you find specific traffic:

| Filter | Purpose |
|--------|---------|
| `ip.addr == 192.168.1.1` | Traffic to/from IP |
| `ip.src == 192.168.1.1` | Traffic from IP |
| `ip.dst == 192.168.1.1` | Traffic to IP |
| `tcp.port == 80` | TCP port 80 |
| `udp.port == 53` | UDP port 53 (DNS) |
| `http` | HTTP traffic only |
| `dns` | DNS traffic only |
| `tcp.flags.syn == 1` | TCP SYN packets |
| `tcp.flags.reset == 1` | TCP RST packets |
| `!(arp or dns)` | Exclude ARP and DNS |

**Combine with and/or:**
```
ip.addr == 192.168.1.1 and tcp.port == 80
http or dns
tcp.port == 80 and http.request.method == "POST"
```

### Following Streams

Right-click on a packet → Follow → TCP Stream

This reconstructs the entire conversation, making it easy to read.

### Hands-On Exercise 2.4: Capture and Analyze

```bash
# 1. Start Wireshark on your host-only interface
sudo wireshark &

# Select the host-only interface (e.g., eth1, vboxnet0)

# 2. Start capture

# 3. From another terminal, generate traffic to Metasploitable
ping -c 3 [METASPLOITABLE_IP]
curl http://[METASPLOITABLE_IP]
nmap -sn [METASPLOITABLE_IP]

# 4. Stop capture

# 5. Apply filters and analyze:
# - Find the ICMP echo requests/replies (ping)
# - Find the HTTP GET request
# - Find the ARP traffic

# 6. Save the capture
# File → Save As → exercise_2_4.pcap

# 7. Document observations
cat << 'EOF' >> ~/security-lab/notes/stage02/wireshark_analysis.md
# Wireshark Exercise 2.4

## Capture Summary
Total packets: ___
Capture duration: ___

## ICMP Analysis
- Echo requests observed: ___
- Echo replies received: ___
- Round trip time: ___

## HTTP Analysis
- HTTP request method: ___
- Host header: ___
- Response code: ___
- Server header: ___

## ARP Analysis
- ARP requests observed: ___
- Source MAC: ___
- Target IP: ___

## Interesting Observations
- 
EOF
```

---

## Part 6 — Network Services (Milestone 6)

### Common Services You'll Encounter

Understanding services helps you identify attack vectors.

### FTP (File Transfer Protocol)

**Ports:** 20 (data), 21 (control)

```
┌─────────────────────────────────────────────────────────────────┐
│                    FTP Security Issues                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  VULNERABILITIES                                                │
│  ├── Transmits credentials in clear text                       │
│  ├── Often allows anonymous access                             │
│  ├── May allow directory traversal                             │
│  └── Old versions have known exploits                          │
│                                                                  │
│  TESTING APPROACH                                               │
│  ├── Check for anonymous login                                 │
│  ├── Enumerate directories                                     │
│  ├── Check version for CVEs                                    │
│  └── Look for writable directories                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Commands:**
```bash
# Connect to FTP
ftp [TARGET_IP]
# Try: anonymous / anonymous@

# List files
ls

# Download file
get filename
```

### SSH (Secure Shell)

**Port:** 22

Secure remote access protocol.

**Testing Approach:**
- Banner grabbing for version
- Check for weak credentials
- Look for key-based auth only
- Check for known CVEs

```bash
# Banner grab
nc -v [TARGET_IP] 22

# SSH connect
ssh user@[TARGET_IP]
```

### SMB (Server Message Block)

**Ports:** 139 (NetBIOS), 445 (Direct SMB)

Windows file and printer sharing.

**Security Issues:**
- EternalBlue (MS17-010) - WannaCry exploit
- Null sessions - anonymous enumeration
- Weak authentication
- Information disclosure

```bash
# Enumerate SMB shares
smbclient -L //[TARGET_IP] -N

# Connect to share
smbclient //[TARGET_IP]/share -N
```

### Hands-On Exercise 2.5: Service Enumeration

```bash
# On Metasploitable, explore services

# FTP test
ftp [METASPLOITABLE_IP]
# Try anonymous login

# SSH banner
nc -v [METASPLOITABLE_IP] 22

# Web server
curl -I http://[METASPLOITABLE_IP]

# Document everything
cat << 'EOF' >> ~/security-lab/notes/stage02/service_enumeration.md
# Service Enumeration Results

## FTP (Port 21)
Anonymous login: Yes/No
Directories visible: 
Interesting files:

## SSH (Port 22)
Banner:
Version:

## HTTP (Port 80)
Server header:
Interesting directories:

## Next Steps
Based on these findings, I would next:
1.
2.
EOF
```

---

## Part 7 — Connecting to Penetration Testing (Milestone 7)

### Applying Network Knowledge

Now you understand how networks work. Here's how this applies to penetration testing:

### Reconnaissance Phase

Network knowledge helps you:
- Identify live hosts (ping sweeps, ARP scans)
- Map network topology
- Understand scope boundaries
- Identify network segments

### Scanning Phase

Understanding protocols helps you:
- Interpret port scan results
- Understand what services mean
- Recognize potential vulnerabilities
- Choose appropriate scan types

### Exploitation Phase

Network understanding enables:
- Knowing how exploits work
- Understanding payload delivery
- Configuring network-based attacks
- Establishing reverse shells

### Post-Exploitation

Network knowledge supports:
- Pivoting to other networks
- Understanding lateral movement
- Identifying high-value targets
- Exfiltrating data

### Hands-On Exercise 2.6: Complete Network Assessment

Perform a network assessment of your lab:

```bash
# 1. Document your network
ip addr show
ip route show

# 2. Discover hosts
nmap -sn 192.168.X.0/24  # Replace with your subnet

# 3. Detailed scan of Metasploitable
nmap -sV -sC [METASPLOITABLE_IP] -oN ~/security-lab/evidence/nmap_full.txt

# 4. Capture traffic during scan
# Run Wireshark during the nmap scan

# 5. Create comprehensive documentation
cat << 'EOF' > ~/security-lab/notes/stage02/network_assessment.md
# Lab Network Assessment

## Network Topology
My Kali IP: 
Metasploitable IP:
Network range:
Gateway:

## Host Discovery
Hosts found:
1.
2.

## Service Inventory (Metasploitable)
| Port | Service | Version | Notes |
|------|---------|---------|-------|
| | | | |

## Network Observations
From Wireshark:
-

## Security Implications
Based on this assessment:
1. 
2.
EOF
```

---

## Stage 02 Assessment

### Written Assessment

Create: `~/security-lab/notes/stage02/assessment.md`

1. Explain the OSI model. Name all 7 layers and give one protocol example for each.

2. What is the difference between TCP and UDP? When would you use each?

3. Explain the TCP three-way handshake. What packets are exchanged?

4. Calculate: For the network 192.168.50.0/26, what is the subnet mask, number of hosts, and broadcast address?

5. What is the difference between a public and private IP address? Give examples of each.

6. Explain what DNS does. Name four DNS record types and their purposes.

7. What port does each service use: SSH, HTTP, HTTPS, FTP, SMB, RDP?

8. What is ARP and why is it a security concern?

9. Write a Wireshark filter to show only HTTP traffic to IP 10.0.0.5.

10. How does understanding networking make you a better penetration tester?

### Practical Assessment

1. **Network Documentation:** Create a complete diagram/documentation of your lab network including all IPs, subnets, and services.

2. **Packet Capture:** Capture and analyze a TCP three-way handshake. Document each packet with its flags and sequence numbers.

3. **Protocol Analysis:** Using Wireshark, capture an HTTP session and document: the GET request, all headers, and the response.

4. **Service Enumeration:** Document all services running on Metasploitable with ports and versions.

---

## Stage 02 Completion Checklist

### OSI/TCP-IP Models
- [ ] Can explain all 7 OSI layers
- [ ] Understand TCP/IP model mapping
- [ ] Know which attacks operate at which layers

### IP Addressing
- [ ] Understand IPv4 addressing
- [ ] Can identify public vs private addresses
- [ ] Can calculate subnets
- [ ] Know important special addresses

### TCP/UDP
- [ ] Understand three-way handshake
- [ ] Know TCP flags and their purposes
- [ ] Understand TCP vs UDP differences
- [ ] Can identify essential port numbers

### Protocols
- [ ] Understand DNS and record types
- [ ] Know HTTP methods and response codes
- [ ] Understand DHCP process
- [ ] Know ARP and its security implications

### Wireshark
- [ ] Can capture traffic
- [ ] Can apply display filters
- [ ] Can follow TCP streams
- [ ] Have saved practice captures

### Integration
- [ ] Understand how networking applies to pentesting
- [ ] Completed network assessment of lab
- [ ] Have comprehensive notes

---

## What's Next: Stage 03 Preview

In Stage 03 — Reconnaissance and Information Gathering, you will:

- Apply passive reconnaissance techniques
- Use OSINT tools professionally
- Conduct DNS enumeration
- Discover subdomains and assets
- Map target infrastructure
- Document reconnaissance findings

**You now have the foundation to understand what these tools are actually doing!**

---

**Commit your work and proceed to Stage 03 when ready:**

```bash
cd ~/security-lab
git add .
git commit -m "Complete Stage 02 - Networking for Penetration Testers"
```

---

**End of Stage 02 — Networking for Penetration Testers**
