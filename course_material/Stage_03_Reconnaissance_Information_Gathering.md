# Stage 03 — Reconnaissance and Information Gathering
## Discovering Everything About Your Target Before the First Scan

**Certified Ethical Hacking I Learning Path**  
**Audience:** Learners who have completed Stages 00-02

Welcome to Stage 03. Reconnaissance is the **most critical phase** of any penetration test. Professional pentesters spend 40-60% of their engagement time on reconnaissance because the quality of your recon directly determines the success of your entire assessment.

"Give me six hours to chop down a tree and I will spend the first four sharpening the axe." — Abraham Lincoln

The same principle applies to penetration testing.

---

## Prerequisites

Before starting Stage 03, you must have completed Stages 00-02:

- [ ] Lab environment configured (Kali + Metasploitable)
- [ ] Understand legal and ethical framework
- [ ] Created ROE and methodology templates
- [ ] Understand networking fundamentals (OSI, TCP/IP, protocols)
- [ ] Can use Wireshark for basic packet analysis
- [ ] Comfortable with Linux command line

If any of these are not checked, return to previous stages first.

---

## Why This Stage Matters

```
┌─────────────────────────────────────────────────────────────────┐
│              Why Reconnaissance Is Critical                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WITHOUT THOROUGH RECON:                                        │
│  ├── Miss vulnerabilities in forgotten systems                 │
│  ├── Waste time on dead ends                                   │
│  ├── Trigger alarms with noisy scanning                        │
│  ├── Overlook the easy wins                                    │
│  └── Deliver incomplete assessments                            │
│                                                                  │
│  WITH THOROUGH RECON:                                           │
│  ├── Discover the full attack surface                          │
│  ├── Find shadow IT and forgotten assets                       │
│  ├── Identify technologies for targeted attacks                │
│  ├── Gather intelligence for social engineering                │
│  └── Prioritize testing efforts efficiently                    │
│                                                                  │
│  REAL WORLD IMPACT:                                             │
│  • Forgotten subdomain → Unpatched server → Complete compromise│
│  • Employee email format → Credential stuffing → Account access │
│  • Technology stack → Known CVE → Remote code execution         │
│  • Open S3 bucket → Sensitive data exposure → Data breach       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## What You Will Learn

By the end of this stage, you will be able to:

- Distinguish between passive and active reconnaissance
- Conduct comprehensive OSINT (Open Source Intelligence)
- Use search engine dorking effectively
- Perform thorough DNS enumeration
- Discover subdomains using multiple methods
- Harvest email addresses and identify employees
- Fingerprint technologies and web applications
- Extract metadata from documents
- Automate reconnaissance workflows
- Document findings professionally

---

## What You Will Build

1. **OSINT methodology checklist** — Systematic approach to information gathering
2. **Google dorking reference** — Custom search operators
3. **DNS enumeration scripts** — Automated DNS discovery
4. **Subdomain discovery toolkit** — Multiple method approach
5. **Email harvesting workflow** — Employee discovery
6. **Target profile template** — Comprehensive documentation
7. **Automated recon script** — Combined reconnaissance workflow

---

## Certification Alignment

| Certification | Relevant Domains |
|--------------|------------------|
| **CompTIA PenTest+** | 2.1 Information Gathering |
| **CompTIA CySA+** | 1.4 Threat Intelligence |
| **CEH** | Module 2: Footprinting and Reconnaissance |
| **eJPT** | Information Gathering |

---

## Time Estimate

**Total: 35-45 hours**

| Section | Hours |
|---------|-------|
| Passive vs Active Reconnaissance | 3-4 |
| OSINT Fundamentals | 5-6 |
| Search Engine Reconnaissance | 4-5 |
| DNS Enumeration | 5-6 |
| Subdomain Discovery | 5-6 |
| Email and Employee Harvesting | 4-5 |
| Technology Fingerprinting | 4-5 |
| Automation and Scripting | 3-4 |
| Stage Assessment | 2-3 |

---

## The Milestones Approach

### Stage 03 Milestones

1. **Understand passive vs active reconnaissance**
2. **Master OSINT methodology**
3. **Use search engine dorking effectively**
4. **Perform comprehensive DNS enumeration**
5. **Discover subdomains using multiple methods**
6. **Harvest emails and identify employees**
7. **Fingerprint technologies**
8. **Automate reconnaissance workflows**
9. **Complete the stage assessment**

---

## Part 1 — Passive vs Active Reconnaissance (Milestone 1)

### Understanding the Difference

The fundamental distinction in reconnaissance is whether you directly interact with the target.

```
┌─────────────────────────────────────────────────────────────────┐
│             Passive vs Active Reconnaissance                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PASSIVE RECONNAISSANCE                                         │
│  ├── No direct contact with target systems                     │
│  ├── Uses publicly available information                        │
│  ├── Cannot be detected by target                               │
│  ├── Generally legal (public information)                       │
│  ├── Lower risk, broader scope                                  │
│  │                                                               │
│  │  Examples:                                                   │
│  │  • Search engine queries                                     │
│  │  • WHOIS lookups (via public registrars)                    │
│  │  • Social media research                                     │
│  │  • Job posting analysis                                      │
│  │  • Public DNS records                                        │
│  │  • Certificate transparency logs                             │
│  │  • Archive.org searches                                      │
│  │  • Public code repositories                                  │
│                                                                  │
│  ACTIVE RECONNAISSANCE                                          │
│  ├── Direct interaction with target systems                    │
│  ├── Can be logged and detected                                 │
│  ├── Requires authorization                                     │
│  ├── More detailed information                                  │
│  ├── Higher risk, focused scope                                 │
│  │                                                               │
│  │  Examples:                                                   │
│  │  • Port scanning                                             │
│  │  • Banner grabbing                                           │
│  │  • Vulnerability scanning                                    │
│  │  • Web spidering                                             │
│  │  • Zone transfer attempts                                    │
│  │  • Directory brute forcing                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Start Passive?

1. **No detection** — Target doesn't know you're looking
2. **Legal safety** — Public information is generally fair game
3. **Broad scope** — Find assets you didn't know existed
4. **Attack surface mapping** — Discover shadow IT
5. **Social engineering prep** — Names, roles, technologies

### The Reconnaissance Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                 Reconnaissance Workflow                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DEFINE SCOPE                                                │
│     └── What are we authorized to find information about?      │
│              │                                                   │
│              ▼                                                   │
│  2. PASSIVE RECONNAISSANCE                                      │
│     ├── OSINT gathering                                        │
│     ├── Search engine research                                  │
│     ├── Social media analysis                                   │
│     ├── DNS enumeration (public)                               │
│     └── Technology identification                               │
│              │                                                   │
│              ▼                                                   │
│  3. COMPILE FINDINGS                                            │
│     ├── Document all discovered assets                         │
│     ├── Map relationships                                       │
│     └── Identify gaps needing active recon                     │
│              │                                                   │
│              ▼                                                   │
│  4. ACTIVE RECONNAISSANCE (with authorization)                  │
│     ├── Verify passive findings                                │
│     ├── Port scanning                                          │
│     ├── Service enumeration                                     │
│     └── Fill information gaps                                   │
│              │                                                   │
│              ▼                                                   │
│  5. CREATE TARGET PROFILE                                       │
│     └── Comprehensive documentation for next phases            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Categories of Information to Gather

#### Organizational Information
- Company structure and hierarchy
- Key personnel and their roles
- Physical locations and addresses
- Business relationships and partners
- Recent news, press releases, events
- Financial information (if public company)

#### Technical Information
- Domain names (primary and secondary)
- IP address ranges
- Email formats and addresses
- Technology stack (languages, frameworks, platforms)
- Public-facing infrastructure
- Cloud services used
- Historical data (old versions, archived content)

#### Human Information
- Employee names and roles
- Email addresses
- Social media profiles
- Published documents and presentations
- Conference talks
- Technical blog posts

### Hands-On Exercise 3.1: Information Categories

Create your reconnaissance checklist:

```bash
mkdir -p ~/security-lab/notes/stage03
cat << 'EOF' > ~/security-lab/notes/stage03/recon_checklist.md
# Reconnaissance Checklist

## Organizational Information
- [ ] Company full legal name
- [ ] Physical addresses/locations
- [ ] Organizational structure
- [ ] Key executives and leadership
- [ ] Business partners
- [ ] Recent news and press releases
- [ ] Job postings (reveal technologies)

## Technical Information
- [ ] Primary domain(s)
- [ ] Subdomains discovered
- [ ] IP ranges
- [ ] Email format
- [ ] MX records (email servers)
- [ ] NS records (name servers)
- [ ] Web technologies
- [ ] Cloud providers
- [ ] Historical website data

## Human Information
- [ ] Employee names
- [ ] Email addresses
- [ ] Social media profiles
- [ ] LinkedIn presence
- [ ] GitHub/GitLab accounts
- [ ] Published presentations
- [ ] Technical blog posts

## Notes
(Add observations as you learn)
EOF

echo "Checklist created at ~/security-lab/notes/stage03/recon_checklist.md"
```

---

### Milestone 1 Checkpoint

Before proceeding, verify:

- [ ] You understand the difference between passive and active recon
- [ ] You know why passive recon comes first
- [ ] You understand the reconnaissance workflow
- [ ] You've created your recon checklist

---

## Part 2 — OSINT Fundamentals (Milestone 2)

### What is OSINT?

**Open Source Intelligence (OSINT)** is intelligence gathered from publicly available sources. In penetration testing, OSINT helps us understand our target without directly interacting with their systems.

### OSINT Sources

```
┌─────────────────────────────────────────────────────────────────┐
│                    OSINT Source Categories                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SEARCH ENGINES                                                 │
│  ├── Google (with advanced operators)                          │
│  ├── Bing (different results, different index)                 │
│  ├── DuckDuckGo (privacy-focused, unique results)              │
│  ├── Yandex (strong for Eastern Europe)                        │
│  └── Baidu (Chinese content)                                   │
│                                                                  │
│  DOMAIN/IP REGISTRIES                                           │
│  ├── WHOIS databases                                            │
│  ├── Regional Internet Registries (ARIN, RIPE, etc.)           │
│  ├── DNS records                                                │
│  └── BGP routing data                                           │
│                                                                  │
│  CERTIFICATE TRANSPARENCY                                       │
│  ├── crt.sh                                                     │
│  ├── Censys                                                     │
│  └── Certificate logs                                           │
│                                                                  │
│  SOCIAL MEDIA                                                   │
│  ├── LinkedIn (employees, roles, technologies)                 │
│  ├── Twitter/X (announcements, employees)                      │
│  ├── Facebook (company pages)                                  │
│  ├── GitHub (code, commits, contributors)                      │
│  └── Stack Overflow (employee questions)                       │
│                                                                  │
│  SPECIALIZED DATABASES                                          │
│  ├── Shodan (internet-connected devices)                       │
│  ├── Censys (internet scanning data)                           │
│  ├── SecurityTrails (DNS history)                              │
│  ├── BuiltWith (technology profiling)                          │
│  └── Netcraft (web server survey)                              │
│                                                                  │
│  ARCHIVED DATA                                                  │
│  ├── Wayback Machine (archive.org)                             │
│  ├── Google Cache                                               │
│  └── CachedView                                                 │
│                                                                  │
│  DOCUMENTS AND FILES                                            │
│  ├── PDF metadata                                               │
│  ├── Office document properties                                 │
│  ├── Public code repositories                                   │
│  └── Paste sites                                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### WHOIS Lookups

WHOIS provides registration information for domains and IP addresses.

**Information Available:**
- Registrant name and organization
- Contact email addresses
- Registration and expiration dates
- Name servers
- Registrar information

**Commands:**
```bash
# Domain WHOIS
whois example.com

# IP WHOIS
whois 93.184.216.34

# Using specific WHOIS server
whois -h whois.arin.net 93.184.216.34
```

**Privacy Note:** Many domains now use privacy protection services that hide registrant details. This is common and legitimate.

**What to Look For:**
```
┌─────────────────────────────────────────────────────────────────┐
│                 Valuable WHOIS Information                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  DOMAIN WHOIS                                                   │
│  ├── Registrant organization → Confirms ownership              │
│  ├── Registrant email → Potential contact/target               │
│  ├── Name servers → Infrastructure insight                     │
│  ├── Creation date → How long established                      │
│  └── Registrar → Sometimes useful for SE                       │
│                                                                  │
│  IP WHOIS                                                       │
│  ├── Organization → Confirms ownership                         │
│  ├── NetRange → Other IPs they own                             │
│  ├── ASN → Autonomous System Number                            │
│  ├── Country → Geographic location                             │
│  └── Abuse contact → For reporting (not pentesting)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Hands-On Exercise 3.2: WHOIS Investigation

```bash
# Practice WHOIS lookups (use legitimate targets only)
# We'll use public example domains

# Domain lookup
whois google.com > ~/security-lab/notes/stage03/whois_google.txt

# Analyze the results
echo "=== Key Information ===" >> ~/security-lab/notes/stage03/whois_google.txt
grep -i "registrant\|name server\|creation\|expir" ~/security-lab/notes/stage03/whois_google.txt

# IP lookup
whois 8.8.8.8 > ~/security-lab/notes/stage03/whois_ip.txt

# Look for organization and netrange
grep -i "orgname\|netrange\|country" ~/security-lab/notes/stage03/whois_ip.txt

# Document findings
cat << 'EOF' >> ~/security-lab/notes/stage03/whois_notes.md
# WHOIS Analysis Notes

## Domain: google.com
Registrant: 
Name Servers:
Creation Date:
Expiration Date:

## IP: 8.8.8.8
Organization:
Net Range:
Country:

## Observations
- 
EOF
```

### Certificate Transparency

Certificate Transparency (CT) logs are public records of SSL/TLS certificates. This is a **goldmine for subdomain discovery**.

**Why It Works:**
- When a certificate is issued, it's logged publicly
- Certificates often cover multiple subdomains
- Historical certificates reveal old infrastructure

**Using crt.sh:**
```bash
# Query crt.sh for subdomains
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Save results
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > subdomains.txt
```

**Note:** The `%25` is URL encoding for `%`, which is a wildcard.

### The Wayback Machine

Archive.org's Wayback Machine stores historical snapshots of websites.

**Why It's Valuable:**
- Find old pages that revealed too much
- Discover removed content
- See old technology stacks
- Find old login portals
- Discover forgotten subdomains

**Usage:**
```bash
# Check if a site is archived
curl -s "http://archive.org/wayback/available?url=example.com" | jq

# Using waybackurls tool (if installed)
# go install github.com/tomnomnom/waybackurls@latest
echo "example.com" | waybackurls
```

### Hands-On Exercise 3.3: OSINT Workflow

Practice a complete OSINT workflow on a test target:

```bash
# Create an OSINT report template
cat << 'EOF' > ~/security-lab/templates/osint_report.md
# OSINT Report

## Target Information
- Primary Domain: 
- Engagement ID:
- Date:

---

## WHOIS Information

### Domain Registration
```
(Paste relevant WHOIS output)
```

### Key Findings
- Registrant:
- Name Servers:
- Registration Date:

---

## DNS Information

### DNS Records
| Type | Value | Notes |
|------|-------|-------|
| A | | |
| MX | | |
| NS | | |
| TXT | | |

---

## Subdomains Discovered

### From Certificate Transparency
- 

### From Other Sources
-

---

## Technology Stack
- Web Server:
- Frameworks:
- CMS:
- Cloud Provider:

---

## Social Media Presence
- LinkedIn:
- Twitter:
- GitHub:

---

## Archived Content (Wayback Machine)
- Notable old pages:
- Removed content:

---

## Summary
Key findings that may be useful for the engagement:
1.
2.
3.
EOF

echo "OSINT report template created"
```

---

### Milestone 2 Checkpoint

Before proceeding, verify:

- [ ] You understand OSINT sources
- [ ] You can perform WHOIS lookups
- [ ] You understand certificate transparency
- [ ] You know how to use the Wayback Machine
- [ ] You've created the OSINT report template

---

## Part 3 — Search Engine Reconnaissance (Milestone 3)

### Google Dorking

**Google Dorking** (or Google Hacking) uses advanced search operators to find specific information indexed by Google.

### Essential Google Operators

```
┌─────────────────────────────────────────────────────────────────┐
│                    Google Search Operators                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  SITE RESTRICTION                                               │
│  site:example.com         Only results from this domain        │
│  site:*.example.com       Include subdomains                    │
│  -site:www.example.com    Exclude www subdomain                │
│                                                                  │
│  FILE TYPE                                                      │
│  filetype:pdf             Only PDF files                        │
│  filetype:xlsx            Only Excel files                      │
│  filetype:docx            Only Word documents                   │
│  filetype:sql             SQL database dumps                    │
│  filetype:log             Log files                             │
│  filetype:bak             Backup files                          │
│                                                                  │
│  URL PATTERNS                                                   │
│  inurl:admin              "admin" in the URL                    │
│  inurl:login              Login pages                           │
│  inurl:wp-admin           WordPress admin                       │
│  inurl:phpMyAdmin         Database management                   │
│                                                                  │
│  TITLE AND CONTENT                                              │
│  intitle:"index of"       Directory listings                    │
│  intitle:admin            Admin in page title                   │
│  intext:password          Password in page text                 │
│                                                                  │
│  CACHE AND LINKS                                                │
│  cache:example.com        Google's cached version               │
│  link:example.com         Pages linking to site                 │
│                                                                  │
│  COMBINING OPERATORS                                            │
│  site:example.com filetype:pdf                                  │
│  site:example.com inurl:admin                                   │
│  site:example.com intitle:"index of"                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Security-Focused Google Dorks

These dorks help find common security issues:

#### Finding Exposed Files
```
# Directory listings
site:example.com intitle:"index of"

# Backup files
site:example.com filetype:bak
site:example.com filetype:old
site:example.com filetype:backup

# Configuration files
site:example.com filetype:conf
site:example.com filetype:cfg
site:example.com filetype:ini
site:example.com filetype:env

# Database files
site:example.com filetype:sql
site:example.com filetype:db
site:example.com filetype:mdb
```

#### Finding Login Pages
```
site:example.com inurl:login
site:example.com inurl:signin
site:example.com inurl:admin
site:example.com inurl:portal
site:example.com intitle:login
```

#### Finding Sensitive Information
```
site:example.com filetype:pdf "confidential"
site:example.com filetype:xlsx "password"
site:example.com filetype:doc "internal use only"
site:example.com "not for public release"
```

#### Finding Technology Indicators
```
site:example.com inurl:wp-content      # WordPress
site:example.com inurl:wp-includes     # WordPress
site:example.com filetype:php          # PHP site
site:example.com inurl:aspx            # ASP.NET
site:example.com "powered by"          # CMS identification
```

### The Google Hacking Database (GHDB)

Exploit-DB maintains a database of Google dorks: https://www.exploit-db.com/google-hacking-database

Categories include:
- Vulnerable files
- Sensitive directories
- Error messages
- Login pages
- Password files
- Server detection

### Hands-On Exercise 3.4: Google Dorking Reference

Create your own dorking reference:

```bash
cat << 'EOF' > ~/security-lab/notes/stage03/google_dorks.md
# Google Dorking Reference

## Basic Operators
| Operator | Purpose | Example |
|----------|---------|---------|
| site: | Limit to domain | site:example.com |
| filetype: | Specific file type | filetype:pdf |
| inurl: | Text in URL | inurl:admin |
| intitle: | Text in title | intitle:login |
| intext: | Text in body | intext:password |
| cache: | Cached version | cache:example.com |
| -keyword | Exclude term | site:example.com -www |

## Reconnaissance Dorks

### Find Subdomains
```
site:*.example.com -www
```

### Find Documents
```
site:example.com filetype:pdf
site:example.com filetype:doc OR filetype:docx
site:example.com filetype:xls OR filetype:xlsx
site:example.com filetype:ppt OR filetype:pptx
```

### Find Login Pages
```
site:example.com inurl:login OR inurl:signin
site:example.com intitle:login OR intitle:"sign in"
site:example.com inurl:admin OR inurl:administrator
```

### Find Exposed Directories
```
site:example.com intitle:"index of"
site:example.com intitle:"directory listing"
```

### Find Potentially Sensitive Files
```
site:example.com filetype:sql
site:example.com filetype:env
site:example.com filetype:log
site:example.com filetype:bak OR filetype:backup
site:example.com filetype:conf OR filetype:cfg
```

### Find Error Messages
```
site:example.com "sql syntax" OR "mysql error"
site:example.com "warning:" filetype:php
site:example.com "fatal error"
```

### Find Email Addresses
```
site:example.com "@example.com"
site:example.com "email" OR "contact"
```

### Technology Identification
```
site:example.com "powered by"
site:example.com inurl:wp-content
site:example.com inurl:wp-admin
site:example.com filetype:aspx
```

## Usage Notes
- Always use within authorized scope
- Google may rate limit aggressive searching
- Results change over time
- Combine with other OSINT sources
- Document all findings
EOF

echo "Google dorks reference created"
```

### Other Search Engines

Don't rely solely on Google:

**Bing:**
- Different index, different results
- Similar operators (site:, filetype:, inurl:)
- Sometimes finds content Google missed

**DuckDuckGo:**
- Privacy-focused but still useful
- Uses bangs (!g for Google, !b for Bing)
- Different result set

**Shodan:**
- Search engine for internet-connected devices
- Finds servers, IoT devices, industrial systems
- We'll cover in detail later

---

### Milestone 3 Checkpoint

Before proceeding, verify:

- [ ] You understand Google search operators
- [ ] You've created your dorking reference
- [ ] You know security-focused dorks
- [ ] You understand the value of multiple search engines

---

## Part 4 — DNS Enumeration (Milestone 4)

### Why DNS Enumeration Matters

DNS is the backbone of the internet. Thorough DNS enumeration reveals:
- All registered subdomains
- Mail servers
- Name servers
- Cloud services
- Load balancers
- Historical records

### DNS Record Types Review

| Type | Purpose | Security Value |
|------|---------|---------------|
| A | IPv4 address | Server locations |
| AAAA | IPv6 address | Additional servers |
| MX | Mail servers | Email infrastructure |
| NS | Name servers | DNS infrastructure |
| TXT | Text records | SPF, verification, secrets |
| CNAME | Aliases | Real hostnames |
| SOA | Authority | Primary DNS info |
| PTR | Reverse lookup | IP to hostname |
| SRV | Service records | Service discovery |

### Basic DNS Commands

```bash
# Using host
host example.com
host -t MX example.com
host -t NS example.com
host -t TXT example.com

# Using nslookup
nslookup example.com
nslookup -type=MX example.com
nslookup -type=NS example.com
nslookup -type=ANY example.com

# Using dig (most powerful)
dig example.com
dig example.com ANY
dig example.com MX
dig example.com NS
dig example.com TXT
dig +short example.com
dig +trace example.com
```

### Advanced dig Usage

```bash
# Short output (just the answer)
dig +short example.com A
dig +short example.com MX
dig +short example.com NS

# Query specific nameserver
dig @8.8.8.8 example.com
dig @ns1.example.com example.com

# Trace the DNS resolution path
dig +trace example.com

# All records
dig example.com ANY +noall +answer

# Reverse lookup
dig -x 93.184.216.34
```

### Zone Transfers

A **zone transfer** is when a DNS server sends all its records to another server. If misconfigured, this leaks ALL DNS records.

```bash
# Attempt zone transfer
dig axfr @ns1.example.com example.com

# Using host
host -t axfr example.com ns1.example.com

# Using nslookup
nslookup
> server ns1.example.com
> set type=any
> ls -d example.com
```

**Note:** Zone transfers are usually blocked. Finding one that works is a significant security finding.

### DNS Enumeration Tools

#### dnsrecon
```bash
# Standard enumeration
dnsrecon -d example.com

# Brute force subdomains
dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt

# Zone transfer attempt
dnsrecon -d example.com -t axfr

# All enumeration
dnsrecon -d example.com -a
```

#### dnsenum
```bash
# Basic enumeration
dnsenum example.com

# With bruteforce
dnsenum --enum example.com

# Specify wordlist
dnsenum -f /usr/share/wordlists/dirb/small.txt example.com
```

#### fierce
```bash
# DNS reconnaissance
fierce --domain example.com

# With wordlist
fierce --domain example.com --subdomain-file /path/to/wordlist.txt
```

### Hands-On Exercise 3.5: DNS Enumeration Script

Create a DNS enumeration script:

```bash
cat << 'EOF' > ~/security-lab/scripts/dns_enum.sh
#!/bin/bash
# DNS Enumeration Script

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR=~/security-lab/evidence/dns_enum_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTPUT_DIR"

echo "[*] DNS Enumeration for: $DOMAIN"
echo "[*] Output directory: $OUTPUT_DIR"
echo ""

# A Records
echo "[*] Querying A records..."
dig +short $DOMAIN A > "$OUTPUT_DIR/a_records.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/a_records.txt") A records"

# AAAA Records
echo "[*] Querying AAAA records..."
dig +short $DOMAIN AAAA > "$OUTPUT_DIR/aaaa_records.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/aaaa_records.txt") AAAA records"

# MX Records
echo "[*] Querying MX records..."
dig +short $DOMAIN MX > "$OUTPUT_DIR/mx_records.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/mx_records.txt") MX records"

# NS Records
echo "[*] Querying NS records..."
dig +short $DOMAIN NS > "$OUTPUT_DIR/ns_records.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/ns_records.txt") NS records"

# TXT Records
echo "[*] Querying TXT records..."
dig +short $DOMAIN TXT > "$OUTPUT_DIR/txt_records.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/txt_records.txt") TXT records"

# SOA Record
echo "[*] Querying SOA record..."
dig +short $DOMAIN SOA > "$OUTPUT_DIR/soa_record.txt"

# Zone Transfer Attempt
echo "[*] Attempting zone transfer..."
for ns in $(dig +short $DOMAIN NS); do
    echo "    Trying $ns..."
    dig axfr @$ns $DOMAIN >> "$OUTPUT_DIR/zone_transfer.txt" 2>&1
done

# Generate summary
echo ""
echo "[*] Generating summary..."
cat << SUMMARY > "$OUTPUT_DIR/summary.txt"
DNS Enumeration Summary for $DOMAIN
Generated: $(date)
====================================

A Records:
$(cat "$OUTPUT_DIR/a_records.txt")

MX Records:
$(cat "$OUTPUT_DIR/mx_records.txt")

NS Records:
$(cat "$OUTPUT_DIR/ns_records.txt")

TXT Records:
$(cat "$OUTPUT_DIR/txt_records.txt")

SOA Record:
$(cat "$OUTPUT_DIR/soa_record.txt")

Zone Transfer:
$(grep -q "XFR" "$OUTPUT_DIR/zone_transfer.txt" && echo "SUCCESS - Zone transfer allowed!" || echo "Failed (expected)")
SUMMARY

echo "[*] Complete! Check $OUTPUT_DIR/summary.txt"
EOF

chmod +x ~/security-lab/scripts/dns_enum.sh
echo "DNS enumeration script created"
```

---

### Milestone 4 Checkpoint

Before proceeding, verify:

- [ ] You know all major DNS record types
- [ ] You can use dig, host, and nslookup
- [ ] You understand zone transfers
- [ ] You've created the DNS enumeration script
- [ ] You can use dnsrecon and dnsenum

---

## Part 5 — Subdomain Discovery (Milestone 5)

### Why Subdomains Matter

Subdomains often host:
- Development/staging environments (less secure)
- Old/forgotten applications (unpatched)
- Admin interfaces
- API endpoints
- Internal tools accidentally exposed

### Subdomain Discovery Methods

```
┌─────────────────────────────────────────────────────────────────┐
│                Subdomain Discovery Methods                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PASSIVE METHODS (No direct contact)                            │
│  ├── Certificate Transparency (crt.sh)                         │
│  ├── Search engines (site:*.example.com)                       │
│  ├── DNS aggregators (SecurityTrails, VirusTotal)              │
│  ├── Wayback Machine                                            │
│  └── Public datasets                                            │
│                                                                  │
│  ACTIVE METHODS (Direct contact - requires authorization)       │
│  ├── DNS brute forcing                                          │
│  ├── Zone transfers                                             │
│  ├── Virtual host brute forcing                                 │
│  └── Reverse DNS sweeps                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Certificate Transparency

```bash
# Using crt.sh
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
    jq -r '.[].name_value' | \
    sed 's/\*\.//g' | \
    sort -u

# Save to file
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
    jq -r '.[].name_value' | \
    sed 's/\*\.//g' | \
    sort -u > subdomains_crt.txt
```

### DNS Brute Forcing

#### Using gobuster
```bash
# DNS mode
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# With thread control
gobuster dns -d example.com -w /path/to/wordlist.txt -t 50

# Show IP addresses
gobuster dns -d example.com -w /path/to/wordlist.txt -i
```

#### Using ffuf
```bash
# DNS brute force
ffuf -u http://FUZZ.example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Filter by response
ffuf -u http://FUZZ.example.com -w wordlist.txt -fc 404
```

#### Using amass
```bash
# Passive enumeration
amass enum -passive -d example.com

# Active enumeration
amass enum -active -d example.com

# With brute forcing
amass enum -brute -d example.com

# Output to file
amass enum -passive -d example.com -o amass_results.txt
```

#### Using sublist3r
```bash
# Basic usage
sublist3r -d example.com

# With brute force
sublist3r -d example.com -b

# Save output
sublist3r -d example.com -o subdomains.txt
```

### Wordlists for Subdomain Discovery

Location in Kali:
```bash
# SecLists DNS wordlists
ls /usr/share/seclists/Discovery/DNS/

# Common ones:
# subdomains-top1million-5000.txt   (quick scan)
# subdomains-top1million-20000.txt  (medium scan)
# subdomains-top1million-110000.txt (thorough scan)
```

### Hands-On Exercise 3.6: Subdomain Discovery Script

```bash
cat << 'EOF' > ~/security-lab/scripts/subdomain_discovery.sh
#!/bin/bash
# Subdomain Discovery Script - Multiple Methods

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR=~/security-lab/evidence/subdomains_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTPUT_DIR"

echo "[*] Subdomain Discovery for: $DOMAIN"
echo "[*] Output directory: $OUTPUT_DIR"
echo ""

# Method 1: Certificate Transparency
echo "[*] Method 1: Certificate Transparency (crt.sh)..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    sort -u > "$OUTPUT_DIR/crt_sh.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/crt_sh.txt") from crt.sh"

# Method 2: DNS Brute Force (using small wordlist)
echo "[*] Method 2: DNS Brute Force..."
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
if [ -f "$WORDLIST" ]; then
    gobuster dns -d $DOMAIN -w "$WORDLIST" -q -o "$OUTPUT_DIR/gobuster.txt" 2>/dev/null
    echo "    Found $(wc -l < "$OUTPUT_DIR/gobuster.txt") from brute force"
else
    echo "    Wordlist not found, skipping brute force"
fi

# Method 3: Basic DNS enumeration
echo "[*] Method 3: DNS Enumeration..."
dnsrecon -d $DOMAIN -t std 2>/dev/null | grep -oP '[a-zA-Z0-9.-]+\.'$DOMAIN | \
    sort -u > "$OUTPUT_DIR/dnsrecon.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/dnsrecon.txt") from dnsrecon"

# Combine and deduplicate
echo ""
echo "[*] Combining results..."
cat "$OUTPUT_DIR"/*.txt | sort -u > "$OUTPUT_DIR/all_subdomains.txt"
TOTAL=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt")
echo "[*] Total unique subdomains found: $TOTAL"

# Verify live hosts
echo ""
echo "[*] Verifying live hosts..."
while read subdomain; do
    if host "$subdomain" > /dev/null 2>&1; then
        echo "$subdomain" >> "$OUTPUT_DIR/live_subdomains.txt"
    fi
done < "$OUTPUT_DIR/all_subdomains.txt"

if [ -f "$OUTPUT_DIR/live_subdomains.txt" ]; then
    LIVE=$(wc -l < "$OUTPUT_DIR/live_subdomains.txt")
    echo "[*] Live subdomains: $LIVE"
else
    echo "[*] No live subdomains verified"
fi

echo ""
echo "[*] Complete! Results in $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
EOF

chmod +x ~/security-lab/scripts/subdomain_discovery.sh
echo "Subdomain discovery script created"
```

### Subdomain Takeover

When a subdomain points to a service that's been decommissioned, an attacker might be able to claim that service and control the subdomain.

**Common vulnerable services:**
- AWS S3 buckets
- Azure blob storage
- GitHub Pages
- Heroku apps
- Shopify stores

**Identification:**
```bash
# Look for CNAME records pointing to external services
dig CNAME subdomain.example.com

# Common error messages indicating potential takeover:
# "There isn't a GitHub Pages site here"
# "NoSuchBucket" (AWS)
# "No such app" (Heroku)
```

---

### Milestone 5 Checkpoint

Before proceeding, verify:

- [ ] You understand different subdomain discovery methods
- [ ] You can use crt.sh for certificate transparency
- [ ] You can use gobuster, amass, or sublist3r
- [ ] You've created the subdomain discovery script
- [ ] You understand subdomain takeover risks

---

## Part 6 — Email and Employee Harvesting (Milestone 6)

### Why Email Harvesting Matters

Email addresses help you:
- Identify employees for social engineering scope
- Determine email format for guessing other addresses
- Find targets for phishing campaigns (if authorized)
- Identify potentially valuable targets (executives, IT)

### Email Format Discovery

Most organizations use predictable email formats:

| Format | Example | Prevalence |
|--------|---------|------------|
| first.last | john.smith@example.com | Very common |
| firstlast | johnsmith@example.com | Common |
| first_last | john_smith@example.com | Less common |
| flast | jsmith@example.com | Common |
| firstl | johns@example.com | Less common |
| first | john@example.com | Rare |

### Tools for Email Harvesting

#### theHarvester
```bash
# Search multiple sources
theHarvester -d example.com -b all

# Specific sources
theHarvester -d example.com -b google
theHarvester -d example.com -b linkedin
theHarvester -d example.com -b bing

# Limit results
theHarvester -d example.com -b google -l 500

# Save to file
theHarvester -d example.com -b all -f output.html
```

#### hunter.io (Web-based)
- https://hunter.io
- Free tier available
- Shows email format
- Lists discovered emails
- Confidence scores

#### Phonebook.cz
- https://phonebook.cz
- Free subdomain and email lookup
- Historical data

### LinkedIn Reconnaissance

LinkedIn is valuable for finding:
- Employee names
- Job titles and roles
- Technologies mentioned in profiles
- Company structure

**Manual Process:**
1. Search for "Company Name" employees
2. Note names and roles
3. Generate potential email addresses based on format

**Tools:**
- linkedin2username (generates usernames from LinkedIn)
- CrossLinked
- LinkedInt

### Hands-On Exercise 3.7: Email Harvesting Workflow

```bash
cat << 'EOF' > ~/security-lab/scripts/email_harvest.sh
#!/bin/bash
# Email Harvesting Script

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR=~/security-lab/evidence/emails_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTPUT_DIR"

echo "[*] Email Harvesting for: $DOMAIN"
echo ""

# theHarvester
echo "[*] Running theHarvester..."
theHarvester -d $DOMAIN -b google,bing -l 200 2>/dev/null | tee "$OUTPUT_DIR/theharvester_raw.txt"

# Extract emails
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$OUTPUT_DIR/theharvester_raw.txt" | \
    sort -u > "$OUTPUT_DIR/emails.txt"

echo ""
echo "[*] Emails found:"
cat "$OUTPUT_DIR/emails.txt"
echo ""
echo "[*] Total: $(wc -l < "$OUTPUT_DIR/emails.txt") unique emails"

# Determine email format
echo ""
echo "[*] Analyzing email format..."
if grep -qE '^[a-z]+\.[a-z]+@' "$OUTPUT_DIR/emails.txt"; then
    echo "    Format appears to be: first.last@$DOMAIN"
elif grep -qE '^[a-z][a-z]+@' "$OUTPUT_DIR/emails.txt"; then
    echo "    Format appears to be: flast@$DOMAIN"
else
    echo "    Could not determine format - manual review needed"
fi

echo ""
echo "[*] Results saved to $OUTPUT_DIR/"
EOF

chmod +x ~/security-lab/scripts/email_harvest.sh
echo "Email harvesting script created"
```

### Generating Email Lists

Once you know the format, generate potential emails:

```bash
cat << 'EOF' > ~/security-lab/scripts/generate_emails.sh
#!/bin/bash
# Generate email addresses from names

# Usage: ./generate_emails.sh <names_file> <domain> <format>
# Formats: first.last, flast, firstl, first_last

if [ -z "$3" ]; then
    echo "Usage: $0 <names_file> <domain> <format>"
    echo "Formats: first.last, flast, firstl, first_last"
    echo ""
    echo "Names file should have one 'Firstname Lastname' per line"
    exit 1
fi

NAMES_FILE=$1
DOMAIN=$2
FORMAT=$3

while IFS= read -r line; do
    FIRST=$(echo "$line" | awk '{print tolower($1)}')
    LAST=$(echo "$line" | awk '{print tolower($2)}')
    
    case $FORMAT in
        "first.last")
            echo "${FIRST}.${LAST}@${DOMAIN}"
            ;;
        "flast")
            echo "${FIRST:0:1}${LAST}@${DOMAIN}"
            ;;
        "firstl")
            echo "${FIRST}${LAST:0:1}@${DOMAIN}"
            ;;
        "first_last")
            echo "${FIRST}_${LAST}@${DOMAIN}"
            ;;
        *)
            echo "Unknown format: $FORMAT"
            exit 1
            ;;
    esac
done < "$NAMES_FILE"
EOF

chmod +x ~/security-lab/scripts/generate_emails.sh
echo "Email generation script created"
```

---

### Milestone 6 Checkpoint

Before proceeding, verify:

- [ ] You understand why email harvesting matters
- [ ] You can identify common email formats
- [ ] You can use theHarvester
- [ ] You've created the email harvesting scripts
- [ ] You understand LinkedIn's value for reconnaissance

---

## Part 7 — Technology Fingerprinting (Milestone 7)

### Why Technology Fingerprinting Matters

Knowing the technology stack helps you:
- Search for known vulnerabilities (CVEs)
- Choose appropriate exploitation techniques
- Understand the application architecture
- Focus testing on relevant areas

### Web Technology Fingerprinting

#### WhatWeb
```bash
# Basic scan
whatweb example.com

# Aggressive scan
whatweb -a 3 example.com

# Verbose output
whatweb -v example.com

# Multiple targets
whatweb -i targets.txt
```

#### Wappalyzer
- Browser extension (Chrome, Firefox)
- Shows technologies on current page
- CMS, frameworks, JavaScript libraries
- Also available as CLI tool

#### BuiltWith
- https://builtwith.com
- Web-based technology lookup
- Historical data
- Detailed technology stack

### HTTP Headers Analysis

HTTP headers reveal valuable information:

```bash
# Get headers
curl -I https://example.com

# Look for:
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
# X-AspNet-Version: 4.0.30319
# Set-Cookie: (session handling)
```

### CMS Detection

#### Common CMS Indicators

```
┌─────────────────────────────────────────────────────────────────┐
│                   CMS Detection Indicators                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WORDPRESS                                                      │
│  ├── /wp-admin/                                                │
│  ├── /wp-content/                                              │
│  ├── /wp-includes/                                             │
│  ├── wp-login.php                                              │
│  └── Meta generator: WordPress                                 │
│                                                                  │
│  DRUPAL                                                         │
│  ├── /sites/default/                                           │
│  ├── /misc/drupal.js                                           │
│  ├── X-Drupal-Cache header                                     │
│  └── Meta generator: Drupal                                    │
│                                                                  │
│  JOOMLA                                                         │
│  ├── /administrator/                                           │
│  ├── /components/                                              │
│  ├── /modules/                                                 │
│  └── Meta generator: Joomla                                    │
│                                                                  │
│  MAGENTO                                                        │
│  ├── /skin/frontend/                                           │
│  ├── /js/mage/                                                 │
│  ├── Mage.Cookies                                              │
│  └── /downloader/                                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### CMSmap
```bash
# WordPress scan
cmsmap -t https://example.com -f W

# Drupal scan
cmsmap -t https://example.com -f D

# Joomla scan
cmsmap -t https://example.com -f J

# Auto-detect
cmsmap https://example.com
```

### Document Metadata Extraction

Documents often contain metadata revealing:
- Author names (usernames)
- Software versions
- Internal paths
- Printer names
- Timestamps

#### Using exiftool
```bash
# Extract metadata
exiftool document.pdf
exiftool document.docx

# Specific fields
exiftool -Author -Creator -Producer document.pdf

# All files in directory
exiftool *.pdf
```

#### Using metagoofil
```bash
# Download and analyze documents from target
metagoofil -d example.com -t pdf,docx,xlsx -l 100 -o ./output -f results.html

# Options:
# -t: file types
# -l: limit of files
# -o: output directory
```

### Hands-On Exercise 3.8: Technology Fingerprinting

```bash
# Create fingerprinting script
cat << 'EOF' > ~/security-lab/scripts/tech_fingerprint.sh
#!/bin/bash
# Technology Fingerprinting Script

if [ -z "$1" ]; then
    echo "Usage: $0 <url>"
    exit 1
fi

TARGET=$1
OUTPUT_DIR=~/security-lab/evidence/tech_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTPUT_DIR"

echo "[*] Technology Fingerprinting: $TARGET"
echo ""

# HTTP Headers
echo "[*] Gathering HTTP headers..."
curl -sI "$TARGET" > "$OUTPUT_DIR/headers.txt"
echo "    Server: $(grep -i '^Server:' "$OUTPUT_DIR/headers.txt")"
echo "    X-Powered-By: $(grep -i '^X-Powered-By:' "$OUTPUT_DIR/headers.txt")"

# WhatWeb
echo ""
echo "[*] Running WhatWeb..."
whatweb -a 3 "$TARGET" 2>/dev/null | tee "$OUTPUT_DIR/whatweb.txt"

# Check for common CMS paths
echo ""
echo "[*] Checking for common CMS indicators..."

# WordPress
if curl -s "$TARGET/wp-admin/" 2>/dev/null | grep -qi "wordpress\|wp-login"; then
    echo "    [+] WordPress detected"
    echo "WordPress" >> "$OUTPUT_DIR/cms.txt"
fi

# Drupal
if curl -s "$TARGET/misc/drupal.js" 2>/dev/null | grep -qi "drupal"; then
    echo "    [+] Drupal detected"
    echo "Drupal" >> "$OUTPUT_DIR/cms.txt"
fi

# Joomla
if curl -s "$TARGET/administrator/" 2>/dev/null | grep -qi "joomla"; then
    echo "    [+] Joomla detected"
    echo "Joomla" >> "$OUTPUT_DIR/cms.txt"
fi

# robots.txt
echo ""
echo "[*] Checking robots.txt..."
curl -s "$TARGET/robots.txt" > "$OUTPUT_DIR/robots.txt"
if [ -s "$OUTPUT_DIR/robots.txt" ]; then
    echo "    robots.txt found - may reveal hidden paths"
    head -20 "$OUTPUT_DIR/robots.txt"
fi

# Summary
echo ""
echo "[*] Results saved to $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
EOF

chmod +x ~/security-lab/scripts/tech_fingerprint.sh
echo "Technology fingerprinting script created"
```

---

### Milestone 7 Checkpoint

Before proceeding, verify:

- [ ] You can use WhatWeb for fingerprinting
- [ ] You understand HTTP header analysis
- [ ] You can identify common CMS platforms
- [ ] You understand document metadata value
- [ ] You've created the fingerprinting script

---

## Part 8 — Automation and Scripting (Milestone 8)

### Combining It All

Now let's create a master reconnaissance script that combines all our techniques:

```bash
cat << 'EOF' > ~/security-lab/scripts/master_recon.sh
#!/bin/bash
# Master Reconnaissance Script
# Combines all reconnaissance techniques

if [ -z "$1" ]; then
    echo "======================================"
    echo "Master Reconnaissance Script"
    echo "======================================"
    echo ""
    echo "Usage: $0 <domain>"
    echo ""
    echo "This script performs:"
    echo "  - WHOIS lookup"
    echo "  - DNS enumeration"
    echo "  - Subdomain discovery"
    echo "  - Email harvesting"
    echo "  - Technology fingerprinting"
    echo ""
    exit 1
fi

DOMAIN=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR=~/security-lab/evidence/recon_${DOMAIN}_${TIMESTAMP}

# Create output directory structure
mkdir -p "$OUTPUT_DIR"/{whois,dns,subdomains,emails,tech,report}

echo "======================================"
echo "Master Reconnaissance: $DOMAIN"
echo "Started: $(date)"
echo "Output: $OUTPUT_DIR"
echo "======================================"
echo ""

# Phase 1: WHOIS
echo "[PHASE 1] WHOIS Lookup"
echo "─────────────────────"
whois $DOMAIN > "$OUTPUT_DIR/whois/domain.txt" 2>&1
echo "[+] WHOIS data saved"
echo ""

# Phase 2: DNS Enumeration
echo "[PHASE 2] DNS Enumeration"
echo "─────────────────────────"
echo "[*] A Records..."
dig +short $DOMAIN A > "$OUTPUT_DIR/dns/a_records.txt"
echo "[*] MX Records..."
dig +short $DOMAIN MX > "$OUTPUT_DIR/dns/mx_records.txt"
echo "[*] NS Records..."
dig +short $DOMAIN NS > "$OUTPUT_DIR/dns/ns_records.txt"
echo "[*] TXT Records..."
dig +short $DOMAIN TXT > "$OUTPUT_DIR/dns/txt_records.txt"

# Zone transfer attempt
echo "[*] Attempting zone transfers..."
for ns in $(dig +short $DOMAIN NS); do
    dig axfr @$ns $DOMAIN >> "$OUTPUT_DIR/dns/zone_transfer.txt" 2>&1
done
echo "[+] DNS enumeration complete"
echo ""

# Phase 3: Subdomain Discovery
echo "[PHASE 3] Subdomain Discovery"
echo "─────────────────────────────"

# Certificate Transparency
echo "[*] Certificate Transparency..."
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | \
    sort -u > "$OUTPUT_DIR/subdomains/crt_sh.txt"
echo "    Found $(wc -l < "$OUTPUT_DIR/subdomains/crt_sh.txt") from crt.sh"

# DNS brute force (quick)
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
if [ -f "$WORDLIST" ]; then
    echo "[*] DNS brute force (top 5000)..."
    gobuster dns -d $DOMAIN -w "$WORDLIST" -q 2>/dev/null | \
        grep "Found:" | awk '{print $2}' > "$OUTPUT_DIR/subdomains/bruteforce.txt"
    echo "    Found $(wc -l < "$OUTPUT_DIR/subdomains/bruteforce.txt") from brute force"
fi

# Combine results
cat "$OUTPUT_DIR/subdomains"/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all.txt"
echo "[+] Total unique subdomains: $(wc -l < "$OUTPUT_DIR/subdomains/all.txt")"
echo ""

# Phase 4: Email Harvesting
echo "[PHASE 4] Email Harvesting"
echo "──────────────────────────"
echo "[*] Running theHarvester..."
theHarvester -d $DOMAIN -b google,bing -l 200 2>/dev/null > "$OUTPUT_DIR/emails/theharvester.txt"
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$OUTPUT_DIR/emails/theharvester.txt" | \
    sort -u > "$OUTPUT_DIR/emails/addresses.txt"
echo "[+] Found $(wc -l < "$OUTPUT_DIR/emails/addresses.txt") email addresses"
echo ""

# Phase 5: Technology Fingerprinting
echo "[PHASE 5] Technology Fingerprinting"
echo "────────────────────────────────────"
echo "[*] HTTP headers..."
curl -sI "http://$DOMAIN" > "$OUTPUT_DIR/tech/headers_http.txt" 2>&1
curl -sI "https://$DOMAIN" > "$OUTPUT_DIR/tech/headers_https.txt" 2>&1

echo "[*] WhatWeb analysis..."
whatweb -a 3 "https://$DOMAIN" 2>/dev/null > "$OUTPUT_DIR/tech/whatweb.txt"
whatweb -a 3 "http://$DOMAIN" 2>/dev/null >> "$OUTPUT_DIR/tech/whatweb.txt"

echo "[*] Checking robots.txt..."
curl -s "https://$DOMAIN/robots.txt" > "$OUTPUT_DIR/tech/robots.txt" 2>&1
curl -s "http://$DOMAIN/robots.txt" >> "$OUTPUT_DIR/tech/robots.txt" 2>&1

echo "[+] Technology fingerprinting complete"
echo ""

# Generate Report
echo "[REPORT] Generating summary..."
echo "──────────────────────────────"

cat << REPORT > "$OUTPUT_DIR/report/summary.md"
# Reconnaissance Report: $DOMAIN

**Generated:** $(date)
**Output Directory:** $OUTPUT_DIR

---

## Executive Summary

This report contains reconnaissance findings for $DOMAIN.

---

## WHOIS Information

\`\`\`
$(head -50 "$OUTPUT_DIR/whois/domain.txt")
\`\`\`

---

## DNS Records

### A Records
\`\`\`
$(cat "$OUTPUT_DIR/dns/a_records.txt")
\`\`\`

### MX Records
\`\`\`
$(cat "$OUTPUT_DIR/dns/mx_records.txt")
\`\`\`

### NS Records
\`\`\`
$(cat "$OUTPUT_DIR/dns/ns_records.txt")
\`\`\`

### TXT Records
\`\`\`
$(cat "$OUTPUT_DIR/dns/txt_records.txt")
\`\`\`

---

## Subdomains Discovered

**Total:** $(wc -l < "$OUTPUT_DIR/subdomains/all.txt") unique subdomains

### All Subdomains
\`\`\`
$(cat "$OUTPUT_DIR/subdomains/all.txt")
\`\`\`

---

## Email Addresses

**Total:** $(wc -l < "$OUTPUT_DIR/emails/addresses.txt") addresses found

\`\`\`
$(cat "$OUTPUT_DIR/emails/addresses.txt")
\`\`\`

---

## Technology Stack

### HTTP Headers
\`\`\`
$(cat "$OUTPUT_DIR/tech/headers_https.txt" | head -20)
\`\`\`

### WhatWeb Results
\`\`\`
$(cat "$OUTPUT_DIR/tech/whatweb.txt")
\`\`\`

---

## Next Steps

Based on these findings, recommended next steps:
1. Verify subdomain accessibility
2. Perform port scanning on discovered hosts
3. Identify vulnerabilities in discovered technologies
4. Develop phishing pretexts using discovered information

---

*Report generated by master_recon.sh*
REPORT

echo "[+] Report saved to $OUTPUT_DIR/report/summary.md"
echo ""
echo "======================================"
echo "Reconnaissance Complete"
echo "Completed: $(date)"
echo "Results: $OUTPUT_DIR/"
echo "======================================"
echo ""
echo "Key files:"
echo "  - $OUTPUT_DIR/report/summary.md"
echo "  - $OUTPUT_DIR/subdomains/all.txt"
echo "  - $OUTPUT_DIR/emails/addresses.txt"
EOF

chmod +x ~/security-lab/scripts/master_recon.sh
echo "Master reconnaissance script created"
```

---

## Stage 03 Assessment

### Written Assessment

Create: `~/security-lab/notes/stage03/assessment.md`

1. What is the difference between passive and active reconnaissance? Give two examples of each.

2. What information can you obtain from a WHOIS lookup?

3. List five Google dork operators and explain what each does.

4. What is certificate transparency and how is it useful for subdomain discovery?

5. Name four methods for discovering subdomains and explain when you would use each.

6. What is a DNS zone transfer and why is it a security concern?

7. How can you determine an organization's email format?

8. What tools can you use for technology fingerprinting? What information do they reveal?

9. Why is document metadata valuable for reconnaissance?

10. How does thorough reconnaissance improve penetration testing effectiveness?

### Practical Assessment

1. **Complete Reconnaissance Exercise:**
   Using your lab environment (or an authorized target), perform complete reconnaissance and document:
   - All DNS records
   - All discovered subdomains
   - Technology stack identified
   - Save in proper report format

2. **Script Demonstration:**
   Run your master_recon.sh script and review the output. Document any improvements you would make.

3. **Target Profile:**
   Create a complete target profile for Metasploitable 2 using all reconnaissance techniques applicable to a local target.

---

## Stage 03 Completion Checklist

### Passive vs Active
- [ ] Understand the difference
- [ ] Know when each is appropriate
- [ ] Created recon checklist

### OSINT
- [ ] Can perform WHOIS lookups
- [ ] Understand certificate transparency
- [ ] Know Wayback Machine usage
- [ ] Created OSINT report template

### Search Engine Recon
- [ ] Know Google operators
- [ ] Created dorking reference
- [ ] Understand security-focused dorks

### DNS Enumeration
- [ ] Master dig, host, nslookup
- [ ] Understand all record types
- [ ] Can attempt zone transfers
- [ ] Created DNS enumeration script

### Subdomain Discovery
- [ ] Use multiple discovery methods
- [ ] Can use crt.sh, gobuster, amass
- [ ] Created subdomain discovery script

### Email Harvesting
- [ ] Can use theHarvester
- [ ] Understand email format discovery
- [ ] Created email harvesting scripts

### Technology Fingerprinting
- [ ] Can use WhatWeb
- [ ] Understand header analysis
- [ ] Can identify CMS platforms
- [ ] Created fingerprinting script

### Automation
- [ ] Created master_recon.sh
- [ ] All scripts working

### Assessment
- [ ] Written assessment complete
- [ ] Practical assessment complete

---

## What's Next: Stage 04 Preview

In Stage 04 — Scanning and Enumeration, you will:

- Master Nmap for network scanning
- Understand different scan types
- Perform service version detection
- Use the Nmap Scripting Engine
- Enumerate network services in detail
- Prepare for vulnerability analysis

**You now know how to find the targets—next you'll learn how to analyze them!**

---

**Commit your work and proceed to Stage 04 when ready:**

```bash
cd ~/security-lab
git add .
git commit -m "Complete Stage 03 - Reconnaissance and Information Gathering"
```

---

**End of Stage 03 — Reconnaissance and Information Gathering**
