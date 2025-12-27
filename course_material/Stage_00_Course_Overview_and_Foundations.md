# Certified Ethical Hacking I
## Complete Beginner's Learning Path to Entry-Level Penetration Testing

**Curriculum Version:** 1.0  
**Audience:** Complete beginners transitioning to cybersecurity careers  
**Prerequisites:** Python basics, Linux CLI fundamentals, Windows fluency, basic computer hardware knowledge

---

## Welcome to Your Ethical Hacking Journey

This comprehensive curriculum will guide you from complete beginner to entry-level job readiness in ethical hacking and penetration testing. Every concept is explained from first principles, every tool is introduced with context and purpose, and every skill is practiced through hands-on exercises that mirror real-world professional engagements.

**This is not a race.** Mastery takes the time it takes. The goal is not to finish quickly—the goal is to understand deeply enough to apply these skills professionally and ethically.

---

## How This Curriculum Is Structured

### The Stage-Based Approach

This curriculum is divided into stages, each building on the previous. You cannot skip stages—later concepts depend on earlier foundations. Each stage follows a consistent structure:

1. **Why This Matters** — Professional context and career relevance
2. **What You Will Learn** — Skills mapped to job requirements
3. **Milestones** — Clear checkpoints to verify progress
4. **Conceptual Foundation** — Theory explained from first principles
5. **Hands-On Practice** — Exercises in your lab environment
6. **Professional Context** — How this skill is used in real engagements
7. **Assessment** — Written and practical verification of understanding
8. **Completion Checklist** — Confirm mastery before advancing

### The Stages

| Stage | Title | Focus |
|-------|-------|-------|
| 00 | Course Overview and Foundations | This document - orientation and prerequisites |
| 01 | Ethical Hacking Fundamentals | Legal/ethical framework, methodology, career paths |
| 02 | Networking for Penetration Testers | TCP/IP, protocols, network analysis (essential foundation) |
| 03 | Reconnaissance and Information Gathering | OSINT, passive/active recon, footprinting |
| 04 | Scanning and Enumeration | Network scanning, service identification, vulnerability discovery |
| 05 | Vulnerability Analysis | Assessment methodologies, CVE/CVSS, prioritization |
| 06 | System Hacking Fundamentals | Password attacks, privilege escalation concepts |
| 07 | Web Application Security | OWASP Top 10, common web vulnerabilities |
| 08 | Exploitation Fundamentals | Metasploit basics, controlled exploitation |
| 09 | Post-Exploitation Concepts | Maintaining access, lateral movement theory |
| 10 | Professional Practice | Documentation, reporting, career preparation |

---

## What You Will Build

Throughout this curriculum, you will create:

### Technical Deliverables
- A fully configured penetration testing lab environment
- Custom reconnaissance scripts and automation tools
- Vulnerability scanning workflows
- Exploitation documentation and notes
- Professional penetration test reports
- A personal methodology reference guide

### Professional Portfolio
- Documented lab exercises demonstrating practical skills
- Written assessments showing conceptual understanding
- Sample deliverables suitable for job interviews
- GitHub repository of your security tools and scripts

---

## Prerequisites Verification

Before beginning Stage 01, verify you have the following:

### From Your Python Tutorial
- [ ] Can write and execute Python scripts
- [ ] Understand functions, loops, and conditionals
- [ ] Can work with files and handle errors
- [ ] Have created CLI tools with user interaction
- [ ] Familiar with APIs and HTTP requests

### From Your Kali Linux Tutorial
- [ ] Comfortable with Linux command line navigation
- [ ] Can create, modify, and manage files and permissions
- [ ] Understand users, groups, and basic system administration
- [ ] Can write basic shell scripts
- [ ] Have VirtualBox or VMware installed and working
- [ ] Have created virtual machines successfully

### Additional Requirements
- [ ] Windows operating system fluency
- [ ] Basic computer hardware understanding (CPU, RAM, storage, network interfaces)
- [ ] Internet connection for downloading tools and updates
- [ ] At least 100GB free disk space for lab VMs
- [ ] 16GB RAM recommended (8GB minimum, will limit concurrent VMs)
- [ ] Patience and commitment to thorough learning

### What You Don't Need (Yet)
- Deep networking knowledge (covered in Stage 02)
- Prior cybersecurity experience
- Expensive tools or certifications
- A degree in computer science

---

## Understanding Ethical Hacking

### What is Ethical Hacking?

**Ethical hacking** (also called penetration testing or "pentesting") is the practice of testing computer systems, networks, and applications for security vulnerabilities using the same techniques that malicious hackers might use—but with explicit authorization and the goal of improving security.

```
┌─────────────────────────────────────────────────────────────────┐
│                  Malicious Hacking vs. Ethical Hacking           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MALICIOUS HACKING                                              │
│  ├── No authorization                                           │
│  ├── Goal: Personal gain (money, data, disruption)             │
│  ├── Illegal in all jurisdictions                               │
│  ├── Damages organizations and individuals                      │
│  └── Results in criminal prosecution                            │
│                                                                  │
│  ETHICAL HACKING                                                │
│  ├── Explicit written authorization required                    │
│  ├── Goal: Improve security by finding weaknesses              │
│  ├── Legal when properly authorized                             │
│  ├── Helps organizations protect themselves                     │
│  └── Results in professional reports and remediation           │
│                                                                  │
│  THE ONLY DIFFERENCE: AUTHORIZATION AND INTENT                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Why Organizations Need Ethical Hackers

Organizations face constant security threats. They need to:
- Identify vulnerabilities before attackers do
- Test security controls to verify they work
- Meet compliance requirements (PCI-DSS, HIPAA, SOC 2)
- Protect customer data and reputation
- Understand their real-world attack surface

**Ethical hackers provide this service professionally and legally.**

### The Ethical Hacking Mindset

To succeed as an ethical hacker, you must develop:

1. **Curiosity** — Always asking "what if?" and "how does this work?"
2. **Persistence** — Trying multiple approaches when one fails
3. **Systematic Thinking** — Following methodology, not random guessing
4. **Attention to Detail** — Small misconfigurations lead to big vulnerabilities
5. **Ethical Foundation** — Understanding the responsibility that comes with these skills
6. **Documentation Discipline** — Recording everything for professional reporting

---

## The Legal Framework

### This Is Not Optional

Understanding the legal framework is **required**, not suggested. Unauthorized access to computer systems is a serious crime with severe consequences.

### Key Laws (United States)

#### Computer Fraud and Abuse Act (CFAA)
The primary federal law governing computer crimes in the United States.

**Violations include:**
- Accessing a computer without authorization
- Exceeding authorized access
- Trafficking in passwords
- Causing damage to protected computers
- Extortion involving computers

**Penalties:**
- First offense: Up to 5-10 years imprisonment
- Repeat offenses: Up to 20 years
- Civil liability for damages

#### State Laws
All 50 states have additional computer crime laws, often with stricter penalties.

### International Considerations

| Region | Key Legislation |
|--------|-----------------|
| European Union | Computer Misuse Directive, GDPR |
| United Kingdom | Computer Misuse Act 1990 |
| Canada | Criminal Code Section 342.1 |
| Australia | Cybercrime Act 2001 |

**Important:** Laws vary by jurisdiction. If testing systems in other countries, research local laws.

### What Makes It Legal?

```
┌─────────────────────────────────────────────────────────────────┐
│                    Requirements for Legal Testing                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. WRITTEN AUTHORIZATION                                       │
│     • Signed by someone with authority to authorize             │
│     • Specifies exactly what systems can be tested              │
│     • Defines the testing period (start/end dates)              │
│     • Lists permitted testing methods                           │
│     • Often called "Rules of Engagement" or "Scope Agreement"   │
│                                                                  │
│  2. CLEAR SCOPE DEFINITION                                      │
│     • IP addresses and ranges in scope                          │
│     • Domains and subdomains in scope                           │
│     • Systems explicitly OUT of scope                           │
│     • Third-party systems (cloud providers, shared hosting)     │
│                                                                  │
│  3. DEFINED BOUNDARIES                                          │
│     • What actions are permitted (scanning, exploitation)       │
│     • What actions are prohibited (DoS, data destruction)       │
│     • Notification requirements for critical findings           │
│     • Emergency contact information                              │
│                                                                  │
│  4. PROFESSIONAL LIABILITY                                      │
│     • Insurance requirements                                     │
│     • Indemnification clauses                                   │
│     • Confidentiality agreements (NDA)                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### For This Curriculum

**You will ONLY practice on systems you control:**
- Virtual machines you create (Kali Linux, Metasploitable, etc.)
- Intentionally vulnerable labs (DVWA, VulnHub, HackTheBox)
- Your own home network equipment

**Never test:**
- Employer systems without written authorization
- Friend/family systems without written authorization
- Public websites or services
- "Just to see if it works"

**When in doubt: DON'T.**

---

## Career Paths in Ethical Hacking

### Entry-Level Positions

This curriculum prepares you for these entry-level roles:

#### Junior Penetration Tester
- Assist senior testers on engagements
- Perform reconnaissance and scanning
- Document findings and evidence
- Help write client reports
- **Typical salary range:** $60,000 - $85,000

#### Security Analyst (with offensive focus)
- Monitor security systems
- Perform vulnerability assessments
- Respond to security incidents
- **Typical salary range:** $55,000 - $80,000

#### SOC Analyst with Testing Knowledge
- Understand attacker techniques (helps with detection)
- Perform threat hunting
- Validate security controls
- **Typical salary range:** $50,000 - $75,000

### Relevant Certifications

This curriculum aligns with objectives from:

| Certification | Organization | Level | Focus |
|--------------|--------------|-------|-------|
| CompTIA Security+ | CompTIA | Entry | Security fundamentals |
| CompTIA PenTest+ | CompTIA | Intermediate | Penetration testing |
| CEH (Certified Ethical Hacker) | EC-Council | Intermediate | Ethical hacking |
| eJPT (eLearnSecurity Junior PT) | INE | Entry | Practical pentesting |
| OSCP (Offensive Security Certified Professional) | Offensive Security | Advanced | Hands-on exploitation |

**Note:** This curriculum provides knowledge that may help prepare for certifications, but does not guarantee exam success or certification eligibility. Always verify current exam objectives with the certifying organization.

### Building Your Career

```
┌─────────────────────────────────────────────────────────────────┐
│                    Typical Career Progression                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  YEAR 0-2: ENTRY LEVEL                                          │
│  ├── Junior Penetration Tester                                  │
│  ├── Security Analyst                                           │
│  ├── SOC Analyst                                                │
│  └── Focus: Learn methodology, tools, documentation             │
│                                                                  │
│  YEAR 2-5: MID LEVEL                                            │
│  ├── Penetration Tester                                         │
│  ├── Red Team Operator                                          │
│  ├── Security Consultant                                        │
│  └── Focus: Lead engagements, specialize, mentor juniors        │
│                                                                  │
│  YEAR 5+: SENIOR                                                │
│  ├── Senior Penetration Tester                                  │
│  ├── Red Team Lead                                              │
│  ├── Principal Security Consultant                              │
│  ├── Security Architect                                         │
│  └── Focus: Strategy, complex engagements, leadership           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Setting Up Your Lab Environment

### Why a Lab Matters

You cannot learn ethical hacking by reading—you must practice. A lab environment gives you:

- **Safe space** to experiment without legal risk
- **Repeatable environment** for consistent learning
- **Realistic targets** that simulate real vulnerabilities
- **No consequences** for mistakes (just rebuild the VM)

### Lab Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Lab Environment                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  YOUR HOST COMPUTER                                             │
│  (Windows/Mac/Linux with VirtualBox or VMware)                  │
│                                                                  │
│     ┌─────────────────────────────────────────────────────┐     │
│     │              VIRTUAL NETWORK (NAT/Host-Only)        │     │
│     │                                                      │     │
│     │   ┌─────────────┐     ┌─────────────────────────┐   │     │
│     │   │ KALI LINUX  │     │  VULNERABLE TARGETS     │   │     │
│     │   │             │     │                         │   │     │
│     │   │ Your attack │────►│ • Metasploitable 2     │   │     │
│     │   │ machine     │     │ • DVWA                  │   │     │
│     │   │             │     │ • Windows vulnerable VM │   │     │
│     │   │             │     │ • Custom vulnerable apps│   │     │
│     │   └─────────────┘     └─────────────────────────┘   │     │
│     │                                                      │     │
│     └─────────────────────────────────────────────────────┘     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Required Virtual Machines

#### 1. Kali Linux (Attack Machine)
Your primary tool for penetration testing.

**What it is:** A Debian-based Linux distribution pre-loaded with hundreds of security tools.

**Download:** https://www.kali.org/get-kali/

**Recommended specs:**
- 4GB RAM (more is better)
- 2 CPU cores
- 50GB disk space
- NAT + Host-Only network adapters

#### 2. Metasploitable 2 (Vulnerable Target)
An intentionally vulnerable Linux VM for safe practice.

**What it is:** A deliberately insecure Ubuntu VM with multiple vulnerabilities.

**Download:** https://sourceforge.net/projects/metasploitable/

**Specs:**
- 512MB RAM
- 1 CPU core
- 10GB disk space
- Host-Only network adapter only (never connect to real network!)

#### 3. DVWA (Damn Vulnerable Web Application)
A PHP/MySQL web application for practicing web attacks.

**What it is:** A deliberately vulnerable web application with various security levels.

**Options:**
- Include in Metasploitable (pre-installed)
- Run standalone in Docker
- Install on separate VM

### Step-by-Step: Lab Setup

Since you've already completed the Kali Linux tutorial, you should have VirtualBox installed and be comfortable creating VMs. Here's how to extend your lab:

#### Step 1: Verify Your Kali VM

```bash
# In your Kali VM, verify tools are available
which nmap
which nikto
which msfconsole
whoami  # Should show your username
```

#### Step 2: Download Metasploitable 2

1. Go to https://sourceforge.net/projects/metasploitable/
2. Download the `.zip` file
3. Extract to find the `.vmdk` file

#### Step 3: Create Metasploitable VM in VirtualBox

1. Open VirtualBox
2. Click **New**
3. Configure:
   - **Name:** Metasploitable2
   - **Type:** Linux
   - **Version:** Ubuntu (64-bit)
4. Memory: 512MB
5. Hard disk: **Use an existing virtual hard disk file**
6. Browse to the extracted `.vmdk` file
7. Click **Create**

#### Step 4: Configure Network

**Critical: Metasploitable must NEVER connect to your real network.**

1. Select Metasploitable2 VM
2. Click **Settings → Network**
3. **Adapter 1:**
   - Attached to: **Host-only Adapter**
   - Name: Select your host-only network
4. Disable all other adapters

5. Configure Kali the same way:
   - **Adapter 1:** NAT (for internet access)
   - **Adapter 2:** Host-only Adapter (same as Metasploitable)

#### Step 5: Verify Connectivity

Start both VMs and verify:

```bash
# On Kali, get your Host-only IP
ip addr show eth1  # or similar

# On Metasploitable, log in (msfadmin:msfadmin) and get IP
ifconfig

# From Kali, ping Metasploitable
ping <metasploitable-ip>

# Should see responses
```

#### Step 6: Create Snapshots

**Always create snapshots before testing:**

1. Power off VMs
2. Right-click VM → **Snapshots**
3. Click **Take** 
4. Name it "Clean State"

**Why snapshots matter:**
- Restore after breaking something
- Reset to clean state between exercises
- Save known-good configurations

---

## The Penetration Testing Methodology

### Why Methodology Matters

Random hacking leads to:
- Missed vulnerabilities
- Wasted time
- Poor documentation
- Unprofessional results

**Methodology provides:**
- Systematic coverage
- Reproducible results
- Professional documentation
- Efficient use of time

### The Five Phases

```
┌─────────────────────────────────────────────────────────────────┐
│              Penetration Testing Methodology                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────┐                                              │
│  │ 1. RECONNAIS- │  Gather information about the target         │
│  │    SANCE      │  (passive and active)                        │
│  └───────┬───────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌───────────────┐                                              │
│  │ 2. SCANNING   │  Identify live hosts, open ports,            │
│  │               │  running services                             │
│  └───────┬───────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌───────────────┐                                              │
│  │ 3. GAINING    │  Exploit vulnerabilities to gain             │
│  │    ACCESS     │  initial access                               │
│  └───────┬───────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌───────────────┐                                              │
│  │ 4. MAINTAIN-  │  Establish persistence, escalate             │
│  │    ING ACCESS │  privileges, move laterally                   │
│  └───────┬───────┘                                              │
│          │                                                       │
│          ▼                                                       │
│  ┌───────────────┐                                              │
│  │ 5. COVERING   │  Document findings, clean up,                │
│  │    TRACKS/    │  deliver professional report                  │
│  │    REPORTING  │                                              │
│  └───────────────┘                                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Phase Details

#### Phase 1: Reconnaissance
**Goal:** Gather as much information as possible about the target.

**Passive Reconnaissance (no direct interaction):**
- WHOIS lookups
- DNS enumeration
- Google dorking
- Social media research
- Job posting analysis

**Active Reconnaissance (direct interaction):**
- Network scanning
- Port scanning
- Service enumeration
- Banner grabbing

**Deliverable:** Target profile with IPs, domains, technologies, personnel

#### Phase 2: Scanning and Enumeration
**Goal:** Identify specific vulnerabilities to exploit.

**Activities:**
- Full port scans
- Service version detection
- Vulnerability scanning
- Web application scanning
- Manual verification

**Deliverable:** List of potential vulnerabilities with evidence

#### Phase 3: Gaining Access
**Goal:** Exploit vulnerabilities to gain initial foothold.

**Activities:**
- Exploit selection
- Payload generation
- Exploitation attempts
- Initial shell access

**Deliverable:** Documented access to target systems

#### Phase 4: Maintaining Access (Post-Exploitation)
**Goal:** Establish persistence and expand access.

**Activities:**
- Privilege escalation
- Credential harvesting
- Lateral movement
- Persistence mechanisms

**Deliverable:** Documented scope of compromise

#### Phase 5: Reporting
**Goal:** Deliver actionable findings to the client.

**Activities:**
- Evidence compilation
- Risk rating
- Remediation recommendations
- Executive summary
- Technical details

**Deliverable:** Professional penetration test report

---

## How to Use This Curriculum

### The Learning Process

For each topic:

1. **Read the conceptual explanation** — Understand what and why before how
2. **Study the technical details** — Learn commands, tools, and techniques
3. **Practice in your lab** — Hands-on exercises are not optional
4. **Verify understanding** — Complete checkpoint assessments
5. **Reflect and document** — Note what worked, what didn't, questions

### What to Do When Stuck

```
┌─────────────────────────────────────────────────────────────────┐
│                    When You Get Stuck                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. RE-READ THE SECTION                                         │
│     Often the answer is there—don't skip ahead                  │
│                                                                  │
│  2. CHECK YOUR SYNTAX                                           │
│     Typos, wrong flags, missing spaces—double-check everything  │
│                                                                  │
│  3. VERIFY YOUR ENVIRONMENT                                     │
│     Is the target running? Is networking configured? Ping it.   │
│                                                                  │
│  4. USE MAN PAGES AND --HELP                                    │
│     $ man nmap                                                  │
│     $ nmap --help                                               │
│                                                                  │
│  5. SEARCH THE ERROR MESSAGE                                    │
│     Copy the exact error and search online                      │
│                                                                  │
│  6. DOCUMENT YOUR QUESTION                                      │
│     Write down exactly what you tried and what happened         │
│     This often reveals the answer                               │
│                                                                  │
│  7. TAKE A BREAK                                                │
│     Fresh eyes solve problems. Walk away and return.            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### The Practice Mindset

**Learning security is not like learning facts—it's like learning a skill.**

You cannot learn to play piano by reading about piano. You cannot learn penetration testing by reading about it.

**Every exercise must be done, not just read.**

When you see a command, type it yourself. Don't copy-paste. The muscle memory matters.

---

## Course Policies

### Documentation Standards

Throughout this course, you will maintain:

1. **Command Notes** — Every command you run, what it does, why you used it
2. **Findings Documentation** — Every vulnerability found, with evidence
3. **Methodology Notes** — Your personal workflow and lessons learned
4. **Error Log** — Problems encountered and how you solved them

**Use this structure:**
```
~/security-lab/
├── notes/
│   ├── stage01/
│   ├── stage02/
│   └── ...
├── scripts/
├── evidence/
└── reports/
```

### Ethical Commitment

By proceeding with this curriculum, you agree to:

1. **Only practice on authorized systems** (your own VMs and lab environments)
2. **Never use these skills maliciously**
3. **Report vulnerabilities responsibly** if you ever discover them in real systems
4. **Respect confidentiality** of any data encountered
5. **Continue ethical conduct** throughout your career

This is not a legal contract—it's a professional commitment to yourself.

---

## Stage 00 Completion Checklist

Before proceeding to Stage 01, verify:

### Prerequisites
- [ ] Python basics completed (can write functions, handle errors)
- [ ] Linux CLI tutorial completed (comfortable with terminal)
- [ ] VirtualBox or VMware installed and working
- [ ] At least 100GB disk space available
- [ ] At least 8GB RAM (16GB recommended)

### Understanding
- [ ] Can explain the difference between ethical and malicious hacking
- [ ] Understand the legal requirements for authorized testing
- [ ] Know the five phases of penetration testing methodology
- [ ] Understand what careers this curriculum prepares for

### Lab Setup
- [ ] Kali Linux VM configured and running
- [ ] Metasploitable 2 downloaded and VM created
- [ ] Network configured (Kali can ping Metasploitable)
- [ ] Both VMs have snapshots saved
- [ ] Metasploitable is NOT connected to real network

### Organization
- [ ] Created `~/security-lab/` directory structure
- [ ] Have a method for taking notes (Markdown recommended)
- [ ] Understand the stage-based learning approach

---

## What's Next: Stage 01 Preview

In Stage 01 — Ethical Hacking Fundamentals, you will:

- Deep dive into legal and ethical frameworks
- Understand penetration testing engagement types
- Learn about penetration testing methodologies in detail (PTES, OWASP, NIST)
- Explore the rules of engagement and scoping
- Begin your penetration testing documentation template
- Complete your first authorized "engagement" against Metasploitable

---

## Important Reminders

1. **Never test without authorization** — This cannot be overstated
2. **Take your time** — Speed is not the goal; understanding is
3. **Practice every exercise** — Reading is not enough
4. **Document everything** — Professional habits start now
5. **Ask questions** — Note what confuses you for further research
6. **Stay ethical** — These skills come with responsibility

---

**You are ready to begin. Proceed to Stage 01 when your checklist is complete.**

```bash
# Create your working directory
mkdir -p ~/security-lab/{notes,scripts,evidence,reports}
mkdir -p ~/security-lab/notes/{stage00,stage01,stage02,stage03,stage04,stage05,stage06,stage07,stage08,stage09,stage10}

# Create your first documentation file
cat << 'EOF' > ~/security-lab/notes/stage00/completion.txt
Stage 00 Completion Notes
=========================
Date completed: 
Prerequisites verified: Yes/No
Lab setup completed: Yes/No
Questions/concerns:

EOF

echo "Setup complete. Edit ~/security-lab/notes/stage00/completion.txt"
```

---

**End of Stage 00 — Course Overview and Foundations**

Proceed to Stage 01 when ready.
