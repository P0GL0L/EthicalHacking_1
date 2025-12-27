# Stage 01 — Ethical Hacking Fundamentals
## The Legal, Ethical, and Methodological Foundation of Penetration Testing

**Certified Ethical Hacking I Learning Path**  
**Audience:** Complete beginners who have completed Stage 00

Welcome to Stage 01. Before you touch a single security tool, you must understand the legal, ethical, and professional framework that governs penetration testing. This is not an obstacle to "the fun stuff"—this IS the foundation that separates professionals from criminals.

---

## Prerequisites

Before starting Stage 01, you must have completed Stage 00:

- [ ] Kali Linux VM configured and working
- [ ] Metasploitable 2 VM configured and working
- [ ] Network connectivity verified between VMs
- [ ] Snapshots created for both VMs
- [ ] Directory structure created (`~/security-lab/`)
- [ ] Understand basic penetration testing phases

If any of these are not checked, return to Stage 00 first.

---

## Why This Stage Matters

Every year, well-meaning individuals face criminal prosecution because they:
- Tested a friend's website "to help them"
- Scanned their employer's network without authorization
- Assumed permission that was never given
- Didn't understand the legal boundaries

**Your technical skills are worthless if you're in prison or facing a lawsuit.**

This stage ensures you understand:
- What makes testing legal
- How professional engagements are structured
- Industry-standard methodologies
- Documentation requirements
- Your professional responsibilities

---

## What You Will Learn

By the end of this stage, you will be able to:

- Explain the legal framework governing penetration testing
- Identify the elements of a valid authorization document
- Describe the different types of penetration testing engagements
- Understand and apply penetration testing methodologies
- Create proper documentation for engagements
- Navigate ethical dilemmas in security testing
- Conduct your first authorized assessment (against Metasploitable)

---

## What You Will Build

1. **Rules of Engagement template** — Professional authorization document
2. **Scope definition template** — Clear boundary documentation
3. **Methodology reference guide** — Personal quick-reference
4. **First engagement documentation** — Practice on Metasploitable
5. **Ethical decision framework** — For navigating dilemmas

---

## Certification Alignment

This stage maps to objectives from:

| Certification | Relevant Domains |
|--------------|------------------|
| **CompTIA PenTest+** | 1.0 Planning and Scoping |
| **CompTIA Security+** | 1.1 Security Concepts, 5.4 Security Governance |
| **CEH** | Module 1: Introduction to Ethical Hacking |
| **eJPT** | Assessment Methodologies |

---

## Time Estimate

**Total: 20-25 hours**

| Section | Hours |
|---------|-------|
| Legal Framework Deep Dive | 4-5 |
| Types of Penetration Tests | 2-3 |
| Authorization and Scoping | 4-5 |
| Penetration Testing Methodologies | 4-5 |
| Documentation Standards | 2-3 |
| Ethics and Professional Conduct | 2-3 |
| Practice Engagement | 2-3 |

Take the time you need—these concepts must be solid before proceeding.

---

## The Milestones Approach

### Stage 01 Milestones

1. **Understand the legal framework completely**
2. **Identify types of penetration testing engagements**
3. **Create authorization documentation templates**
4. **Master the phases of penetration testing methodology**
5. **Establish documentation standards**
6. **Complete ethical decision-making exercises**
7. **Conduct first practice engagement**
8. **Complete the stage assessment**

---

## Part 1 — The Legal Framework (Milestone 1)

### Why Legal Understanding Is Non-Negotiable

```
┌─────────────────────────────────────────────────────────────────┐
│                    The Stakes Are Real                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WHAT CAN HAPPEN WITHOUT AUTHORIZATION:                         │
│                                                                  │
│  • Criminal prosecution under CFAA or state laws                │
│  • Felony charges (not misdemeanors)                            │
│  • Prison sentences up to 20 years for repeat offenses          │
│  • Massive civil liability                                      │
│  • Permanent criminal record                                    │
│  • Career destruction in cybersecurity                          │
│  • Loss of professional certifications                          │
│  • Inability to obtain security clearances                      │
│                                                                  │
│  "I WAS JUST TESTING" IS NOT A LEGAL DEFENSE                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Computer Fraud and Abuse Act (CFAA) - Deep Dive

The CFAA is the primary federal law in the United States governing computer crimes. Enacted in 1986 and amended multiple times, it defines what constitutes unauthorized computer access.

#### Key Provisions

**§ 1030(a)(2) - Obtaining Information**
Intentionally accessing a computer without authorization (or exceeding authorized access) to obtain:
- Information from financial institutions
- Information from the US government
- Information from any protected computer

**§ 1030(a)(5) - Causing Damage**
Knowingly causing damage to a protected computer through:
- Transmission of code, programs, or commands
- Intentional access without authorization

**§ 1030(a)(7) - Extortion**
Threatening to damage a protected computer or obtain information to extort money.

#### What Is a "Protected Computer"?

Under CFAA, virtually every computer connected to the internet is a "protected computer":
- Computers used in interstate or foreign commerce
- Computers used by financial institutions
- Computers used by the US government
- Any computer connected to the internet (per court interpretations)

**In practice: Every computer you might want to test is protected by CFAA.**

#### What Is "Authorization"?

This is where penetration testers must be extremely careful.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authorization Spectrum                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CLEARLY AUTHORIZED                                             │
│  ├── Written contract specifying systems, dates, methods       │
│  ├── Signed by person with authority over those systems        │
│  ├── Clear scope boundaries                                     │
│  └── Legal review completed                                     │
│                                                                  │
│  GRAY AREA (DANGEROUS)                                          │
│  ├── Verbal permission ("sure, go ahead")                       │
│  ├── Implied permission ("they probably wouldn't mind")         │
│  ├── Bug bounty programs (read terms VERY carefully)            │
│  ├── Assuming authorization from one person covers all systems  │
│  └── "Authorized user" extending testing beyond granted access  │
│                                                                  │
│  CLEARLY UNAUTHORIZED                                           │
│  ├── No permission sought or given                              │
│  ├── Permission denied but testing anyway                       │
│  ├── Testing systems outside agreed scope                       │
│  └── Continuing after authorization expires                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Case Studies: When "Helpful" Became Criminal

**Case 1: The "Helpful" Security Researcher**
A researcher discovered a vulnerability in a company's website while browsing. Without authorization, they:
- Verified the vulnerability was real (unauthorized access)
- Downloaded sample data to prove the issue (obtaining information)
- Reported it to the company

Result: Criminal charges under CFAA. The "helpful" intent didn't matter legally.

**Case 2: The Enthusiastic Intern**
An IT intern, wanting to impress their employer:
- Ran a vulnerability scanner against company systems
- Found several vulnerabilities
- Reported them to their manager

Result: Terminated and investigated. Even as an employee, they exceeded their authorized access.

**Case 3: The Bug Bounty Misunderstanding**
A researcher found a bug bounty program for a company's main website. They:
- Tested the main website (authorized)
- Found a link to a subsidiary's system
- Tested the subsidiary (NOT in scope)

Result: Threatened with legal action. The subsidiary was not covered by the bounty program.

**Key Lesson:** Authorization must be explicit, in writing, and carefully scoped.

### International Legal Considerations

If you test systems in other jurisdictions, additional laws apply:

| Country | Law | Key Points |
|---------|-----|------------|
| **UK** | Computer Misuse Act 1990 | Similar to CFAA; unauthorized access is criminal |
| **EU** | Directive 2013/40/EU | Harmonized cyber crime laws across EU |
| **Germany** | § 202c StGB | Even possessing "hacker tools" with intent can be illegal |
| **Australia** | Criminal Code Act 1995 | Unauthorized access, impairment, data theft |
| **Canada** | Criminal Code § 342.1 | Unauthorized use of computer systems |

**Important:** Many countries have stricter laws than the US. Research before testing.

### Bug Bounty Programs - A Special Case

Bug bounty programs are NOT blanket authorization to test anything.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Bug Bounty Reality Check                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WHAT BOUNTY PROGRAMS TYPICALLY AUTHORIZE:                      │
│  ├── Specific domains listed in scope                           │
│  ├── Specific vulnerability types                               │
│  ├── Specific testing methods                                   │
│  └── Testing by individual (not team/organization)             │
│                                                                  │
│  WHAT BOUNTY PROGRAMS TYPICALLY PROHIBIT:                       │
│  ├── Social engineering                                         │
│  ├── Physical security testing                                  │
│  ├── DoS attacks                                                │
│  ├── Testing non-production systems                             │
│  ├── Accessing customer/user data                               │
│  ├── Third-party systems (even if integrated)                   │
│  ├── Automated scanning (in some programs)                      │
│  └── Public disclosure before fix                               │
│                                                                  │
│  BEFORE TESTING: Read the ENTIRE program policy                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Hands-On Exercise 1.1: Legal Research

Create a file: `~/security-lab/notes/stage01/legal_research.md`

Research and document:

1. **Your State/Province Laws**
   - What computer crime laws exist in your jurisdiction?
   - What are the penalties for unauthorized access?
   
2. **CFAA Key Provisions**
   - Summarize the main provisions in your own words
   - What constitutes "exceeding authorized access"?
   
3. **Recent CFAA Cases**
   - Find one recent CFAA prosecution
   - Summarize what happened and the outcome

**Template:**
```markdown
# Legal Research - Stage 01

## My Jurisdiction: [State/Country]

### Local Computer Crime Laws
[Research and document]

### CFAA Summary
[Your understanding in your own words]

### Case Study
[Recent case you researched]

### Key Takeaways
[What this means for your practice]
```

---

### Milestone 1 Checkpoint

Before proceeding, verify:

- [ ] You understand CFAA and its provisions
- [ ] You can distinguish authorized from unauthorized testing
- [ ] You know the potential consequences of unauthorized access
- [ ] You've completed Exercise 1.1
- [ ] You understand bug bounty limitations

---

## Part 2 — Types of Penetration Testing (Milestone 2)

### Understanding Engagement Types

Not all penetration tests are the same. Different engagements have different goals, scopes, and approaches.

### By Information Provided

```
┌─────────────────────────────────────────────────────────────────┐
│              Penetration Test Types by Knowledge                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  BLACK BOX (Zero Knowledge)                                     │
│  ├── Tester knows: Nothing or minimal (company name only)      │
│  ├── Simulates: External attacker with no inside knowledge     │
│  ├── Advantages:                                                │
│  │   • Most realistic attack simulation                         │
│  │   • Tests external security controls                         │
│  │   • No assumptions based on documentation                    │
│  ├── Disadvantages:                                             │
│  │   • More time required for reconnaissance                    │
│  │   • May miss internal vulnerabilities                        │
│  │   • Less comprehensive coverage                              │
│  └── When used: External pentests, red team engagements        │
│                                                                  │
│  WHITE BOX (Full Knowledge)                                     │
│  ├── Tester knows: Everything (code, diagrams, credentials)    │
│  ├── Simulates: Insider threat or code review                  │
│  ├── Advantages:                                                │
│  │   • Maximum coverage                                         │
│  │   • Efficient use of time                                   │
│  │   • Can find deeper vulnerabilities                          │
│  ├── Disadvantages:                                             │
│  │   • Less realistic attacker simulation                       │
│  │   • May skip reconnaissance phase learning                   │
│  └── When used: Source code review, internal audits            │
│                                                                  │
│  GRAY BOX (Partial Knowledge)                                   │
│  ├── Tester knows: Some information (credentials, IP ranges)   │
│  ├── Simulates: Insider with limited access, or compromised    │
│  │              credentials scenario                            │
│  ├── Advantages:                                                │
│  │   • Balance of realism and efficiency                        │
│  │   • Tests insider threat scenarios                           │
│  │   • More comprehensive than black box                        │
│  ├── Disadvantages:                                             │
│  │   • Less realistic than black box                            │
│  │   • Less thorough than white box                             │
│  └── When used: Most common for internal testing               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### By Target Type

#### Network Penetration Testing
- Tests network infrastructure
- Includes routers, switches, firewalls, servers
- Identifies misconfigurations, unpatched services
- Examples: Scanning for open ports, exploiting SMB vulnerabilities

#### Web Application Penetration Testing
- Tests web applications specifically
- Follows OWASP methodology
- Includes authentication, authorization, input validation
- Examples: SQL injection, XSS, CSRF testing

#### Wireless Penetration Testing
- Tests wireless networks and security
- Includes encryption, access points, rogue devices
- Examples: WPA2 cracking, evil twin attacks

#### Social Engineering Testing
- Tests human security awareness
- Includes phishing, pretexting, physical access
- Examples: Phishing campaigns, USB drops

#### Physical Penetration Testing
- Tests physical security controls
- Includes locks, cameras, access controls
- Examples: Tailgating, lock picking, dumpster diving

#### Mobile Application Testing
- Tests mobile apps (iOS, Android)
- Includes data storage, communication, authentication
- Examples: Reverse engineering apps, API testing

### By Perspective

#### External Testing
- Tests from outside the network perimeter
- Simulates internet-based attacker
- Focuses on public-facing systems
- Goal: Can an outsider get in?

#### Internal Testing
- Tests from inside the network
- Simulates compromised employee or insider threat
- Focuses on lateral movement and privilege escalation
- Goal: How far can an insider get?

### Red Team vs. Penetration Test

```
┌─────────────────────────────────────────────────────────────────┐
│             Red Team vs. Penetration Test                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PENETRATION TEST                                               │
│  ├── Duration: Days to weeks                                    │
│  ├── Scope: Defined systems/applications                        │
│  ├── Goal: Find as many vulnerabilities as possible             │
│  ├── Approach: Systematic, comprehensive                        │
│  ├── Detection: Defenders may be aware                          │
│  └── Output: Vulnerability list with recommendations            │
│                                                                  │
│  RED TEAM ENGAGEMENT                                            │
│  ├── Duration: Weeks to months                                  │
│  ├── Scope: Objective-based (get to X data)                    │
│  ├── Goal: Achieve specific objective like a real attacker     │
│  ├── Approach: Realistic, use any means necessary              │
│  ├── Detection: Defenders unaware (tests detection)            │
│  └── Output: Narrative of attack path + detection gaps          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Vulnerability Assessment vs. Penetration Test

| Aspect | Vulnerability Assessment | Penetration Test |
|--------|-------------------------|------------------|
| **Goal** | Identify vulnerabilities | Exploit vulnerabilities |
| **Depth** | Wide and shallow | Deep and focused |
| **Tools** | Primarily automated scanners | Manual + automated |
| **Exploitation** | None (just identification) | Active exploitation |
| **Risk** | Very low | Moderate (controlled) |
| **Output** | List of potential vulnerabilities | Proof of exploitation |
| **Frequency** | Continuous/regular | Periodic (quarterly/annual) |

### Hands-On Exercise 1.2: Engagement Classification

Create a file: `~/security-lab/notes/stage01/engagement_types.md`

For each scenario, classify the engagement type:

1. A bank hires you to test their online banking application. They give you test credentials and API documentation.

2. A company wants to see if an external attacker could breach their network. They give you only their company name.

3. A hospital hires you to find vulnerabilities in their network. They give you the IP ranges and network diagrams.

4. A company's CISO wants to test if their security team can detect an intrusion. They want you to try to access the CEO's email without being caught.

5. A mobile app company wants you to review their iOS app before launch. They give you the source code.

**Template:**
```markdown
# Engagement Classification Exercise

## Scenario 1: Bank Online Banking
- Knowledge Level: [Black/White/Gray]
- Target Type: [Network/Web/Wireless/etc.]
- Perspective: [Internal/External]
- Engagement Type: [Pentest/Red Team/Vuln Assessment]
- Justification: [Why you classified it this way]

[Repeat for each scenario]
```

---

### Milestone 2 Checkpoint

Before proceeding, verify:

- [ ] You can distinguish black/white/gray box testing
- [ ] You understand different target types
- [ ] You know the difference between red team and pentest
- [ ] You can differentiate vulnerability assessment from pentest
- [ ] You've completed Exercise 1.2

---

## Part 3 — Authorization and Scoping (Milestone 3)

### The Authorization Document

Authorization is the legal foundation of every engagement. It must be:
- **Written** (not verbal)
- **Signed** by someone with authority
- **Specific** about what is authorized
- **Time-bound** (clear start and end dates)

### Key Components of Authorization

```
┌─────────────────────────────────────────────────────────────────┐
│                    Authorization Components                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. PARTIES IDENTIFIED                                          │
│     • Client organization (full legal name)                     │
│     • Testing organization/individual                           │
│     • Key contacts on both sides                                │
│                                                                  │
│  2. SCOPE DEFINITION                                            │
│     • In-scope systems (IPs, domains, applications)             │
│     • Out-of-scope systems (explicitly listed)                  │
│     • Third-party systems (cloud, shared hosting)               │
│     • Physical locations (if applicable)                        │
│                                                                  │
│  3. TESTING WINDOW                                              │
│     • Start date and time                                       │
│     • End date and time                                         │
│     • Testing hours (business hours only? 24/7?)                │
│     • Blackout periods (quarterly close, holidays)              │
│                                                                  │
│  4. RULES OF ENGAGEMENT                                         │
│     • Permitted testing methods                                 │
│     • Prohibited actions                                        │
│     • Social engineering allowed?                               │
│     • DoS testing allowed?                                      │
│     • Physical testing allowed?                                 │
│                                                                  │
│  5. COMMUNICATION                                               │
│     • Emergency contacts (24/7)                                 │
│     • Notification requirements                                 │
│     • Status update frequency                                   │
│     • Critical finding notification                             │
│                                                                  │
│  6. LEGAL                                                       │
│     • Authorization statement                                   │
│     • Liability limitations                                     │
│     • Confidentiality requirements                              │
│     • Data handling requirements                                │
│                                                                  │
│  7. SIGNATURES                                                  │
│     • Client signature (authorized person)                      │
│     • Tester signature                                          │
│     • Date                                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Understanding Scope

Scope defines what you CAN and CANNOT test. Getting scope wrong is one of the most common causes of legal problems.

#### In-Scope Assets

Must be explicitly listed:
- IP addresses and ranges (e.g., 192.168.1.0/24)
- Domain names (e.g., example.com, *.example.com)
- Specific applications (e.g., "the web application at app.example.com")
- Physical locations (if applicable)

#### Out-of-Scope Assets

Must be explicitly listed (even if obvious):
- Production databases (if testing on staging only)
- Third-party services
- Partner/vendor systems
- Specific IP ranges
- Specific applications

#### Third-Party Considerations

```
┌─────────────────────────────────────────────────────────────────┐
│                Third-Party System Considerations                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  REQUIRES ADDITIONAL AUTHORIZATION:                             │
│                                                                  │
│  Cloud Providers                                                │
│  ├── AWS: Has penetration testing policy                       │
│  ├── Azure: Has penetration testing policy                     │
│  ├── GCP: Has penetration testing policy                       │
│  └── Others: CHECK THEIR POLICIES                               │
│                                                                  │
│  Shared Hosting                                                 │
│  ├── Testing might affect other customers                      │
│  └── Usually prohibited without host authorization             │
│                                                                  │
│  SaaS Applications                                              │
│  ├── Client uses Salesforce, Office 365, etc.                  │
│  └── Testing the SaaS itself is NOT authorized by client       │
│                                                                  │
│  Payment Processors                                             │
│  ├── PCI-DSS has specific testing requirements                 │
│  └── May need QSA involvement                                  │
│                                                                  │
│  RULE: If you don't own it, you need permission from owner     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Rules of Engagement

The Rules of Engagement (ROE) define HOW you can test.

#### Common Permitted Actions
- Port scanning
- Vulnerability scanning
- Manual exploitation of discovered vulnerabilities
- Password attacks against in-scope systems
- Web application testing

#### Common Prohibited Actions
- Denial of Service attacks
- Physical damage to equipment
- Attacking production databases
- Exfiltrating real customer data
- Social engineering (unless specifically authorized)
- Attacking systems outside the scope
- Testing after the engagement end date

#### Emergency Procedures

Every engagement should have:
- Emergency contact (available 24/7)
- Procedure for system crashes
- Procedure for accidental data access
- Procedure for finding active attackers
- "Stop" authority (who can halt testing)

### Hands-On Exercise 1.3: Create an ROE Template

Create a file: `~/security-lab/templates/rules_of_engagement.md`

Create a comprehensive Rules of Engagement template you can adapt for future (practice) engagements:

```markdown
# Rules of Engagement Template
## [Client Name] Penetration Test

### Document Control
- Version: 1.0
- Date Created: [DATE]
- Last Modified: [DATE]

---

## 1. Parties

### Client
- Organization: [LEGAL NAME]
- Authorizing Contact: [NAME, TITLE]
- Email: [EMAIL]
- Phone: [PHONE]

### Tester
- Name/Organization: [NAME]
- Contact: [EMAIL]
- Phone: [PHONE]

---

## 2. Scope

### In-Scope Assets
| Asset Type | Details | Notes |
|-----------|---------|-------|
| IP Ranges | | |
| Domains | | |
| Applications | | |
| Physical | | |

### Out-of-Scope Assets
| Asset | Reason |
|-------|--------|
| | |

### Third-Party Systems
| System | Owner | Authorization Status |
|--------|-------|---------------------|
| | | |

---

## 3. Testing Window

- Start Date: [DATE]
- Start Time: [TIME + TIMEZONE]
- End Date: [DATE]
- End Time: [TIME + TIMEZONE]
- Testing Hours: [e.g., "Business hours only" or "24/7"]

### Blackout Periods
[List any times when testing is not permitted]

---

## 4. Permitted Testing Methods

- [ ] Network scanning
- [ ] Vulnerability scanning
- [ ] Web application testing
- [ ] Password attacks
- [ ] Manual exploitation
- [ ] Social engineering (specify type)
- [ ] Physical testing
- [ ] Wireless testing
- [ ] Other: [SPECIFY]

---

## 5. Prohibited Actions

- [ ] Denial of Service attacks
- [ ] Physical damage
- [ ] Data destruction
- [ ] Real data exfiltration
- [ ] Social engineering
- [ ] Other: [SPECIFY]

---

## 6. Communication

### Regular Updates
- Frequency: [e.g., "Daily email summary"]
- Format: [e.g., "Email to security@client.com"]

### Emergency Contact
- Name: [NAME]
- Phone: [24/7 NUMBER]
- Email: [EMAIL]

### Critical Finding Notification
[Define what constitutes "critical" and notification procedure]

---

## 7. Data Handling

- How test data will be stored:
- How long data will be retained:
- Data destruction procedure:
- Encryption requirements:

---

## 8. Authorization Statement

I, [AUTHORIZING PERSON], am authorized to permit the above-described testing 
on behalf of [CLIENT ORGANIZATION]. I authorize [TESTER] to perform security 
testing as described in this document from [START DATE] to [END DATE].

I understand that penetration testing may cause system disruptions and I accept 
this risk within the scope defined above.

Client Signature: _________________________ Date: __________

Printed Name: _________________________

Title: _________________________

---

Tester Acknowledgment:

I, [TESTER], agree to perform testing only within the scope defined above, 
following all rules of engagement and reporting all findings appropriately.

Tester Signature: _________________________ Date: __________

Printed Name: _________________________
```

---

### Milestone 3 Checkpoint

Before proceeding, verify:

- [ ] You understand all components of authorization
- [ ] You can define scope properly
- [ ] You understand third-party considerations
- [ ] You know what rules of engagement cover
- [ ] You've created your ROE template (Exercise 1.3)

---

## Part 4 — Penetration Testing Methodologies (Milestone 4)

### Why Use a Methodology?

A methodology provides:
- **Consistency** — Same approach every time
- **Completeness** — Don't miss important steps
- **Professionalism** — Industry-standard practice
- **Documentation** — Clear record of what was done
- **Repeatability** — Others can verify your work

### Major Penetration Testing Frameworks

#### PTES (Penetration Testing Execution Standard)

The most comprehensive open-source penetration testing framework.

```
┌─────────────────────────────────────────────────────────────────┐
│                    PTES Phases                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. PRE-ENGAGEMENT INTERACTIONS                                 │
│     ├── Scope definition                                        │
│     ├── Goals and objectives                                    │
│     ├── Rules of engagement                                     │
│     └── Authorization                                           │
│                                                                  │
│  2. INTELLIGENCE GATHERING                                      │
│     ├── OSINT (Open Source Intelligence)                       │
│     ├── Footprinting                                           │
│     ├── Target identification                                   │
│     └── Asset discovery                                         │
│                                                                  │
│  3. THREAT MODELING                                             │
│     ├── Identify valuable assets                               │
│     ├── Identify threat agents                                  │
│     ├── Document attack scenarios                               │
│     └── Prioritize testing efforts                              │
│                                                                  │
│  4. VULNERABILITY ANALYSIS                                      │
│     ├── Active scanning                                        │
│     ├── Passive scanning                                        │
│     ├── Validation                                              │
│     └── Research                                                │
│                                                                  │
│  5. EXPLOITATION                                                │
│     ├── Precision strikes                                      │
│     ├── Custom exploitation                                     │
│     ├── Avoid detection                                        │
│     └── Document everything                                     │
│                                                                  │
│  6. POST-EXPLOITATION                                          │
│     ├── Infrastructure analysis                                │
│     ├── Pillaging (data gathering)                             │
│     ├── High-value target identification                       │
│     └── Persistence                                            │
│                                                                  │
│  7. REPORTING                                                   │
│     ├── Executive summary                                       │
│     ├── Technical findings                                      │
│     ├── Risk ratings                                           │
│     └── Remediation recommendations                            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### OWASP Testing Guide

Focused specifically on web application testing.

**Key Categories:**
1. Information Gathering
2. Configuration and Deployment Management Testing
3. Identity Management Testing
4. Authentication Testing
5. Authorization Testing
6. Session Management Testing
7. Input Validation Testing
8. Error Handling Testing
9. Cryptography Testing
10. Business Logic Testing
11. Client-Side Testing

#### NIST SP 800-115

Technical Guide to Information Security Testing and Assessment.

**Phases:**
1. Planning
2. Discovery
3. Attack
4. Reporting

#### OSSTMM (Open Source Security Testing Methodology Manual)

Scientific approach to security testing.

**Focuses on:**
- Operational security
- Human security
- Physical security
- Wireless security
- Telecommunications security
- Data networks security

### The EC-Council CEH Methodology

Since this course aligns with CEH objectives, understand their five-phase approach:

```
┌─────────────────────────────────────────────────────────────────┐
│                    CEH Hacking Phases                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PHASE 1: RECONNAISSANCE                                        │
│  ├── Passive: No direct interaction                            │
│  │   • WHOIS, DNS, search engines, social media               │
│  └── Active: Direct interaction with target                    │
│      • Scanning, banner grabbing, social engineering           │
│                                                                  │
│  PHASE 2: SCANNING                                              │
│  ├── Network scanning: Live hosts, topology                    │
│  ├── Port scanning: Open ports, services                       │
│  └── Vulnerability scanning: Known weaknesses                  │
│                                                                  │
│  PHASE 3: GAINING ACCESS                                        │
│  ├── Exploitation of vulnerabilities                           │
│  ├── Password attacks                                          │
│  └── Social engineering                                        │
│                                                                  │
│  PHASE 4: MAINTAINING ACCESS                                    │
│  ├── Escalating privileges                                     │
│  ├── Installing backdoors                                      │
│  └── Creating persistent access                                │
│                                                                  │
│  PHASE 5: COVERING TRACKS                                       │
│  ├── Clearing logs                                             │
│  ├── Hiding files                                              │
│  └── (For ethical hackers: Document and report instead)        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Important Note:** As ethical hackers, we do NOT actually cover our tracks. We document everything for the client. Phase 5 exists in the CEH framework because real attackers do this, and understanding it helps defense.

### Building Your Personal Methodology

Every penetration tester develops their own workflow based on industry frameworks.

**Create a file:** `~/security-lab/templates/my_methodology.md`

```markdown
# Personal Penetration Testing Methodology
## Based on PTES and CEH Frameworks

---

## Phase 1: Pre-Engagement
- [ ] Scope defined and documented
- [ ] Rules of engagement signed
- [ ] Emergency contacts confirmed
- [ ] Testing window confirmed
- [ ] Out-of-scope assets clearly listed
- [ ] Required tools prepared

### My Pre-Engagement Checklist
[Add personal items as you learn]

---

## Phase 2: Reconnaissance

### Passive Reconnaissance
- [ ] WHOIS lookup
- [ ] DNS enumeration
- [ ] Search engine dorking
- [ ] Social media review
- [ ] Job posting analysis
- [ ] Public document search
- [ ] Archive searches (Wayback Machine)

### Active Reconnaissance
- [ ] DNS zone transfer attempts
- [ ] Network mapping
- [ ] Technology fingerprinting

### Tools I Use
[List as you learn them]

---

## Phase 3: Scanning and Enumeration

### Host Discovery
- [ ] Ping sweeps
- [ ] ARP scanning (internal)
- [ ] ICMP discovery

### Port Scanning
- [ ] Full TCP scan
- [ ] UDP scan (top ports)
- [ ] Service version detection

### Vulnerability Scanning
- [ ] Network vulnerability scan
- [ ] Web vulnerability scan
- [ ] Manual verification

### Tools I Use
[List as you learn them]

---

## Phase 4: Vulnerability Analysis

- [ ] Review scan results
- [ ] Research CVEs
- [ ] Prioritize by severity
- [ ] Validate findings (eliminate false positives)
- [ ] Document evidence

---

## Phase 5: Exploitation

- [ ] Select appropriate exploits
- [ ] Configure payloads
- [ ] Document each attempt
- [ ] Capture evidence of access
- [ ] Avoid causing damage

### Tools I Use
[List as you learn them]

---

## Phase 6: Post-Exploitation

- [ ] Determine access level
- [ ] Attempt privilege escalation
- [ ] Identify additional targets
- [ ] Document sensitive data found
- [ ] Demonstrate impact

---

## Phase 7: Reporting

- [ ] Compile all evidence
- [ ] Write technical findings
- [ ] Assign risk ratings
- [ ] Write executive summary
- [ ] Provide remediation recommendations
- [ ] Review and proofread

---

## Notes and Lessons Learned
[Add as you progress through the course]
```

---

### Milestone 4 Checkpoint

Before proceeding, verify:

- [ ] You know the PTES phases
- [ ] You understand OWASP Testing Guide purpose
- [ ] You can describe the CEH five phases
- [ ] You've created your personal methodology template
- [ ] You understand why methodology matters

---

## Part 5 — Documentation Standards (Milestone 5)

### Why Documentation Matters

```
┌─────────────────────────────────────────────────────────────────┐
│                Why Documentation Is Essential                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  FOR THE CLIENT                                                 │
│  ├── They pay for findings, not for you having fun             │
│  ├── They need evidence to justify remediation                 │
│  ├── They need to reproduce issues for fixing                  │
│  └── They need to verify fixes worked                          │
│                                                                  │
│  FOR YOU                                                        │
│  ├── Proves you stayed within scope                            │
│  ├── Protects you legally                                      │
│  ├── Enables report writing                                    │
│  ├── Helps you learn from each engagement                      │
│  └── Builds your professional reputation                       │
│                                                                  │
│  FOR THE PROFESSION                                             │
│  ├── Enables knowledge sharing                                 │
│  ├── Establishes professional standards                        │
│  └── Supports reproducible security research                   │
│                                                                  │
│  UNDOCUMENTED WORK IS WORTHLESS                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### What to Document

#### Every Command
Record every command you run:
- What the command was
- Why you ran it
- What the output was
- What it means
- Timestamp

#### Every Finding
For each vulnerability:
- Description
- Location (IP, URL, port)
- Severity rating
- Evidence (screenshots, output)
- Steps to reproduce
- Remediation recommendation

#### Every Access
When you gain access:
- How you gained access
- What credentials/method
- What access level
- What you could access/see
- Impact/significance

### Documentation Tools

#### Terminal Logging

**script command (Linux):**
```bash
# Start logging everything
script -a ~/security-lab/evidence/engagement_log_$(date +%Y%m%d).txt

# ... do your testing ...

# Stop logging
exit
```

**tmux logging:**
```bash
# In tmux, press: Ctrl+B then :
# Type: pipe-pane -o 'cat >> ~/log.txt'
```

#### Screenshot Evidence

Always screenshot:
- Proof of access
- Sensitive data discovered
- Successful exploits
- Configuration issues
- Error messages revealing information

**Tools:**
- `scrot` (Linux command line)
- `gnome-screenshot`
- Kali's built-in screenshot tool
- Flameshot

#### Note-Taking Systems

**Recommended Tools:**
- CherryTree (tree-structured notes, good for pentests)
- Obsidian (Markdown-based, linked notes)
- Joplin (encrypted notes)
- Simple Markdown files in organized directories

### Hands-On Exercise 1.4: Create Documentation Structure

Set up your documentation system:

```bash
# Create comprehensive documentation structure
mkdir -p ~/security-lab/evidence/{screenshots,logs,scans}
mkdir -p ~/security-lab/reports/{templates,final}
mkdir -p ~/security-lab/notes/stage01

# Create a command logging script
cat << 'EOF' > ~/security-lab/scripts/start_logging.sh
#!/bin/bash
# Start terminal logging for penetration testing

LOGDIR="$HOME/security-lab/evidence/logs"
LOGFILE="${LOGDIR}/session_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$LOGDIR"

echo "[*] Starting session logging to: $LOGFILE"
echo "=== Session started: $(date) ===" >> "$LOGFILE"
echo "[*] Type 'exit' to stop logging"

script -a "$LOGFILE"
EOF

chmod +x ~/security-lab/scripts/start_logging.sh

# Create a finding template
cat << 'EOF' > ~/security-lab/reports/templates/finding_template.md
# Finding: [TITLE]

## Summary
[One sentence description]

## Severity
[Critical/High/Medium/Low/Informational]

## Location
- IP/Host: 
- Port/Service:
- URL (if applicable):

## Description
[Detailed description of the vulnerability]

## Evidence
[Screenshots, command output, proof of concept]

## Steps to Reproduce
1. 
2. 
3. 

## Impact
[What an attacker could do with this vulnerability]

## Remediation
[How to fix it]

## References
[CVEs, CWEs, external documentation]
EOF

echo "Documentation structure created!"
ls -la ~/security-lab/
```

---

### Milestone 5 Checkpoint

Before proceeding, verify:

- [ ] You understand why documentation matters
- [ ] You know what to document
- [ ] You've set up your documentation structure
- [ ] You've created the logging script
- [ ] You have the finding template ready

---

## Part 6 — Ethics and Professional Conduct (Milestone 6)

### The Ethical Foundation

Penetration testing is one of the few professions where you're authorized to do things that would otherwise be crimes. This comes with profound responsibility.

### Core Ethical Principles

```
┌─────────────────────────────────────────────────────────────────┐
│              Ethical Principles for Penetration Testers          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. AUTHORIZATION IS SACRED                                     │
│     Never test without explicit, written authorization          │
│     Never exceed your authorized scope                          │
│     Stop immediately if authorization is revoked                │
│                                                                  │
│  2. DO NO UNNECESSARY HARM                                      │
│     Avoid disrupting production systems                         │
│     Don't access/copy real sensitive data                       │
│     Report critical vulnerabilities immediately                 │
│     Clean up after testing                                      │
│                                                                  │
│  3. MAINTAIN CONFIDENTIALITY                                    │
│     Client data is confidential                                 │
│     Findings are confidential                                   │
│     Don't discuss engagements publicly                          │
│     Secure your own systems                                     │
│                                                                  │
│  4. BE HONEST AND TRANSPARENT                                   │
│     Accurately represent your skills                            │
│     Don't exaggerate findings                                   │
│     Admit mistakes                                              │
│     Disclose conflicts of interest                              │
│                                                                  │
│  5. RESPECT THE PROFESSION                                      │
│     Follow industry standards                                   │
│     Contribute to the security community                        │
│     Mentor others ethically                                     │
│     Report violations                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Ethical Dilemmas in Practice

#### Scenario 1: Finding Criminal Activity

You're testing a company's network and discover evidence of fraud or illegal activity.

**What do you do?**
- Document the finding
- Report to your designated client contact
- Follow your contract terms
- **Do NOT investigate further** (not authorized)
- **Do NOT contact law enforcement directly** (that's the client's decision)
- Consult with your organization's legal counsel

#### Scenario 2: Finding Another Attacker

During testing, you discover evidence of an active breach by someone else.

**What do you do?**
- **STOP TESTING IMMEDIATELY**
- Contact the emergency contact
- Document what you found
- Preserve evidence
- Let incident responders take over

#### Scenario 3: Scope Creep

The client asks you to "just take a quick look" at a system that wasn't in scope.

**What do you do?**
- **REFUSE** until authorization is updated in writing
- Explain the legal and ethical reasons
- Offer to amend the scope document
- Don't be pressured by urgency

#### Scenario 4: Finding Sensitive Personal Data

You exploit a vulnerability and gain access to a database with sensitive personal information (SSNs, medical records, etc.).

**What do you do?**
- **STOP immediately** — don't browse further
- Screenshot minimal proof of access
- Document what type of data was accessible
- Report immediately as critical finding
- **NEVER extract real personal data**

### Professional Conduct

#### In Client Interactions

- Be professional and respectful
- Communicate clearly about risks
- Set realistic expectations
- Never mock or shame the client for vulnerabilities
- Remember: they're paying you to help, not to feel bad

#### In the Security Community

- Share knowledge appropriately
- Give credit where due
- Don't attack other researchers
- Report vulnerabilities responsibly
- Mentor newcomers

#### Online Presence

- Don't post about active engagements
- Be careful with details even of past work
- Your social media represents your professionalism
- Never brag about unauthorized access

### Hands-On Exercise 1.5: Ethical Decision-Making

Create a file: `~/security-lab/notes/stage01/ethical_scenarios.md`

For each scenario, write your analysis:

**Scenario A:** Your friend asks you to test their company's website to "help out." They're a mid-level employee.

**Scenario B:** You discover a vulnerability in a public website while browsing normally. You're not a customer or authorized tester.

**Scenario C:** During a pentest, you find the CEO's personal banking credentials saved in a browser on a work computer.

**Scenario D:** A colleague at your security firm suggests using client systems to mine cryptocurrency "just during off-hours testing."

**Template for each:**
```markdown
## Scenario [X]

### The Situation
[Summarize the dilemma]

### Key Ethical Considerations
[List the ethical principles at stake]

### Potential Actions
[List possible responses]

### My Decision
[What would you do and why]

### Consequences to Consider
[What could go wrong with different choices]
```

---

### Milestone 6 Checkpoint

Before proceeding, verify:

- [ ] You understand the core ethical principles
- [ ] You can navigate common ethical dilemmas
- [ ] You understand professional conduct expectations
- [ ] You've completed Exercise 1.5

---

## Part 7 — First Practice Engagement (Milestone 7)

Now it's time to apply what you've learned in a controlled practice engagement against Metasploitable.

### Engagement: Metasploitable 2 Assessment

**Client:** Yourself (practicing)
**Target:** Metasploitable 2 VM
**Type:** Gray Box (you know the IP, it's an intentionally vulnerable VM)
**Duration:** This exercise

### Step 1: Create Authorization Document

Even for practice, create proper documentation.

**Create:** `~/security-lab/evidence/engagement_001/authorization.md`

```markdown
# Practice Engagement Authorization
## Metasploitable 2 Assessment

### Engagement Identifier: PRACTICE-001

### Authorization Statement
I am the owner/operator of the Metasploitable 2 virtual machine and all 
host systems involved in this practice engagement. I authorize myself to 
conduct security testing as described below.

### Scope
- **In-Scope:** Metasploitable 2 VM at [IP ADDRESS]
- **Out-of-Scope:** 
  - Host operating system
  - Real network infrastructure
  - Internet-connected systems

### Testing Window
- Start: [DATE/TIME]
- End: [DATE/TIME]

### Permitted Activities
- Network scanning
- Port scanning
- Service enumeration
- Vulnerability scanning
- Banner grabbing

### Prohibited Activities
- Testing outside defined scope
- Attacking real networks
- Causing denial of service

### Emergency Contact
- N/A (practice lab)

Signature: [YOUR NAME]
Date: [DATE]
```

### Step 2: Start Documentation

```bash
# Create engagement directory
mkdir -p ~/security-lab/evidence/engagement_001/{scans,screenshots,findings}

# Start terminal logging
~/security-lab/scripts/start_logging.sh
```

### Step 3: Verify Connectivity

```bash
# Get Metasploitable IP (log into Metasploitable, run ifconfig)
# Or if DHCP, find it from Kali:

# Find your Kali IP on the host-only network
ip addr show

# Ping Metasploitable
ping -c 3 [METASPLOITABLE_IP]
```

### Step 4: Conduct Basic Reconnaissance

At this stage, you haven't learned the tools yet—that's fine. This exercise is about the process.

```bash
# Basic information gathering (commands you know)
# We'll learn more tools in later stages

# What's your IP?
ip addr show

# Can you reach the target?
ping -c 3 [TARGET_IP]

# Basic DNS lookup (if applicable)
host [TARGET_IP]

# What services does nmap see? (basic scan)
nmap [TARGET_IP]

# Save the results
nmap [TARGET_IP] > ~/security-lab/evidence/engagement_001/scans/initial_scan.txt
```

### Step 5: Document Your Findings

Even with basic commands, document what you learned:

**Create:** `~/security-lab/evidence/engagement_001/initial_findings.md`

```markdown
# Engagement PRACTICE-001
## Initial Findings

### Executive Summary
[1-2 sentences about what was discovered]

### Methodology
1. Verified network connectivity
2. Conducted basic port scan
3. Identified running services

### Findings

#### Finding 1: [Service on Port X]
- **Description:** [What you found]
- **Evidence:** [See scan output]
- **Initial Assessment:** [Your thoughts]

[Repeat for each notable finding]

### Next Steps
[What would you do next with more tools/knowledge]

### Notes
[Any observations, questions, issues]
```

### Step 6: End Session

```bash
# Exit the script logging
exit

# Review your log
less ~/security-lab/evidence/logs/session_*.log

# Take screenshot of your documentation directory
ls -la ~/security-lab/evidence/engagement_001/
```

---

### Milestone 7 Checkpoint

Before proceeding, verify:

- [ ] You created authorization documentation
- [ ] You started terminal logging
- [ ] You verified connectivity
- [ ] You ran basic reconnaissance
- [ ] You documented your findings
- [ ] You understand this process will repeat with more tools

---

## Stage 01 Assessment

### Written Assessment

Create: `~/security-lab/notes/stage01/assessment.md`

Answer these questions thoroughly:

1. What are the three main provisions of the CFAA and what do they prohibit?

2. Explain the difference between black box, white box, and gray box testing. Give a scenario where each would be most appropriate.

3. What elements MUST be included in a rules of engagement document? List at least seven.

4. Describe the five phases of the CEH methodology. What happens in each phase?

5. You're conducting a pentest and discover that someone else has already breached the client's network. What do you do?

6. Why is documentation essential in penetration testing? Give at least four reasons.

7. What is the difference between a vulnerability assessment and a penetration test?

8. You're testing a company and they ask you to "quickly check" their cloud-hosted email (Office 365). Should you do it? Why or why not?

9. Explain what scope is and why it's important. What are two things that should ALWAYS be out of scope?

10. What ethical principles should guide a penetration tester? List at least four.

### Practical Assessment

1. **Create a complete ROE document** for a fictional engagement:
   - Client: "TechCorp Industries"
   - Testing their external network 203.0.113.0/24
   - Two-week engagement
   - No social engineering permitted
   - Save to: `~/security-lab/reports/practice_roe.md`

2. **Document your Metasploitable assessment** from Part 7:
   - Ensure all sections are complete
   - Include proper evidence organization
   - Save to: `~/security-lab/evidence/engagement_001/final_report.md`

3. **Create a personal methodology guide** that includes:
   - All phases you'll follow
   - Tools you'll learn to use (leave placeholders)
   - Documentation requirements
   - Ethical reminders
   - Save to: `~/security-lab/templates/my_methodology.md`

---

## Stage 01 Completion Checklist

### Legal Understanding
- [ ] Understand CFAA provisions
- [ ] Know the consequences of unauthorized access
- [ ] Understand bug bounty limitations
- [ ] Completed legal research exercise

### Engagement Types
- [ ] Can classify black/white/gray box
- [ ] Know different target types (network, web, wireless, etc.)
- [ ] Understand red team vs. pentest difference
- [ ] Completed engagement classification exercise

### Authorization and Scoping
- [ ] Understand all ROE components
- [ ] Know how to define scope properly
- [ ] Understand third-party considerations
- [ ] Created ROE template

### Methodology
- [ ] Know PTES phases
- [ ] Know CEH methodology phases
- [ ] Understand OWASP purpose
- [ ] Created personal methodology template

### Documentation
- [ ] Set up documentation structure
- [ ] Created logging script
- [ ] Have finding template ready
- [ ] Understand what to document

### Ethics
- [ ] Understand core ethical principles
- [ ] Can navigate ethical dilemmas
- [ ] Completed ethical scenarios exercise

### Practice Engagement
- [ ] Created authorization document
- [ ] Conducted basic reconnaissance
- [ ] Documented findings properly

### Assessment
- [ ] Written assessment complete
- [ ] Practical assessment complete
- [ ] All files saved and organized

---

## Definition of Done

Stage 01 is complete when:

1. All checklist items above are checked
2. You can explain the legal framework confidently
3. You have created all required templates
4. You've completed your first documented (practice) engagement
5. All work is organized in `~/security-lab/`

---

## What's Next: Stage 02 Preview

In Stage 02 — Networking for Penetration Testers, you will learn:

- TCP/IP fundamentals from the ground up
- How data travels across networks
- Network protocols relevant to security testing
- Packet analysis basics with Wireshark
- Understanding what your tools are actually doing

**This is essential foundation.** You cannot effectively test networks you don't understand.

---

## Supplementary Resources

### Legal
- EFF: Know Your Rights (https://www.eff.org/)
- CFAA text (Cornell Law)
- Your jurisdiction's computer crime laws

### Methodology
- PTES: http://www.pentest-standard.org/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-115

### Practice
- OWASP WebGoat
- PortSwigger Web Security Academy
- TryHackMe (guided rooms)

---

**Commit your work and proceed to Stage 02 when ready:**

```bash
cd ~/security-lab
git init  # If not already initialized
git add .
git commit -m "Complete Stage 01 - Ethical Hacking Fundamentals"
```

---

**End of Stage 01 — Ethical Hacking Fundamentals**

You now have the legal, ethical, and methodological foundation that everything else builds upon. This is the most important stage—if you cut corners here, the rest means nothing.

**Proceed to Stage 02 when your checklist is complete.**
