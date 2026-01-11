# Stage 16: Social Engineering & Physical Security

## Overview

**Duration:** 25-30 hours  
**Difficulty:** Intermediate  
**Prerequisites:** Stage 1-10, Basic understanding of security concepts

This stage covers the human element of security - social engineering attacks that exploit psychology and trust, as well as physical security assessments. Understanding these attack vectors is crucial for comprehensive security testing and defense.

---

## Learning Objectives

By the end of this stage, you will be able to:

1. Understand psychological principles behind social engineering
2. Identify and execute various social engineering techniques
3. Create and conduct phishing campaigns (authorized)
4. Perform physical security assessments
5. Understand and test physical access controls
6. Develop security awareness training programs
7. Implement defenses against social engineering attacks

---

## Module 16.1: Social Engineering Fundamentals (4-5 hours)

### 16.1.1 Psychology of Social Engineering

```
SOCIAL ENGINEERING PRINCIPLES:
══════════════════════════════

Robert Cialdini's Principles of Influence:

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   1. RECIPROCITY                                                        │
│   ──────────────                                                        │
│   People feel obligated to return favors                                │
│   Example: "I helped you last week, now I need a small favor..."        │
│                                                                         │
│   2. COMMITMENT & CONSISTENCY                                           │
│   ───────────────────────────                                           │
│   People want to be consistent with past behavior                       │
│   Example: "You've always been helpful to IT before..."                 │
│                                                                         │
│   3. SOCIAL PROOF                                                       │
│   ──────────────                                                        │
│   People follow what others do                                          │
│   Example: "Everyone else in your department has already done this..."  │
│                                                                         │
│   4. AUTHORITY                                                          │
│   ──────────                                                            │
│   People comply with authority figures                                  │
│   Example: "This is John from the CEO's office..."                      │
│                                                                         │
│   5. LIKING                                                             │
│   ───────                                                               │
│   People comply with those they like                                    │
│   Example: Building rapport before making request                       │
│                                                                         │
│   6. SCARCITY                                                           │
│   ─────────                                                             │
│   People value things that are rare or limited                          │
│   Example: "This offer expires in 24 hours..."                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

ADDITIONAL MANIPULATION TECHNIQUES:
───────────────────────────────────

• URGENCY: Creating time pressure to prevent careful thinking
• FEAR: Threatening negative consequences
• TRUST: Exploiting established relationships or positions
• CURIOSITY: Leveraging natural human curiosity
• GREED: Offering too-good-to-be-true rewards
• HELPFULNESS: Exploiting desire to be helpful
```

### 16.1.2 Social Engineering Attack Cycle

```
SOCIAL ENGINEERING ATTACK CYCLE:
════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│      ┌───────────────┐                                                  │
│      │ 1. RESEARCH   │                                                  │
│      │   (OSINT)     │                                                  │
│      └───────┬───────┘                                                  │
│              │                                                          │
│              ▼                                                          │
│      ┌───────────────┐                                                  │
│      │ 2. TARGET     │    • Identify targets                            │
│      │  SELECTION    │    • Gather information                          │
│      └───────┬───────┘    • Find vulnerabilities                        │
│              │                                                          │
│              ▼                                                          │
│      ┌───────────────┐                                                  │
│      │ 3. DEVELOP    │    • Choose attack vector                        │
│      │   PRETEXT     │    • Create believable story                     │
│      └───────┬───────┘    • Prepare materials                           │
│              │                                                          │
│              ▼                                                          │
│      ┌───────────────┐                                                  │
│      │ 4. BUILD      │    • Establish communication                     │
│      │   RAPPORT     │    • Develop trust                               │
│      └───────┬───────┘    • Create relationship                         │
│              │                                                          │
│              ▼                                                          │
│      ┌───────────────┐                                                  │
│      │ 5. EXPLOIT    │    • Execute attack                              │
│      │   TRUST       │    • Obtain credentials/access                   │
│      └───────┬───────┘    • Plant malware                               │
│              │                                                          │
│              ▼                                                          │
│      ┌───────────────┐                                                  │
│      │ 6. EXIT       │    • Leave no evidence                           │
│      │               │    • Maintain access if needed                   │
│      └───────────────┘                                                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 16.1.3 Types of Social Engineering

```python
#!/usr/bin/env python3
"""
social_engineering_types.py - Overview of social engineering attack types
"""

SE_ATTACK_TYPES = """
SOCIAL ENGINEERING ATTACK TYPES:
════════════════════════════════

ELECTRONIC/REMOTE ATTACKS:
──────────────────────────

1. PHISHING
   ─────────
   • Mass email campaigns
   • Fake login pages
   • Malicious attachments
   • Link manipulation
   
2. SPEAR PHISHING
   ───────────────
   • Targeted at specific individuals
   • Highly personalized content
   • Research-based approach
   • Higher success rate
   
3. WHALING
   ────────
   • Targets executives/VIPs
   • High-value targets
   • Sophisticated pretexts
   • Often financial fraud
   
4. VISHING (Voice Phishing)
   ─────────────────────────
   • Phone-based attacks
   • Impersonation
   • Tech support scams
   • IRS/government impersonation
   
5. SMISHING (SMS Phishing)
   ────────────────────────
   • Text message attacks
   • Malicious links
   • Verification scams
   • Package delivery scams
   
6. BUSINESS EMAIL COMPROMISE (BEC)
   ────────────────────────────────
   • Compromised/spoofed executive email
   • Wire transfer requests
   • Vendor impersonation
   • Invoice manipulation

IN-PERSON ATTACKS:
──────────────────

1. PRETEXTING
   ───────────
   • Creating false scenario
   • Impersonating someone
   • Gaining trust through story
   
2. TAILGATING/PIGGYBACKING
   ────────────────────────
   • Following authorized person
   • Exploiting politeness
   • Physical access bypass
   
3. BAITING
   ────────
   • Leaving infected USB drives
   • Offering free items
   • Exploiting curiosity
   
4. QUID PRO QUO
   ─────────────
   • Offering service for information
   • "IT support" calling
   • Exchange-based manipulation
   
5. DUMPSTER DIVING
   ────────────────
   • Searching through trash
   • Finding sensitive documents
   • Recovering discarded media
"""

print(SE_ATTACK_TYPES)
```

---

## Module 16.2: OSINT and Reconnaissance (4-5 hours)

### 16.2.1 Open Source Intelligence Gathering

```python
#!/usr/bin/env python3
"""
osint_techniques.py - OSINT gathering for social engineering
"""

OSINT_SOURCES = """
OSINT SOURCES FOR SOCIAL ENGINEERING:
═════════════════════════════════════

PERSONAL INFORMATION:
─────────────────────

Social Media:
• LinkedIn    - Job titles, connections, skills
• Facebook    - Personal life, friends, interests
• Twitter/X   - Opinions, activities, location
• Instagram   - Lifestyle, locations, relationships
• GitHub      - Technical skills, email addresses

Professional Sources:
• Company website - Org structure, key personnel
• Press releases  - Projects, partnerships
• SEC filings     - Executive information
• Conference talks - Technical details, photos
• Publications    - Research interests, affiliations

Public Records:
• WHOIS         - Domain ownership
• DNS records   - Infrastructure details
• Job postings  - Technologies used
• Court records - Legal issues
• Property records - Addresses

ORGANIZATIONAL INFORMATION:
──────────────────────────

Technical:
• Shodan       - Internet-connected devices
• Censys       - Certificate information
• SecurityTrails - Historical DNS
• BuiltWith    - Technology stack
• Archive.org  - Historical website data

Email:
• Hunter.io    - Email format discovery
• Phonebook.cz - Email addresses
• Have I Been Pwned - Breach data
• Email permutator - Generate possible emails

Documents:
• Google dorks - Exposed documents
• Pastebin     - Leaked data
• GitHub       - Code repositories
"""

GOOGLE_DORKS = """
GOOGLE DORKS FOR OSINT:
═══════════════════════

FINDING DOCUMENTS:
──────────────────
site:company.com filetype:pdf
site:company.com filetype:doc
site:company.com filetype:xls
site:company.com filetype:ppt

FINDING EMAILS:
───────────────
site:company.com "@company.com"
site:company.com email
"@company.com" filetype:pdf

FINDING EMPLOYEES:
──────────────────
site:linkedin.com "company name" "title"
site:linkedin.com/in "company name"

FINDING SENSITIVE INFO:
───────────────────────
site:company.com inurl:admin
site:company.com inurl:login
site:company.com "password"
site:company.com "confidential"

FINDING INFRASTRUCTURE:
───────────────────────
site:company.com inurl:vpn
site:company.com inurl:remote
site:company.com inurl:portal
"""

OSINT_TOOLS = """
OSINT TOOLS:
════════════

FRAMEWORKS:
───────────
• Maltego       - Visual link analysis
• SpiderFoot    - Automated OSINT
• Recon-ng      - Web reconnaissance
• theHarvester  - Email/domain gathering

SPECIALIZED:
────────────
• Sherlock      - Username search
• Holehe        - Email to account
• GHunt         - Google account info
• Maigret       - Username search
• social-analyzer - Profile analysis

PEOPLE SEARCH:
──────────────
• Pipl
• BeenVerified
• Spokeo
• WhitePages

METADATA:
─────────
• FOCA          - Document metadata
• ExifTool      - Image metadata
• Metagoofil    - Metadata extraction
"""

print(OSINT_SOURCES)
print(GOOGLE_DORKS)
print(OSINT_TOOLS)
```

### 16.2.2 Target Profiling

```python
#!/usr/bin/env python3
"""
target_profiling.py - Building target profiles for social engineering
"""

TARGET_PROFILE = """
TARGET PROFILE TEMPLATE:
════════════════════════

INDIVIDUAL PROFILE:
───────────────────

Personal Information:
┌─────────────────────────────────────┐
│ Name: ________________________      │
│ Title: _______________________      │
│ Department: __________________      │
│ Reports to: __________________      │
│ Email: ______________________       │
│ Phone: ______________________       │
│ Location: ___________________       │
└─────────────────────────────────────┘

Professional:
┌─────────────────────────────────────┐
│ Responsibilities: _______________   │
│ Projects: ______________________    │
│ Skills: ________________________    │
│ Conferences: ___________________    │
│ Publications: __________________    │
└─────────────────────────────────────┘

Social Media Presence:
┌─────────────────────────────────────┐
│ LinkedIn: ______________________    │
│ Twitter: _______________________    │
│ Facebook: ______________________    │
│ Other: _________________________    │
└─────────────────────────────────────┘

Personal Interests:
┌─────────────────────────────────────┐
│ Hobbies: _______________________    │
│ Sports: ________________________    │
│ Charities: _____________________    │
│ Groups: ________________________    │
└─────────────────────────────────────┘

Potential Attack Vectors:
┌─────────────────────────────────────┐
│ Work context: __________________    │
│ Personal interests: ____________    │
│ Known vendors: _________________    │
│ Recent events: _________________    │
└─────────────────────────────────────┘


ORGANIZATIONAL PROFILE:
───────────────────────

Company Information:
• Industry: ________________
• Size: ________________
• Locations: ________________
• Key executives: ________________

Technology:
• Email provider: ________________
• Web technologies: ________________
• Security products: ________________
• Cloud providers: ________________

Culture:
• Dress code: ________________
• Badge requirements: ________________
• Visitor procedures: ________________
• Security awareness: ________________
"""

print(TARGET_PROFILE)
```

---

## Module 16.3: Phishing Campaigns (5-6 hours)

### 16.3.1 Phishing Campaign Planning

```python
#!/usr/bin/env python3
"""
phishing_campaign.py - Planning and executing phishing campaigns
"""

PHISHING_PLANNING = """
PHISHING CAMPAIGN PLANNING:
═══════════════════════════

LEGAL REQUIREMENTS:
───────────────────
☐ Written authorization from client
☐ Defined scope (who can be targeted)
☐ Allowed techniques specified
☐ Reporting requirements
☐ Data handling procedures
☐ Emergency contact information

CAMPAIGN ELEMENTS:
──────────────────

1. PRETEXT SELECTION
   ──────────────────
   Common effective pretexts:
   • Password expiration
   • HR policy update
   • IT security alert
   • Shared document
   • Package delivery
   • Invoice/payment
   • Account verification
   • Training requirement
   
2. TIMING CONSIDERATIONS
   ──────────────────────
   • Business hours vs. after hours
   • Day of week (Tuesday-Thursday optimal)
   • Avoid holidays and events
   • Consider time zones
   
3. TARGET SELECTION
   ─────────────────
   • All employees
   • Specific departments
   • Executive staff
   • New employees
   • Contractors

4. METRICS TO TRACK
   ─────────────────
   • Emails sent
   • Emails opened
   • Links clicked
   • Credentials submitted
   • Attachments opened
   • Reports to security
"""

PHISHING_TOOLS = """
PHISHING TOOLS:
═══════════════

FRAMEWORKS:
───────────
• Gophish      - Open source phishing framework
• King Phisher - Phishing campaign toolkit
• Evilginx2    - Advanced phishing with 2FA bypass
• Modlishka    - Reverse proxy phishing

INFRASTRUCTURE:
───────────────
• Fresh domain (similar to target)
• SSL certificate (Let's Encrypt)
• Email server or service
• Landing page hosting

GOPHISH SETUP:
──────────────
# Download and run
./gophish

# Access admin panel
https://localhost:3333

# Default credentials
admin:gophish

# Configure:
1. Sending profile (SMTP)
2. Landing page (credential capture)
3. Email template
4. User groups
5. Campaign

EMAIL AUTHENTICATION:
─────────────────────
• SPF record setup
• DKIM signing
• Avoid spam triggers
• Warm up domain
"""

PHISHING_TEMPLATES = """
PHISHING EMAIL TEMPLATES:
═════════════════════════

TEMPLATE 1: PASSWORD EXPIRATION
───────────────────────────────
Subject: [Action Required] Password Expires in 24 Hours

Dear {{.FirstName}},

Your network password will expire in 24 hours. To avoid 
disruption to your work, please update your password now.

Click here to update your password:
{{.URL}}

If you do not update your password, you will be locked 
out of your account.

IT Support Team


TEMPLATE 2: SHARED DOCUMENT
───────────────────────────
Subject: {{.FirstName}} - Document Shared With You

Hi {{.FirstName}},

A document has been shared with you via OneDrive.

Document: Q4_Financial_Report.xlsx
Shared by: [Executive Name]

View Document: {{.URL}}

This link will expire in 48 hours.


TEMPLATE 3: SECURITY ALERT
──────────────────────────
Subject: Unusual Sign-in Activity Detected

We detected unusual sign-in activity on your account.

Date: [Current Date]
Location: [Foreign Country]
Device: Unknown

If this was you, you can ignore this message.

If this wasn't you, your account may be compromised:
{{.URL}}

Security Team
"""

print(PHISHING_PLANNING)
print(PHISHING_TOOLS)
print(PHISHING_TEMPLATES)
```

### 16.3.2 Landing Page Creation

```python
#!/usr/bin/env python3
"""
phishing_landing_page.py - Creating convincing landing pages
"""

LANDING_PAGE_TIPS = """
LANDING PAGE BEST PRACTICES:
════════════════════════════

VISUAL ELEMENTS:
────────────────
• Clone legitimate login page exactly
• Match fonts, colors, logos
• Include all form fields
• Add security indicators
• Mobile responsive

TECHNICAL ELEMENTS:
───────────────────
• Valid SSL certificate
• Similar domain name
• Fast loading
• Handle form submission
• Redirect after capture

CREDENTIAL CAPTURE:
───────────────────
# Basic PHP credential capture
<?php
$file = 'creds.txt';
$username = $_POST['username'];
$password = $_POST['password'];
$ip = $_SERVER['REMOTE_ADDR'];
$date = date('Y-m-d H:i:s');

$entry = "$date | $ip | $username | $password\\n";
file_put_contents($file, $entry, FILE_APPEND);

// Redirect to real site
header('Location: https://real-site.com/login?error=1');
?>

DOMAIN SELECTION:
─────────────────
Techniques:
• Typosquatting: gooogle.com
• Homograph: gооgle.com (Cyrillic 'o')
• Subdomain: login.company.attacker.com
• Similar: company-login.com
• TLD variation: company.co (vs .com)

EVASION TECHNIQUES:
───────────────────
• Bot detection
• Geofencing
• Time-based access
• Referrer checking
• User-agent filtering
"""

print(LANDING_PAGE_TIPS)
```

### 16.3.3 Reporting and Metrics

```python
#!/usr/bin/env python3
"""
phishing_reporting.py - Phishing campaign metrics and reporting
"""

PHISHING_METRICS = """
PHISHING CAMPAIGN METRICS:
══════════════════════════

KEY METRICS:
────────────
┌────────────────────────────────────────────────────────┐
│ Metric                 │ Calculation                   │
├────────────────────────┼───────────────────────────────┤
│ Delivery Rate          │ Delivered / Sent × 100%       │
│ Open Rate              │ Opened / Delivered × 100%     │
│ Click Rate             │ Clicked / Delivered × 100%    │
│ Submission Rate        │ Submitted / Delivered × 100%  │
│ Report Rate            │ Reported / Delivered × 100%   │
│ Time to Click          │ Average time to first click   │
│ Time to Report         │ Average time to first report  │
└────────────────────────┴───────────────────────────────┘

BENCHMARK COMPARISONS:
──────────────────────
Industry Average Click Rates:
• Technology: 15-20%
• Healthcare: 20-25%
• Finance: 12-18%
• Government: 18-22%
• Education: 25-30%

SUCCESS INDICATORS:
───────────────────
• Lower click rates than baseline
• Increased reporting rates
• Faster reporting times
• Improved after training
"""

REPORT_TEMPLATE = """
PHISHING ASSESSMENT REPORT TEMPLATE:
════════════════════════════════════

1. EXECUTIVE SUMMARY
   ──────────────────
   • Campaign overview
   • Key findings
   • Risk assessment
   • Recommendations

2. METHODOLOGY
   ────────────
   • Scope definition
   • Pretext used
   • Timeline
   • Tools utilized

3. RESULTS
   ────────
   • Total emails sent: ___
   • Delivery rate: ___%
   • Open rate: ___%
   • Click rate: ___%
   • Credential submission: ___%
   • Reports to security: ___%

4. ANALYSIS
   ─────────
   • Most vulnerable departments
   • Time-based patterns
   • Device breakdown
   • Comparison to baseline

5. RISK ASSESSMENT
   ────────────────
   • Impact of successful attack
   • Current controls effectiveness
   • Gap analysis

6. RECOMMENDATIONS
   ────────────────
   • Training programs
   • Technical controls
   • Policy updates
   • Follow-up testing

7. APPENDICES
   ───────────
   • Email templates used
   • Raw data
   • Screenshots
"""

print(PHISHING_METRICS)
print(REPORT_TEMPLATE)
```

---

## Module 16.4: Voice and In-Person Attacks (4-5 hours)

### 16.4.1 Vishing (Voice Phishing)

```python
#!/usr/bin/env python3
"""
vishing_techniques.py - Voice-based social engineering
"""

VISHING_GUIDE = """
VISHING TECHNIQUES:
═══════════════════

PREPARATION:
────────────
• Research target thoroughly
• Prepare scripts and talking points
• Have backup stories ready
• Practice voice/accent if needed
• Set up caller ID spoofing (if authorized)

COMMON PRETEXTS:
────────────────

1. IT SUPPORT
   ───────────
   "Hi, this is [Name] from IT support. We're seeing some 
   unusual activity on your account and need to verify 
   some information..."

2. HELP DESK
   ──────────
   "I'm calling because we received a ticket about your 
   computer. I need to verify your employee ID to pull 
   up your record..."

3. VENDOR/SUPPLIER
   ────────────────
   "This is [Name] from [Vendor]. We need to update our 
   records and verify the payment information for your 
   account..."

4. EXECUTIVE ASSISTANT
   ────────────────────
   "Hi, I'm calling from [CEO's] office. [He/She] needs 
   [information] urgently for a meeting..."

5. SURVEY/RESEARCH
   ────────────────
   "We're conducting a brief survey about employee 
   satisfaction. This will only take a few minutes..."

TECHNIQUES:
───────────
• Build rapport quickly
• Use names and details from research
• Create urgency without suspicion
• Offer to call back (establishes trust)
• Transfer to "colleague" (partner)
• Background noise for authenticity
"""

VISHING_SCRIPT = """
EXAMPLE VISHING SCRIPT (IT Support):
════════════════════════════════════

[OPENING]
"Hello, is this [Target Name]? Hi [First Name], this is 
[Your Name] calling from the IT security team. How are 
you today?"

[BUILD RAPPORT]
"Great! I hope I'm not catching you at a bad time. This 
should only take a minute."

[CREATE CONTEXT]
"I'm reaching out because our security systems flagged 
some unusual activity on your account this morning. It's 
probably nothing, but we need to verify a few things to 
make sure your account hasn't been compromised."

[GATHER INFORMATION]
"First, can you confirm your employee ID for me?"
"And just to verify, what department are you in?"
"What version of Windows are you running?"

[EXPLOIT]
"Okay, I can see the issue now. It looks like your 
password may have been exposed in a recent breach. 
I'll need to reset it on our end. What password would 
you like to use?"

[OR - Credential Verification]
"I need you to verify your current password so I can 
compare it against what's in our system."

[CLOSE]
"Perfect, I've updated everything on our end. You should 
be all set. Is there anything else I can help with today?"
"""

print(VISHING_GUIDE)
print(VISHING_SCRIPT)
```

### 16.4.2 In-Person Social Engineering

```python
#!/usr/bin/env python3
"""
in_person_se.py - In-person social engineering techniques
"""

IN_PERSON_ATTACKS = """
IN-PERSON SOCIAL ENGINEERING:
═════════════════════════════

TAILGATING/PIGGYBACKING:
────────────────────────

Techniques:
• Wait for authorized person at door
• Carry items (boxes, coffee) - hands full
• Dress appropriately for environment
• Act confident and natural
• Pretend to be on phone call
• Ask for help holding door

Scripts:
• "Could you hold the door? My badge is in my bag."
• "Thanks! I forgot my badge at my desk."
• [Just follow confidently, don't ask]

IMPERSONATION:
──────────────

Common Roles:
• IT support/technician
• Delivery person
• Maintenance worker
• Fire inspector
• Auditor
• New employee
• Contractor
• Vendor representative

Preparation:
• Appropriate clothing/uniform
• Fake badge/credentials
• Props (clipboard, tools, boxes)
• Business cards
• Knowledge of company/role

BADGE CLONING:
──────────────

Equipment:
• Proxmark3
• Long-range RFID reader
• Blank cards

Technique:
• Get close to target's badge
• Read card data
• Clone to blank card
• Test at off-hours entrance

PRETEXTING SCENARIOS:
─────────────────────

1. NEW EMPLOYEE
   "Hi, I'm [Name], I just started in [Department]. 
   I'm trying to find [Location]. Could you help?"

2. LOST VENDOR
   "I'm here from [Company] for a meeting with 
   [Executive]. Can you point me to their office?"

3. IT SUPPORT
   "We received a call about computer issues in 
   this area. I'm here to check on it."

4. DELIVERY
   "I have a delivery for [Name]. Can you sign 
   for it or show me where their office is?"
"""

PHYSICAL_ACCESS = """
GAINING PHYSICAL ACCESS:
════════════════════════

RECONNAISSANCE:
───────────────
• Observe entry/exit points
• Note security measures
• Identify busy vs. quiet times
• Watch badge procedures
• Note dress codes
• Identify smoking areas (social opportunity)

ENTRY TECHNIQUES:
─────────────────

1. Front Door (Confidence)
   • Walk in confidently
   • Look like you belong
   • Have a story ready

2. Employee Entrance
   • Tailgate during rush hour
   • Hands full technique
   
3. Loading Dock
   • Often less secured
   • Delivery pretext
   
4. Emergency Exits
   • May not alarm
   • Propped open for smokers
   
5. Parking Garage
   • Follow cars in
   • Less monitored

ONCE INSIDE:
────────────
• Move with purpose
• Don't linger or look lost
• Carry props (folder, laptop)
• Avoid eye contact with security
• Know exit routes
• Document everything
"""

print(IN_PERSON_ATTACKS)
print(PHYSICAL_ACCESS)
```

---

## Module 16.5: Physical Security Assessment (5-6 hours)

### 16.5.1 Physical Security Overview

```
PHYSICAL SECURITY COMPONENTS:
═════════════════════════════

PERIMETER SECURITY:
───────────────────
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   OUTER PERIMETER                                                       │
│   ────────────────                                                      │
│   • Fencing and barriers                                                │
│   • Vehicle barriers                                                    │
│   • Lighting                                                            │
│   • CCTV coverage                                                       │
│   • Security patrols                                                    │
│   • Signage                                                             │
│                                                                         │
│   BUILDING PERIMETER                                                    │
│   ───────────────────                                                   │
│   • Entry points (doors, windows)                                       │
│   • Access control systems                                              │
│   • Visitor management                                                  │
│   • Reception/security desk                                             │
│   • Loading docks                                                       │
│   • Emergency exits                                                     │
│                                                                         │
│   INTERIOR SECURITY                                                     │
│   ─────────────────                                                     │
│   • Access zones                                                        │
│   • Server room protection                                              │
│   • Sensitive area controls                                             │
│   • Clean desk policy                                                   │
│   • Document security                                                   │
│   • Device security                                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

ACCESS CONTROL TYPES:
─────────────────────

Something You HAVE:
• Key cards/badges
• Proximity cards (RFID)
• Smart cards
• Tokens
• Mobile credentials

Something You KNOW:
• PIN codes
• Passwords
• Lock combinations

Something You ARE:
• Fingerprint
• Facial recognition
• Iris scan
• Voice recognition

COMMON ACCESS CARD TECHNOLOGIES:
────────────────────────────────
• 125 kHz Proximity (HID, EM4100) - Easily cloned
• 13.56 MHz Smart Cards (MIFARE, iCLASS)
• NFC (Near Field Communication)
• Magnetic stripe
```

### 16.5.2 Physical Security Testing

```python
#!/usr/bin/env python3
"""
physical_testing.py - Physical security assessment guide
"""

PHYSICAL_TESTING = """
PHYSICAL SECURITY TESTING:
══════════════════════════

SCOPE DEFINITION:
─────────────────
☐ Facilities included
☐ Hours of testing
☐ Allowed techniques
☐ Restricted areas
☐ Emergency contacts
☐ "Get out of jail" letter
☐ Client badge/escort option

ASSESSMENT AREAS:
─────────────────

1. PERIMETER ASSESSMENT
   ─────────────────────
   • Fence integrity
   • Gate security
   • Lighting coverage
   • Camera placement
   • Blind spots
   • Landscaping issues

2. BUILDING ACCESS
   ────────────────
   • Door security (locks, closers)
   • Badge reader placement
   • Tailgating opportunities
   • Reception procedures
   • Visitor management
   • Emergency exit security

3. INTERIOR SECURITY
   ──────────────────
   • Server room access
   • Wiring closets
   • Sensitive areas
   • Clean desk compliance
   • Unlocked computers
   • Visible passwords

4. BADGE SECURITY
   ───────────────
   • Badge visibility requirements
   • Challenge culture
   • Visitor badge procedures
   • Badge cloning possibility

5. INFORMATION LEAKAGE
   ────────────────────
   • Dumpster diving opportunity
   • Visible screens
   • Whiteboards with info
   • Printed documents
   • Shipping labels
"""

TESTING_TECHNIQUES = """
PHYSICAL TESTING TECHNIQUES:
════════════════════════════

1. OBSERVATION
   ────────────
   • Perimeter walkthrough
   • Watch entry/exit patterns
   • Identify security gaps
   • Note camera coverage
   • Time security patrols

2. SOCIAL ENGINEERING
   ───────────────────
   • Tailgating attempts
   • Impersonation
   • Pretext calls
   • Fake deliveries

3. TECHNICAL TESTING
   ──────────────────
   • Badge cloning
   • Lock picking/bypassing
   • Sensor testing
   • Alarm testing

4. DUMPSTER DIVING
   ────────────────
   • Check for sensitive documents
   • Note disposal procedures
   • Photograph findings

5. NETWORK ACCESS
   ───────────────
   • Find open network ports
   • Unlocked network closets
   • Rogue device placement

EQUIPMENT:
──────────
• Camera (covert)
• Clipboard and props
• Lock picks (if authorized)
• Proxmark3 (badge cloning)
• USB Rubber Ducky
• Network implant device
• Appropriate clothing/uniforms
"""

print(PHYSICAL_TESTING)
print(TESTING_TECHNIQUES)
```

### 16.5.3 Lock Bypass Techniques

```python
#!/usr/bin/env python3
"""
lock_bypass.py - Physical lock bypass techniques (educational)
"""

LOCK_BYPASS = """
LOCK BYPASS TECHNIQUES:
═══════════════════════

NOTE: Only perform with proper authorization!

1. LOCK PICKING
   ─────────────
   Tools:
   • Tension wrench
   • Pick set (hooks, rakes, diamonds)
   • Practice locks
   
   Basic technique:
   • Insert tension wrench
   • Apply light rotational pressure
   • Insert pick
   • Manipulate pins
   • Turn lock when set

2. BUMP KEYS
   ──────────
   • Modified key with all cuts at maximum
   • Insert and "bump" while turning
   • Effective on pin tumbler locks
   
3. BYPASS TOOLS
   ─────────────
   • Under-door tools
   • Latch slipping (credit card)
   • Traveler hooks
   • Comb picks

4. ELECTRONIC LOCK BYPASS
   ───────────────────────
   • Default codes
   • Magnet attacks
   • Signal replay
   • Power manipulation

5. DESTRUCTIVE METHODS
   ────────────────────
   (Usually not authorized)
   • Drilling
   • Cutting
   • Force

COMMON WEAKNESSES:
──────────────────
• Poor lock installation
• Gap between door and frame
• Unlocked secondary exits
• Propped open doors
• Worn lock mechanisms
• REX (Request to Exit) sensor bypass
"""

BADGE_CLONING = """
BADGE/CARD CLONING:
═══════════════════

EQUIPMENT:
──────────
• Proxmark3 (most capable)
• ACR122U (NFC reader)
• Long-range reader (covert)
• Blank cards

125 kHz CARDS (Low Frequency):
──────────────────────────────
• HID Prox
• EM4100
• Easily cloned

# Using Proxmark3
lf search              # Identify card type
lf hid read            # Read HID card
lf hid clone -r [id]   # Clone to blank

13.56 MHz CARDS (High Frequency):
─────────────────────────────────
• MIFARE Classic (vulnerabilities exist)
• MIFARE DESFire (more secure)
• iCLASS (various security levels)

# Reading MIFARE
hf mf autopwn          # Attack MIFARE Classic
hf mf dump             # Dump card data

COVERT READING:
───────────────
• Long-range reader (up to 3 feet)
• Concealed in bag/briefcase
• Requires proximity to target
• Works best at badge height
"""

print(LOCK_BYPASS)
print(BADGE_CLONING)
```

---

## Module 16.6: Defense and Awareness (3-4 hours)

### 16.6.1 Security Awareness Training

```python
#!/usr/bin/env python3
"""
security_awareness.py - Building security awareness programs
"""

AWARENESS_PROGRAM = """
SECURITY AWARENESS PROGRAM:
═══════════════════════════

PROGRAM COMPONENTS:
───────────────────

1. INITIAL TRAINING
   ─────────────────
   • Onboarding security training
   • Policy acknowledgment
   • Role-based training
   • Hands-on exercises

2. ONGOING EDUCATION
   ──────────────────
   • Monthly newsletters
   • Quarterly training updates
   • Simulated phishing
   • Security champions program

3. REINFORCEMENT
   ──────────────
   • Posters and signage
   • Screensaver reminders
   • Email signatures
   • Intranet resources

TRAINING TOPICS:
────────────────
☐ Phishing recognition
☐ Password security
☐ Social engineering awareness
☐ Physical security
☐ Clean desk policy
☐ Mobile device security
☐ Data handling
☐ Incident reporting
☐ Travel security
☐ Social media safety

METRICS TO TRACK:
─────────────────
• Training completion rates
• Phishing simulation results
• Incident report volume
• Security question submissions
• Policy violation trends
"""

PHISHING_INDICATORS = """
PHISHING RECOGNITION TRAINING:
══════════════════════════════

RED FLAGS TO IDENTIFY:
──────────────────────

EMAIL INDICATORS:
• Sender address mismatch
• Generic greetings
• Spelling/grammar errors
• Urgent/threatening language
• Unexpected attachments
• Suspicious links
• Requests for credentials
• Too good to be true offers

LINK VERIFICATION:
• Hover before clicking
• Check for HTTPS
• Verify domain spelling
• Be wary of shortened URLs
• Check for typosquatting

ATTACHMENT SAFETY:
• Don't open unexpected attachments
• Verify with sender through other channel
• Be cautious of macros
• Check file extensions

REPORTING PROCEDURE:
1. Don't click any links
2. Don't reply to the email
3. Forward to security team
4. Delete the email
5. If clicked, report immediately

VISHING INDICATORS:
• Unsolicited calls
• Requests for sensitive info
• Pressure/urgency
• Unusual caller ID
• Threats of consequences
• Offers that seem too good
"""

print(AWARENESS_PROGRAM)
print(PHISHING_INDICATORS)
```

### 16.6.2 Technical Defenses

```python
#!/usr/bin/env python3
"""
se_defenses.py - Technical defenses against social engineering
"""

TECHNICAL_DEFENSES = """
TECHNICAL DEFENSES:
═══════════════════

EMAIL SECURITY:
───────────────
• SPF (Sender Policy Framework)
• DKIM (DomainKeys Identified Mail)
• DMARC (Domain-based Message Authentication)
• Email filtering/gateway
• Link rewriting/sandboxing
• Attachment sandboxing
• External email warnings
• Impersonation protection

EXAMPLE DMARC RECORD:
v=DMARC1; p=quarantine; rua=mailto:dmarc@company.com; pct=100

PHISHING PROTECTION:
────────────────────
• URL filtering
• Browser isolation
• Safe browsing features
• Anti-phishing toolbars
• DNS filtering
• Threat intelligence feeds

PHYSICAL SECURITY:
──────────────────
• Multi-factor authentication for access
• Anti-tailgating measures (mantraps)
• Security cameras with analytics
• Visitor management systems
• Badge challenge policies
• Secure document destruction

ENDPOINT PROTECTION:
────────────────────
• USB device control
• Application whitelisting
• Screen lock policies
• DLP (Data Loss Prevention)
• Endpoint detection and response
"""

POLICY_DEFENSES = """
POLICY-BASED DEFENSES:
══════════════════════

VERIFICATION POLICIES:
──────────────────────
• Callback verification for sensitive requests
• Out-of-band confirmation for wire transfers
• Dual authorization for high-value actions
• Identity verification procedures

DATA HANDLING:
──────────────
• Classification scheme
• Need-to-know principle
• Clean desk policy
• Secure disposal procedures
• Social media guidelines

INCIDENT RESPONSE:
──────────────────
• Clear reporting channels
• No-blame reporting culture
• Rapid response procedures
• Post-incident analysis

VISITOR MANAGEMENT:
───────────────────
• Sign-in requirements
• Escort policies
• Visitor badges (different from employee)
• Access limitations
• Exit procedures
"""

print(TECHNICAL_DEFENSES)
print(POLICY_DEFENSES)
```

---

## Module 16.7: Hands-On Labs (3-4 hours)

### Lab 16.1: OSINT Exercise

```
╔══════════════════════════════════════════════════════════════════════════╗
║                      LAB 16.1: OSINT EXERCISE                            ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Gather intelligence on a target organization                 ║
║  (Use a company you have permission to assess, or a training target)     ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Identify key personnel (executives, IT staff)                        ║
║  2. Map organizational structure                                         ║
║  3. Find email format and addresses                                      ║
║  4. Identify technologies used                                           ║
║  5. Find physical locations                                              ║
║  6. Document social media presence                                       ║
║  7. Look for leaked credentials                                          ║
║  8. Create target profiles                                               ║
║                                                                          ║
║  TOOLS:                                                                  ║
║  • Google dorking                                                        ║
║  • LinkedIn                                                              ║
║  • theHarvester                                                          ║
║  • Maltego (CE)                                                          ║
║  • Shodan                                                                ║
║  • Hunter.io                                                             ║
║                                                                          ║
║  DELIVERABLES:                                                           ║
║  • Organization profile document                                         ║
║  • Key personnel list with details                                       ║
║  • Potential attack vectors identified                                   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Lab 16.2: Phishing Campaign

```
╔══════════════════════════════════════════════════════════════════════════╗
║                    LAB 16.2: PHISHING CAMPAIGN                           ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Create and execute a phishing campaign                       ║
║  (ONLY with proper authorization!)                                       ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Set up Gophish                                                       ║
║  2. Create email template                                                ║
║  3. Build landing page                                                   ║
║  4. Configure sending profile                                            ║
║  5. Create target group                                                  ║
║  6. Launch campaign                                                      ║
║  7. Monitor results                                                      ║
║  8. Generate report                                                      ║
║                                                                          ║
║  GOPHISH SETUP:                                                          ║
║  ──────────────                                                          ║
║  # Download from https://getgophish.com                                  ║
║  ./gophish                                                               ║
║  # Access: https://localhost:3333                                        ║
║                                                                          ║
║  DELIVERABLES:                                                           ║
║  • Campaign statistics                                                   ║
║  • Analysis of results                                                   ║
║  • Recommendations for improvement                                       ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Summary and Key Takeaways

### Social Engineering Principles

| Principle | Application | Defense |
|-----------|-------------|---------|
| Authority | Impersonate executives | Verify through official channels |
| Urgency | Create time pressure | Take time to verify |
| Social Proof | "Everyone else did it" | Follow policy, not peers |
| Reciprocity | Offer help first | Don't feel obligated |
| Scarcity | Limited time offers | Question unrealistic offers |

### Defense Priorities

1. **Security Awareness Training** - Regular, engaging, measured
2. **Technical Controls** - Email filtering, MFA, access controls
3. **Policies and Procedures** - Verification requirements
4. **Culture** - Encourage reporting, no-blame environment
5. **Physical Security** - Badge policies, visitor management

### Assessment Focus Areas

| Area | Key Tests |
|------|-----------|
| Phishing | Email campaigns, credential capture |
| Vishing | Phone pretexting, information gathering |
| Physical | Tailgating, impersonation, badge cloning |
| OSINT | Information exposure, data leakage |

---

## Further Reading

- Social Engineering: The Science of Human Hacking (Christopher Hadnagy)
- The Art of Deception (Kevin Mitnick)
- Influence: The Psychology of Persuasion (Robert Cialdini)
- NIST SP 800-50 - Building Security Awareness Program
- SANS Security Awareness Resources

---

*Stage 16 Complete - Curriculum Complete*
