# Stage 12: Mobile and IoT Security

## Overview

**Duration:** 35-45 hours  
**Difficulty:** Intermediate to Advanced  
**Prerequisites:** Stage 1-10, Basic programming knowledge

This stage covers security concepts for mobile platforms (Android, iOS) and Internet of Things (IoT) devices. Students will learn vulnerability assessment, attack techniques, and defensive strategies for these increasingly important attack surfaces.

---

## Learning Objectives

By the end of this stage, you will be able to:

1. Understand mobile platform security architectures
2. Perform mobile application security assessments
3. Identify and exploit common mobile vulnerabilities
4. Assess IoT device security
5. Analyze IoT communication protocols
6. Exploit common IoT vulnerabilities
7. Implement mobile and IoT security best practices

---

## Module 12.1: Mobile Security Fundamentals (5-6 hours)

### 12.1.1 Mobile Platform Architecture

```
ANDROID SECURITY ARCHITECTURE:
══════════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                          ANDROID STACK                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     APPLICATIONS                                │   │
│   │  Home  |  Contacts  |  Browser  |  Camera  |  Third-Party Apps  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                  ANDROID FRAMEWORK                              │   │
│   │  Activity Manager | Content Providers | Package Manager         │   │
│   │  View System | Notification Manager | Resource Manager          │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                  NATIVE LIBRARIES | ANDROID RUNTIME             │   │
│   │  SQLite | OpenGL | SSL | WebKit  |  ART | Core Libraries        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │            HARDWARE ABSTRACTION LAYER (HAL)                     │   │
│   │  Audio | Camera | Bluetooth | GPS | Sensors | WiFi              │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     LINUX KERNEL                                │   │
│   │  Security | Memory Management | Process Management | Drivers    │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   SECURITY FEATURES:                                                    │
│   • Application Sandboxing (UID per app)                                │
│   • SELinux enforcement                                                 │
│   • Permission system                                                   │
│   • Verified Boot                                                       │
│   • Full Disk Encryption                                                │
│   • SafetyNet/Play Integrity                                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘


iOS SECURITY ARCHITECTURE:
══════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                            iOS STACK                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     APPLICATIONS                                │   │
│   │     System Apps  |  App Store Apps  |  Enterprise Apps          │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     COCOA TOUCH                                 │   │
│   │  UIKit | MapKit | EventKit | GameKit | PushKit                  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                        MEDIA                                    │   │
│   │  Core Audio | Core Graphics | OpenGL | Metal | AVFoundation     │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                    CORE SERVICES                                │   │
│   │  Security | Core Data | Core Location | Foundation | CFNetwork  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                    CORE OS / DARWIN                             │   │
│   │  XNU Kernel | Mach | BSD | Security Framework | Keychain        │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   SECURITY FEATURES:                                                    │
│   • App Sandbox (strict isolation)                                      │
│   • Code Signing (mandatory)                                            │
│   • Data Protection (file encryption classes)                           │
│   • Secure Enclave (hardware security)                                  │
│   • Keychain (secure credential storage)                                │
│   • App Transport Security (ATS)                                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 12.1.2 Mobile Threat Landscape

```python
#!/usr/bin/env python3
"""
mobile_threats.py - Mobile threat landscape overview
"""

OWASP_MOBILE_TOP_10 = """
OWASP MOBILE TOP 10 (2024):
═══════════════════════════

M1: IMPROPER CREDENTIAL USAGE
─────────────────────────────
• Hardcoded credentials in app
• Insecure storage of credentials
• Improper use of biometrics
Example: API key stored in strings.xml

M2: INADEQUATE SUPPLY CHAIN SECURITY
────────────────────────────────────
• Vulnerable third-party libraries
• Malicious SDKs
• Compromised development tools
Example: Malicious code in npm package

M3: INSECURE AUTHENTICATION/AUTHORIZATION
─────────────────────────────────────────
• Weak authentication mechanisms
• Missing authorization checks
• Session management issues
Example: Client-side auth bypass

M4: INSUFFICIENT INPUT/OUTPUT VALIDATION
────────────────────────────────────────
• SQL injection in local DB
• XSS in WebViews
• Path traversal
Example: SQL injection in SQLite queries

M5: INSECURE COMMUNICATION
──────────────────────────
• Missing certificate validation
• Using HTTP instead of HTTPS
• Ignoring TLS errors
Example: App accepts self-signed certs

M6: INADEQUATE PRIVACY CONTROLS
───────────────────────────────
• Excessive data collection
• Improper PII handling
• Missing privacy policies
Example: App leaks location data

M7: INSUFFICIENT BINARY PROTECTIONS
───────────────────────────────────
• Missing code obfuscation
• No anti-tampering
• Debuggable release builds
Example: Decompiled app reveals logic

M8: SECURITY MISCONFIGURATION
─────────────────────────────
• Improper export of components
• Insecure file permissions
• Debug features in production
Example: Exported ContentProvider

M9: INSECURE DATA STORAGE
─────────────────────────
• Plaintext sensitive data
• Insecure SharedPreferences
• Unencrypted databases
Example: Password in SQLite DB

M10: INSUFFICIENT CRYPTOGRAPHY
──────────────────────────────
• Weak algorithms (MD5, SHA1)
• Hardcoded keys
• Poor key management
Example: AES with ECB mode
"""

print(OWASP_MOBILE_TOP_10)
```

---

## Module 12.2: Android Security Testing (8-10 hours)

### 12.2.1 Android Testing Environment

```python
#!/usr/bin/env python3
"""
android_testing_setup.py - Android security testing environment
"""

ANDROID_TOOLS = """
ANDROID SECURITY TESTING TOOLS:
═══════════════════════════════

STATIC ANALYSIS:
────────────────
• APKTool      - Decompile/recompile APK
• jadx         - Decompile to Java
• dex2jar      - Convert DEX to JAR
• Androguard   - Python analysis framework
• MobSF        - Automated scanner
• QARK         - Find vulnerabilities

DYNAMIC ANALYSIS:
─────────────────
• Frida        - Runtime instrumentation
• Objection    - Runtime mobile exploration
• Drozer       - Security testing framework
• adb          - Android Debug Bridge
• Logcat       - System logs
• Burp Suite   - Traffic interception

EMULATORS:
──────────
• Android Studio Emulator
• Genymotion
• Corellium (paid, powerful)

ROOTED DEVICE TOOLS:
────────────────────
• Magisk       - Root management
• EdXposed     - Xposed framework
• LSPosed      - Modern Xposed
• RootBeer     - Root detection testing
"""

ADB_COMMANDS = """
ESSENTIAL ADB COMMANDS:
═══════════════════════

# Device management
adb devices                          # List connected devices
adb shell                           # Interactive shell
adb root                            # Restart as root

# App management
adb install app.apk                  # Install APK
adb install -r app.apk               # Replace existing
adb uninstall com.example.app        # Uninstall
adb shell pm list packages           # List all packages
adb shell pm list packages -3        # Third-party only
adb shell pm path com.example.app    # Find APK path

# Extract APK
adb pull /data/app/com.example.app-1/base.apk ./app.apk

# Data extraction
adb pull /data/data/com.example.app/ ./app_data/
adb shell run-as com.example.app ls  # Access app data (debuggable)

# Logging
adb logcat                           # All logs
adb logcat | grep com.example.app    # Filter by app
adb logcat -c                        # Clear log buffer

# Port forwarding (for Burp)
adb reverse tcp:8080 tcp:8080

# Screen capture
adb shell screencap /sdcard/screen.png
adb pull /sdcard/screen.png
"""

print(ANDROID_TOOLS)
print(ADB_COMMANDS)
```

### 12.2.2 Static Analysis

```python
#!/usr/bin/env python3
"""
android_static_analysis.py - Android static analysis techniques
"""

STATIC_ANALYSIS = """
ANDROID STATIC ANALYSIS:
════════════════════════

1. DECOMPILE APK
   ──────────────
   # Using APKTool (resources + smali)
   apktool d app.apk -o app_decompiled
   
   # Using jadx (Java source)
   jadx app.apk -d app_java

2. ANALYZE MANIFEST
   ─────────────────
   Key things to check:
   
   <!-- Exported components (accessible by other apps) -->
   <activity android:name=".AdminActivity" android:exported="true"/>
   
   <!-- Debuggable (CRITICAL - should be false in production) -->
   <application android:debuggable="true">
   
   <!-- Backup allowed (data extractable) -->
   <application android:allowBackup="true">
   
   <!-- Permissions requested -->
   <uses-permission android:name="android.permission.READ_CONTACTS"/>
   
   <!-- Intent filters on sensitive components -->
   <intent-filter>
       <action android:name="android.intent.action.VIEW"/>
   </intent-filter>
   
   <!-- Network security config -->
   <application android:networkSecurityConfig="@xml/network_security_config">

3. CODE REVIEW
   ────────────
   Look for:
   • Hardcoded secrets
   • Insecure crypto
   • SQL injection
   • Path traversal
   • WebView issues
   • Insecure data storage

4. STRINGS ANALYSIS
   ─────────────────
   # Search for sensitive strings
   grep -r "api_key" app_decompiled/
   grep -r "password" app_decompiled/
   grep -r "secret" app_decompiled/
   grep -r "http://" app_decompiled/  # Insecure connections
   
   # Find URLs
   strings app.apk | grep -E "https?://"

5. SECRETS DISCOVERY
   ──────────────────
   # Common locations
   res/values/strings.xml
   assets/config.json
   lib/*.so (native libraries)
   META-INF/
"""

COMMON_VULNS = """
COMMON ANDROID VULNERABILITIES:
═══════════════════════════════

1. EXPORTED COMPONENTS
   ────────────────────
   # In AndroidManifest.xml
   <activity android:name=".InternalActivity" 
             android:exported="true"/>  # BAD
   
   # Can be called by any app:
   adb shell am start -n com.example.app/.InternalActivity

2. INSECURE DATA STORAGE
   ──────────────────────
   # Check SharedPreferences
   /data/data/com.example.app/shared_prefs/
   
   # Check databases
   /data/data/com.example.app/databases/
   
   # Check for plaintext credentials
   sqlite3 database.db ".dump"

3. INSECURE WEBVIEW
   ─────────────────
   // JavaScript enabled
   webView.getSettings().setJavaScriptEnabled(true);
   
   // File access enabled
   webView.getSettings().setAllowFileAccess(true);
   
   // JavaScript interface (pre-API 17 vulnerability)
   webView.addJavascriptInterface(new WebAppInterface(), "Android");

4. INSECURE BROADCAST
   ───────────────────
   // Sending sensitive data via broadcast
   Intent intent = new Intent("com.example.SENSITIVE_ACTION");
   intent.putExtra("password", userPassword);
   sendBroadcast(intent);  // Any app can receive!

5. SQL INJECTION
   ──────────────
   // Vulnerable query
   String query = "SELECT * FROM users WHERE name='" + userInput + "'";
   db.rawQuery(query, null);
   
   // Safe query (parameterized)
   db.query("users", null, "name=?", new String[]{userInput}, null, null, null);

6. PATH TRAVERSAL
   ───────────────
   // ContentProvider vulnerability
   @Override
   public ParcelFileDescriptor openFile(Uri uri, String mode) {
       File file = new File(getContext().getFilesDir(), uri.getLastPathSegment());
       // ../../../etc/passwd could escape
       return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
   }
"""

print(STATIC_ANALYSIS)
print(COMMON_VULNS)
```

### 12.2.3 Dynamic Analysis with Frida

```python
#!/usr/bin/env python3
"""
frida_android.py - Frida scripts for Android analysis
"""

FRIDA_BASICS = """
FRIDA FOR ANDROID:
══════════════════

INSTALLATION:
─────────────
pip install frida-tools
# Download frida-server for your Android architecture
# Push to device and run as root

BASIC USAGE:
────────────
# List running apps
frida-ps -U

# Attach to running app
frida -U com.example.app

# Spawn app with script
frida -U -f com.example.app -l script.js

# List processes
frida-ps -Uai
"""

FRIDA_SCRIPTS = '''
/* Frida Script: SSL Pinning Bypass */

Java.perform(function() {
    // Trust Manager bypass
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManagerImpl = Java.registerClass({
        name: 'com.example.TrustManagerImpl',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManagerImpl.$new()];
    var sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, TrustManagers, null);
    
    console.log('[+] SSL Pinning Bypassed');
});


/* Frida Script: Hook Encryption */

Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[Cipher.doFinal] Input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[Cipher.doFinal] Output: ' + bytesToHex(result));
        return result;
    };
    
    function bytesToHex(bytes) {
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
});


/* Frida Script: Root Detection Bypass */

Java.perform(function() {
    // Bypass common root detection methods
    
    // Method 1: Hook File.exists()
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/system/app/Superuser.apk', '/system/xbin/su', 
                        '/system/bin/su', '/sbin/su', '/data/local/xbin/su'];
        
        if (rootPaths.indexOf(path) >= 0) {
            console.log('[Root Detection] Blocked check for: ' + path);
            return false;
        }
        return this.exists();
    };
    
    // Method 2: Hook Build.TAGS
    var Build = Java.use('android.os.Build');
    var TAGS = Build.class.getDeclaredField('TAGS');
    TAGS.setAccessible(true);
    TAGS.set(null, 'release-keys');
    
    console.log('[+] Root Detection Bypassed');
});


/* Frida Script: Method Tracing */

Java.perform(function() {
    var targetClass = Java.use('com.example.app.AuthManager');
    
    // Hook all methods in class
    var methods = targetClass.class.getDeclaredMethods();
    methods.forEach(function(method) {
        var methodName = method.getName();
        
        try {
            targetClass[methodName].overloads.forEach(function(overload) {
                overload.implementation = function() {
                    console.log('[' + methodName + '] Called');
                    console.log('Arguments: ' + JSON.stringify(arguments));
                    var result = overload.apply(this, arguments);
                    console.log('Return: ' + result);
                    return result;
                };
            });
        } catch(e) {}
    });
});
'''

print(FRIDA_BASICS)
print("FRIDA SCRIPTS:")
print(FRIDA_SCRIPTS)
```

---

## Module 12.3: iOS Security Testing (6-8 hours)

### 12.3.1 iOS Testing Environment

```python
#!/usr/bin/env python3
"""
ios_testing_setup.py - iOS security testing environment
"""

IOS_TOOLS = """
iOS SECURITY TESTING TOOLS:
═══════════════════════════

STATIC ANALYSIS:
────────────────
• class-dump      - Extract ObjC headers
• otool           - Object file tool
• Hopper          - Disassembler
• IDA Pro         - Disassembler
• MobSF           - Automated scanner

DYNAMIC ANALYSIS:
─────────────────
• Frida           - Runtime instrumentation
• Objection       - Runtime exploration
• Cycript         - Runtime manipulation
• LLDB            - Debugger
• Charles/Burp    - Traffic interception

JAILBROKEN DEVICE:
──────────────────
• Checkra1n       - Hardware exploit jailbreak
• unc0ver         - Semi-untethered
• Dopamine        - Rootless jailbreak
• Cydia/Sileo     - Package managers

FILESYSTEM ACCESS:
──────────────────
• ssh to device (default: alpine)
• scp for file transfer
• iFunBox (USB access)
"""

IOS_ANALYSIS = """
iOS STATIC ANALYSIS:
════════════════════

1. EXTRACT IPA
   ────────────
   # From jailbroken device
   ssh root@device
   cd /var/containers/Bundle/Application/
   find . -name "*.app" -type d
   
   # Copy .app bundle to computer
   scp -r root@device:/path/to/App.app ./

2. ANALYZE BINARY
   ───────────────
   # Check architecture
   lipo -info App.app/App
   
   # List classes (Objective-C)
   class-dump App.app/App > classes.h
   
   # Check for encryption
   otool -l App.app/App | grep crypt
   
   # If encrypted, decrypt with Clutch or bfdecrypt

3. CHECK INFO.PLIST
   ─────────────────
   Key things to check:
   • NSAppTransportSecurity
   • URLSchemes (deep links)
   • NSCameraUsageDescription
   • Background modes

4. CHECK BINARY PROTECTIONS
   ─────────────────────────
   # PIE (Position Independent Executable)
   otool -hv App.app/App | grep PIE
   
   # Stack canaries
   otool -I -v App.app/App | grep stack_chk
   
   # ARC (Automatic Reference Counting)
   otool -I -v App.app/App | grep objc_release

5. STRINGS ANALYSIS
   ─────────────────
   strings App.app/App | grep -i password
   strings App.app/App | grep -E "https?://"
"""

print(IOS_TOOLS)
print(IOS_ANALYSIS)
```

### 12.3.2 iOS Dynamic Analysis

```python
#!/usr/bin/env python3
"""
ios_dynamic_analysis.py - iOS dynamic analysis with Frida/Objection
"""

OBJECTION_GUIDE = """
OBJECTION FOR iOS:
══════════════════

INSTALLATION:
─────────────
pip install objection

BASIC USAGE:
────────────
# List apps
objection --gadget "App Name" explore

# Inside objection
ios info binary                    # Binary info
ios plist cat Info.plist           # View plist
ios keychain dump                  # Dump keychain
ios cookies get                    # Get cookies
ios nsuserdefaults get             # Get user defaults
ios sslpinning disable             # Disable SSL pinning

FILESYSTEM COMMANDS:
────────────────────
file download /path/to/file        # Download file
file upload local.txt remote.txt   # Upload file
ls                                 # List directory
cd /var/mobile/                    # Change directory
pwd                                # Print working directory
cat file.txt                       # View file

HOOKING:
────────
ios hooking watch class ClassName       # Watch all methods
ios hooking watch method "-[Class method]"  # Watch specific
ios hooking set return_value true      # Modify return
"""

IOS_FRIDA = '''
/* Frida Script: iOS Keychain Access */

if (ObjC.available) {
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName('Security', 'SecItemCopyMatching'),
        'int', ['pointer', 'pointer']
    );
    
    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            console.log('[Keychain Access]');
        },
        onLeave: function(retval) {
            console.log('Result: ' + retval);
        }
    });
}


/* Frida Script: iOS SSL Pinning Bypass */

if (ObjC.available) {
    try {
        var className = "NSURLSessionConfiguration";
        var funcName = "+ sessionConfiguration";
        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        
        Interceptor.attach(hook.implementation, {
            onLeave: function(retval) {
                var config = new ObjC.Object(retval);
                config.setURLCredentialStorage_(null);
                console.log('[+] SSL Pinning Bypassed');
            }
        });
    } catch(e) {
        console.log('[-] Error: ' + e.message);
    }
}


/* Frida Script: iOS Jailbreak Detection Bypass */

if (ObjC.available) {
    // Hook NSFileManager
    var NSFileManager = ObjC.classes.NSFileManager;
    
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function(args) {
            var path = new ObjC.Object(args[2]).toString();
            this.isJailbreakPath = path.indexOf('/Applications/Cydia') >= 0 ||
                                   path.indexOf('/Library/MobileSubstrate') >= 0 ||
                                   path.indexOf('/bin/bash') >= 0;
        },
        onLeave: function(retval) {
            if (this.isJailbreakPath) {
                retval.replace(0);
                console.log('[+] Blocked jailbreak detection');
            }
        }
    });
}


/* Frida Script: Trace ObjC Methods */

if (ObjC.available) {
    var resolver = new ApiResolver('objc');
    resolver.enumerateMatches('-[* password*]', {
        onMatch: function(match) {
            console.log('Found: ' + match.name);
            Interceptor.attach(match.address, {
                onEnter: function(args) {
                    console.log('[' + match.name + '] called');
                }
            });
        },
        onComplete: function() {}
    });
}
'''

print(OBJECTION_GUIDE)
print("\niOS FRIDA SCRIPTS:")
print(IOS_FRIDA)
```

---

## Module 12.4: IoT Security Fundamentals (6-8 hours)

### 12.4.1 IoT Architecture and Attack Surface

```
IoT ARCHITECTURE:
═════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│                          IoT ECOSYSTEM                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                         CLOUD LAYER                             │   │
│   │    ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐       │   │
│   │    │  API    │   │  Data   │   │ Device  │   │Analytics│       │   │
│   │    │ Gateway │   │ Storage │   │ Mgmt    │   │         │       │   │
│   │    └─────────┘   └─────────┘   └─────────┘   └─────────┘       │   │
│   └───────────────────────────┬─────────────────────────────────────┘   │
│                               │                                         │
│   ┌───────────────────────────▼─────────────────────────────────────┐   │
│   │                      NETWORK LAYER                              │   │
│   │    ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐       │   │
│   │    │ Gateway │   │ Router  │   │ Firewall│   │ Bridge  │       │   │
│   │    └─────────┘   └─────────┘   └─────────┘   └─────────┘       │   │
│   └───────────────────────────┬─────────────────────────────────────┘   │
│                               │                                         │
│   ┌───────────────────────────▼─────────────────────────────────────┐   │
│   │                      DEVICE LAYER                               │   │
│   │    ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐       │   │
│   │    │ Sensors │   │Actuators│   │ Cameras │   │ Smart   │       │   │
│   │    │         │   │         │   │         │   │ Devices │       │   │
│   │    └─────────┘   └─────────┘   └─────────┘   └─────────┘       │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ATTACK SURFACE:                                                       │
│   ───────────────                                                       │
│   • Device: Firmware, hardware, debug ports, bootloader                 │
│   • Communication: WiFi, Bluetooth, Zigbee, MQTT, CoAP                  │
│   • Cloud: APIs, authentication, data storage                           │
│   • Mobile App: Companion apps, local communication                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 12.4.2 IoT Communication Protocols

```python
#!/usr/bin/env python3
"""
iot_protocols.py - IoT communication protocols security
"""

IOT_PROTOCOLS = """
IoT COMMUNICATION PROTOCOLS:
════════════════════════════

MQTT (Message Queuing Telemetry Transport):
────────────────────────────────────────────
• Port: 1883 (unencrypted), 8883 (TLS)
• Publish/Subscribe model
• Lightweight, ideal for constrained devices

Common issues:
• Anonymous access allowed
• No TLS encryption
• Weak authentication
• Wildcard subscriptions (#)

# Test MQTT
mosquitto_sub -h target -t '#' -v  # Subscribe to all topics
mosquitto_pub -h target -t 'test' -m 'message'  # Publish


CoAP (Constrained Application Protocol):
────────────────────────────────────────
• Port: 5683 (UDP)
• REST-like operations
• Designed for constrained networks

Common issues:
• No authentication
• No encryption (unless DTLS)
• Predictable tokens


HTTP/HTTPS APIs:
────────────────
• Standard REST APIs
• Often lack proper authentication
• Insecure direct object references

Common issues:
• Missing authentication
• Broken access control
• Injection vulnerabilities


WIRELESS PROTOCOLS:
───────────────────

Zigbee:
• 2.4 GHz, mesh network
• Used in smart home devices
• Vulnerabilities: key extraction, replay attacks

Z-Wave:
• Sub-GHz frequency
• Home automation
• Vulnerabilities: forced pairing, encryption weaknesses

Bluetooth/BLE:
• Short range communication
• Smartphone to device
• Vulnerabilities: MITM, pairing attacks, sniffing
"""

MQTT_ANALYSIS = """
MQTT SECURITY TESTING:
══════════════════════

TOOLS:
──────
• mosquitto_sub/pub - Command line MQTT client
• MQTT Explorer - GUI client
• mqtt-pwn - MQTT pentesting tool
• Wireshark - Protocol analysis

TESTING STEPS:
──────────────
1. DISCOVER BROKER
   ────────────────
   nmap -p 1883,8883 target
   
2. TEST ANONYMOUS ACCESS
   ──────────────────────
   mosquitto_sub -h target -t '#' -v
   # If successful, anonymous access is enabled
   
3. ENUMERATE TOPICS
   ─────────────────
   # Subscribe to all with wildcard
   mosquitto_sub -h target -t '#' -v
   mosquitto_sub -h target -t '$SYS/#' -v  # System topics
   
4. TEST PUBLISHING
   ────────────────
   mosquitto_pub -h target -t 'device/command' -m 'ON'
   
5. CREDENTIAL BRUTE FORCE
   ───────────────────────
   # Use mqtt-pwn or custom script
   for pass in $(cat wordlist.txt); do
       mosquitto_sub -h target -u admin -P $pass -t '#'
   done
"""

print(IOT_PROTOCOLS)
print(MQTT_ANALYSIS)
```

### 12.4.3 Firmware Analysis

```python
#!/usr/bin/env python3
"""
firmware_analysis.py - IoT firmware analysis techniques
"""

FIRMWARE_ANALYSIS = """
FIRMWARE ANALYSIS:
══════════════════

OBTAINING FIRMWARE:
───────────────────
• Manufacturer website (updates)
• Device memory extraction
• UART/JTAG interfaces
• Intercepted OTA updates
• FCC ID database

TOOLS:
──────
• binwalk      - Firmware extraction
• firmware-mod-kit - Modification tools
• Ghidra       - Reverse engineering
• QEMU         - Emulation
• Firmwalker   - Analysis automation
• FACT         - Firmware Analysis and Comparison Tool

EXTRACTION PROCESS:
───────────────────
# 1. Analyze firmware structure
binwalk firmware.bin

# 2. Extract filesystem
binwalk -e firmware.bin
# or
binwalk -Me firmware.bin  # Recursive extraction

# 3. Identify filesystem type
file _firmware.bin.extracted/*

# Common filesystems:
# • SquashFS
# • JFFS2
# • UBIFS
# • ext4
"""

FIRMWARE_VULNS = """
COMMON FIRMWARE VULNERABILITIES:
════════════════════════════════

1. HARDCODED CREDENTIALS
   ──────────────────────
   # Search for passwords
   grep -r "password" ./extracted/
   grep -r "admin" ./extracted/
   strings firmware.bin | grep -i pass
   
   # Check /etc/passwd, /etc/shadow
   cat ./extracted/squashfs-root/etc/passwd

2. BACKDOOR ACCOUNTS
   ──────────────────
   # Look for hidden accounts
   cat ./extracted/etc/passwd
   # Check for unusual shells or UIDs

3. INSECURE SERVICES
   ──────────────────
   # Check for enabled services
   ls ./extracted/etc/init.d/
   
   # Look for telnet, debug ports
   grep -r "telnetd" ./extracted/
   grep -r "23" ./extracted/etc/

4. ENCRYPTION KEYS
   ────────────────
   # Find private keys
   find ./extracted -name "*.pem" -o -name "*.key"
   
   # Find certificates
   find ./extracted -name "*.crt" -o -name "*.cer"

5. DEBUG INTERFACES
   ─────────────────
   # UART configuration
   grep -r "console" ./extracted/
   
   # Debug scripts
   find ./extracted -name "*debug*"

6. VULNERABLE LIBRARIES
   ─────────────────────
   # Check versions
   strings ./extracted/lib/*.so | grep -i version
   
   # Look for known vulnerable libs
   # BusyBox, OpenSSL, etc.
"""

HARDWARE_INTERFACES = """
HARDWARE DEBUG INTERFACES:
══════════════════════════

UART (Universal Asynchronous Receiver-Transmitter):
────────────────────────────────────────────────────
• Serial console access
• Often provides root shell
• Pins: TX, RX, GND, (VCC)

Identification:
• Look for 4-pin headers
• Use multimeter for ground
• Use logic analyzer for TX

Connection:
• USB-to-UART adapter (FTDI, CP2102)
• Connect TX→RX, RX→TX, GND→GND
• Common baud rates: 115200, 9600


JTAG (Joint Test Action Group):
───────────────────────────────
• Debug and flash interface
• Full memory access
• Firmware extraction/modification

Identification:
• 10-20 pin headers
• Use JTAGulator

Tools:
• OpenOCD
• JTAGulator
• Bus Pirate


SPI (Serial Peripheral Interface):
──────────────────────────────────
• Flash memory access
• Direct firmware extraction

Tools:
• flashrom
• Bus Pirate
• SPI flash programmers
"""

print(FIRMWARE_ANALYSIS)
print(FIRMWARE_VULNS)
print(HARDWARE_INTERFACES)
```

---

## Module 12.5: IoT Exploitation (5-6 hours)

### 12.5.1 Common IoT Attacks

```python
#!/usr/bin/env python3
"""
iot_attacks.py - Common IoT attack techniques
"""

IOT_ATTACKS = """
COMMON IoT ATTACK VECTORS:
══════════════════════════

1. DEFAULT CREDENTIALS
   ────────────────────
   # Try default passwords
   admin:admin
   root:root
   admin:password
   user:user
   
   # Check manufacturer documentation
   # Search: "device_name default password"

2. FIRMWARE MODIFICATION
   ──────────────────────
   # Extract firmware
   binwalk -e firmware.bin
   
   # Modify (add backdoor)
   # Edit files in extracted filesystem
   
   # Repack
   # Flash modified firmware

3. NETWORK ATTACKS
   ────────────────
   # ARP spoofing
   arpspoof -i eth0 -t device_ip gateway_ip
   
   # Traffic capture
   tcpdump -i eth0 host device_ip
   
   # Downgrade attacks (force HTTP)

4. REPLAY ATTACKS
   ───────────────
   # Capture command
   # Replay to device
   
   # Example with MQTT:
   mosquitto_sub -h target -t 'device/command' -v
   # Capture legitimate command, replay later

5. DENIAL OF SERVICE
   ──────────────────
   # Resource exhaustion
   # Protocol-specific attacks
   # Physical jamming (RF)

6. PHYSICAL ATTACKS
   ─────────────────
   # UART shell access
   # JTAG debugging
   # Chip desoldering
   # Side-channel attacks
"""

MIRAI_ANALYSIS = """
MIRAI BOTNET ANALYSIS (Educational):
════════════════════════════════════

INFECTION VECTOR:
─────────────────
• Telnet brute force
• Default credentials
• Targeted IoT devices (cameras, routers, DVRs)

CREDENTIAL LIST (from leaked source):
─────────────────────────────────────
root:xc3511
root:vizxv
root:admin
admin:admin
root:888888
root:xmhdipc
root:default
root:juantech
(60+ credential pairs)

CAPABILITIES:
─────────────
• DDoS attacks (UDP flood, TCP flood, HTTP flood)
• Self-propagation
• Removes competing malware
• Persistence through reboots

DEFENSE:
────────
• Change default credentials
• Disable Telnet
• Network segmentation
• Monitor for scanning behavior
• Regular firmware updates
"""

print(IOT_ATTACKS)
print(MIRAI_ANALYSIS)
```

### 12.5.2 BLE (Bluetooth Low Energy) Attacks

```python
#!/usr/bin/env python3
"""
ble_security.py - Bluetooth Low Energy security testing
"""

BLE_ATTACKS = """
BLUETOOTH LOW ENERGY (BLE) SECURITY:
════════════════════════════════════

TOOLS:
──────
• hcitool       - Bluetooth scanning
• gatttool      - GATT operations
• btlejack      - BLE sniffing
• Ubertooth     - Bluetooth sniffer
• BLE CTF       - Practice app
• nRF Connect   - Mobile app

RECONNAISSANCE:
───────────────
# Scan for BLE devices
sudo hcitool lescan

# Get device info
sudo hcitool leinfo [MAC]

# List services and characteristics
gatttool -b [MAC] --primary
gatttool -b [MAC] --characteristics

COMMON ATTACKS:
───────────────

1. EAVESDROPPING
   ──────────────
   # Sniff BLE traffic
   sudo btlejack -d [MAC] -f
   
   # With Ubertooth
   ubertooth-btle -f -c [channel]

2. SPOOFING
   ─────────
   # Clone device MAC/advertisement
   # Perform MITM attacks

3. REPLAY ATTACKS
   ───────────────
   # Capture authenticated command
   # Replay without encryption

4. UNAUTHORIZED ACCESS
   ────────────────────
   # Connect without pairing
   gatttool -b [MAC] -I
   > connect
   > char-read-hnd 0x0001
   
5. DOS ATTACKS
   ────────────
   # Flood connection requests
   # Jam BLE channels

GATT EXPLOITATION:
──────────────────
# Read all characteristics
gatttool -b [MAC] -I
> connect
> primary
> characteristics
> char-read-hnd [handle]

# Write to characteristic
> char-write-cmd [handle] [value]

# Enable notifications
> char-write-cmd [handle] 0100
"""

print(BLE_ATTACKS)
```

---

## Module 12.6: Mobile and IoT Defense (4-5 hours)

### 12.6.1 Secure Development Practices

```python
#!/usr/bin/env python3
"""
secure_development.py - Mobile and IoT security best practices
"""

MOBILE_SECURITY = """
MOBILE SECURE DEVELOPMENT:
══════════════════════════

DATA STORAGE:
─────────────
Android:
• Use EncryptedSharedPreferences
• Encrypt SQLite with SQLCipher
• Use Keystore for keys
• Avoid external storage for sensitive data

iOS:
• Use Keychain for credentials
• Set appropriate Data Protection class
• Use file protection attributes
• Avoid UserDefaults for secrets

NETWORK SECURITY:
─────────────────
• Implement certificate pinning
• Use TLS 1.2+ only
• Validate server certificates
• Don't trust user-added CAs
• Implement proper error handling

AUTHENTICATION:
───────────────
• Use biometrics properly
• Implement session timeout
• Server-side validation
• Rate limiting
• Secure token storage

CODE PROTECTION:
────────────────
• Obfuscate code (ProGuard/R8, iOS obfuscators)
• Implement anti-tampering
• Detect rooted/jailbroken devices
• Strip debug symbols
• Use native code for sensitive logic
"""

IOT_SECURITY = """
IoT SECURE DEVELOPMENT:
═══════════════════════

DEVICE SECURITY:
────────────────
• Disable debug interfaces in production
• Secure boot implementation
• Hardware security modules (TPM, Secure Enclave)
• Tamper detection
• Secure firmware updates (signed, encrypted)

COMMUNICATION:
──────────────
• Use TLS/DTLS for all traffic
• Mutual authentication
• Certificate pinning
• Message authentication
• Encryption for sensitive data

AUTHENTICATION:
───────────────
• Unique credentials per device
• No default passwords
• Certificate-based auth preferred
• Secure key storage
• Regular credential rotation

FIRMWARE:
─────────
• Signed updates only
• Secure boot chain
• Encrypted storage
• No hardcoded secrets
• Regular security updates

NETWORK:
────────
• Segment IoT networks
• Monitor traffic patterns
• Firewall IoT devices
• Disable unnecessary services
• Regular vulnerability scanning
"""

SECURITY_CHECKLIST = """
MOBILE/IoT SECURITY CHECKLIST:
══════════════════════════════

MOBILE APP:
───────────
☐ No hardcoded credentials
☐ Secure data storage
☐ Certificate pinning
☐ Input validation
☐ Code obfuscation
☐ Jailbreak/root detection
☐ Anti-debugging measures
☐ Secure session management
☐ Proper logging (no sensitive data)
☐ Secure IPC

IoT DEVICE:
───────────
☐ Change default credentials
☐ Disable debug ports
☐ Secure firmware updates
☐ Encrypted communication
☐ Network segmentation
☐ Regular updates
☐ Secure boot
☐ No unnecessary services
☐ Unique device credentials
☐ Tamper detection
"""

print(MOBILE_SECURITY)
print(IOT_SECURITY)
print(SECURITY_CHECKLIST)
```

---

## Module 12.7: Hands-On Labs (4-5 hours)

### Lab 12.1: Android App Assessment

```
╔══════════════════════════════════════════════════════════════════════════╗
║                  LAB 12.1: ANDROID APP ASSESSMENT                        ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Perform security assessment of an Android application        ║
║                                                                          ║
║  TARGET: DIVA (Damn Insecure and Vulnerable App)                         ║
║  Download: https://github.com/payatu/diva-android                        ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Install and explore the app                                          ║
║  2. Decompile APK with jadx/apktool                                      ║
║  3. Analyze AndroidManifest.xml                                          ║
║  4. Find hardcoded credentials                                           ║
║  5. Test insecure data storage                                           ║
║  6. Exploit input validation issues                                      ║
║  7. Test access control issues                                           ║
║  8. Intercept and analyze traffic                                        ║
║                                                                          ║
║  TOOLS NEEDED:                                                           ║
║  • Android emulator or device                                            ║
║  • APKTool / jadx                                                        ║
║  • ADB                                                                   ║
║  • Burp Suite                                                            ║
║  • Frida (optional)                                                      ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Lab 12.2: IoT Device Analysis

```
╔══════════════════════════════════════════════════════════════════════════╗
║                   LAB 12.2: IoT DEVICE ANALYSIS                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  OBJECTIVE: Analyze IoT device firmware and communications               ║
║                                                                          ║
║  TARGET: Practice firmware or vulnerable VM                              ║
║  • DVR firmware (available online)                                       ║
║  • IoTGoat (OWASP vulnerable IoT)                                        ║
║                                                                          ║
║  TASKS:                                                                  ║
║  ─────                                                                   ║
║  1. Download sample firmware                                             ║
║  2. Extract filesystem with binwalk                                      ║
║  3. Identify filesystem type                                             ║
║  4. Search for hardcoded credentials                                     ║
║  5. Analyze configuration files                                          ║
║  6. Identify enabled services                                            ║
║  7. Check for vulnerable libraries                                       ║
║  8. Document all findings                                                ║
║                                                                          ║
║  COMMANDS:                                                               ║
║  binwalk -e firmware.bin                                                 ║
║  grep -r "password" ./extracted/                                         ║
║  find ./extracted -name "*.conf"                                         ║
║  strings ./extracted/bin/* | grep -i admin                               ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Summary and Key Takeaways

### Mobile Security Priorities

| Platform | Key Controls |
|----------|--------------|
| Android | Proper permissions, secure storage, ProGuard, certificate pinning |
| iOS | Keychain usage, ATS, code signing, jailbreak detection |
| Both | Input validation, secure APIs, no hardcoded secrets |

### IoT Security Priorities

| Layer | Key Controls |
|-------|--------------|
| Device | Secure boot, no debug ports, unique credentials |
| Network | TLS/DTLS, segmentation, monitoring |
| Cloud | Strong authentication, secure APIs, encryption |
| Firmware | Signed updates, no secrets, regular patching |

### Essential Tools

| Category | Tools |
|----------|-------|
| Android | APKTool, Frida, Objection, MobSF |
| iOS | class-dump, Frida, Objection, otool |
| IoT | binwalk, Wireshark, MQTT tools, Ubertooth |

---

## Further Reading

- OWASP Mobile Security Testing Guide
- OWASP IoT Security Verification Standard
- Android Security Documentation
- Apple Platform Security Guide
- IoT Hackers Handbook (Aditya Gupta)

---

*Stage 12 Complete - Continue to Stage 16: Social Engineering & Physical Security*
