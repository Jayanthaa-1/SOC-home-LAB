# Security Home Lab Environment

**Virtualised SOC Lab | 15 Alerts Triaged | Incident Response | Playbook Execution**

![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Level](https://img.shields.io/badge/Level-SOC%20L1-blue?style=flat-square)
![Alerts](https://img.shields.io/badge/Alerts%20Closed-15-orange?style=flat-square)
![VMs](https://img.shields.io/badge/VMs-3-informational?style=flat-square)

---

## What I Built

Designed and deployed a virtualised home lab to simulate enterprise security scenarios and practise SOC Level 1 skills. Three virtual machines were configured on an isolated internal network — a Windows 10 target endpoint, an Ubuntu log server running Splunk Free, and a Kali Linux attacker machine. All 15 alerts were self-generated and triaged using real SOC L1 methodology.

---

## Lab Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │                  HOST MACHINE                           │
  │                                                         │
  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
  │  │  Windows 10 │  │Ubuntu Server │  │  Kali Linux   │  │
  │  │             │  │              │  │               │  │
  │  │  Target     │  │  Log Server  │  │  Attacker     │  │
  │  │  Endpoint   │  │  Splunk Free │  │  Simulation   │  │
  │  │             │  │              │  │               │  │
  │  │192.168.56.10│  │192.168.56.20 │  │192.168.56.30  │  │
  │  └─────────────┘  └──────────────┘  └───────────────┘  │
  │                                                         │
  │          Host-Only Network: 192.168.56.0/24             │
  └─────────────────────────────────────────────────────────┘
```

| VM | OS | IP | Role |
|---|---|---|---|
| VM1 | Windows 10 Pro | 192.168.56.10 | Target endpoint |
| VM2 | Ubuntu Server 22.04 | 192.168.56.20 | Log server — Splunk Free |
| VM3 | Kali Linux 2024.1 | 192.168.56.30 | Attacker simulation |

---

## Evidence

### 1 — Lab Network — VirtualBox Host-Only Adapter Config

```
VirtualBox Network Manager
─────────────────────────────────────────────────
Adapter     : VirtualBox Host-Only Ethernet Adapter
IPv4 Address: 192.168.56.1
IPv4 Mask   : 255.255.255.0
DHCP Server : Disabled (static IPs assigned per VM)

VM1 (Windows 10)     : 192.168.56.10  — static
VM2 (Ubuntu Server)  : 192.168.56.20  — static
VM3 (Kali Linux)     : 192.168.56.30  — static
```

### 2 — Splunk Receiving Logs from Windows Target

```
Splunk Search — confirming Windows logs indexed from VM1

index=wineventlog host="WINDOWS-TARGET"
| stats count by EventCode
| sort - count

EventCode  | count
───────────────────
4624       | 847    (Successful logon)
4625       | 312    (Failed logon)
4688       | 1,204  (Process creation)
4663       | 438    (Object access)
7045       | 12     (New service installed)

Data source: 192.168.56.10 → Splunk Universal Forwarder → VM2
```

### 3 — Attack Simulation from Kali Linux

```
kali@kali:~$ nmap -sS -p 1-1024 192.168.56.10

Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.56.10
Host is up (0.00042s latency).

PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  closed http
135/tcp open   msrpc
139/tcp open   netbios-ssn
443/tcp closed https
445/tcp open   microsoft-ds
3389/tcp open  ms-wbt-server (RDP)

Nmap done: 1 IP address scanned in 3.42 seconds
```

```
kali@kali:~$ hydra -l administrator -P /usr/share/wordlists/rockyou.txt \
  192.168.56.20 ssh -t 4

Hydra v9.5 starting

[DATA] attacking ssh://192.168.56.20:22/
[ATTEMPT] target 192.168.56.20 - login "administrator" - pass "123456"
[ATTEMPT] target 192.168.56.20 - login "administrator" - pass "password"
[ATTEMPT] target 192.168.56.20 - login "administrator" - pass "qwerty"
...
[STATUS] 48 attempts completed — SSH brute-force simulation active
```

### 4 — Sysmon Detecting Reverse Shell (High Severity Alert)

```
Sysmon Event ID 3 — Network Connection

Image         : C:\Windows\Temp\payload.exe
User          : SYSTEM
Protocol      : tcp
Initiated     : true
SourceIp      : 192.168.56.10
SourcePort    : 49721
DestinationIp : 192.168.56.30
DestinationPort: 4444

ANALYSIS:
  - payload.exe calling out to attacker IP on port 4444
  - Port 4444 = default Metasploit Meterpreter listener port
  - Process running as SYSTEM = privilege escalation has occurred
  - Verdict: Reverse shell session established — HIGH severity
```

```
Sysmon Event ID 1 — Process Creation (spawned by shell)

ParentImage   : C:\Windows\Temp\payload.exe
Image         : C:\Windows\System32\cmd.exe
CommandLine   : cmd.exe /c whoami
User          : NT AUTHORITY\SYSTEM

ANALYSIS:
  - cmd.exe spawned by payload.exe — shell execution confirmed
  - whoami run as SYSTEM — confirms full system compromise
```

### 5 — All 15 Alerts Triaged

**High Severity — 5 alerts (all TRUE POSITIVE)**

```
H-01 | Successful Exploitation
      EternalBlue (ms17-010) via Metasploit — RCE on Windows target
      Evidence: Sysmon EID 1 — cmd.exe spawned as SYSTEM
      Verdict : TRUE POSITIVE — Escalate

H-02 | Reverse Shell Connection
      Outbound TCP to attacker IP port 4444 — Meterpreter session
      Evidence: Sysmon EID 3 — payload.exe → 192.168.56.30:4444
      Verdict : TRUE POSITIVE — Escalate

H-03 | Privilege Escalation
      EID 4672 (Special Logon) + whoami /all running as SYSTEM
      Evidence: Process tree shows privilege escalation chain
      Verdict : TRUE POSITIVE — Escalate

H-04 | SMB Lateral Movement
      EID 5140 — C$ share accessed from attacker IP + file write to Temp
      Evidence: Logon Type 3 from 192.168.56.30 to WINDOWS-TARGET
      Verdict : TRUE POSITIVE — Escalate

H-05 | LSASS Credential Dump
      Sysmon EID 10 — mimikatz.exe accessing lsass.exe process memory
      Evidence: Process access with rights 0x1010 (PROCESS_VM_READ)
      Verdict : TRUE POSITIVE — Escalate
```

**Medium Severity — 6 alerts (5 TRUE POSITIVE, 1 investigated)**

```
M-01 | Port Scan Detected
      Nmap SYN scan — 1024 ports in 3.4 seconds from 192.168.56.30
      Evidence: High rate of RST/ACK packets in Sysmon network logs
      Verdict : TRUE POSITIVE — Monitor

M-02 | SSH Brute-Force (Ubuntu)
      Hydra from Kali — 48 failed SSH attempts in 2 minutes
      Evidence: /var/log/auth.log — repeated "Failed password for root"
      Verdict : TRUE POSITIVE — Block source IP

M-03 | Suspicious Scheduled Task Created
      schtasks.exe /create — task named "WindowsUpdate" (spoofed)
      Evidence: Sysmon EID 1 — binary path C:\Users\Public\malware.exe
      Verdict : TRUE POSITIVE — Escalate

M-04 | Outbound DNS to Suspicious Domain
      DNS query from target to update-checker[.]xyz
      Evidence: No legitimate software installed maps to this domain
      Verdict : TRUE POSITIVE — Block + Investigate

M-05 | Unauthorised Service Installed
      EID 7045 — service "SvcHost32" by non-SYSTEM account
      Evidence: Binary path C:\Users\Public\svchost32.exe
      Verdict : TRUE POSITIVE — Escalate

M-06 | Off-Hours Administrator Login
      EID 4624 — Administrator logon at 02:17 on Sunday
      Evidence: No maintenance window scheduled
      Verdict : Investigated — cross-checked with known lab activity
```

**Low Severity — 4 alerts (all FALSE POSITIVE)**

```
L-01 | Failed Logon — Single Account
      3 failed attempts for "testuser" over 10 minutes
      Reason : Below brute-force threshold — likely mistyped password
      Verdict : FALSE POSITIVE — Closed with justification

L-02 | New Local User Created
      EID 4720 — account "labuser2" created
      Reason : Confirmed planned test account for lab exercise
      Verdict : FALSE POSITIVE — Closed with justification

L-03 | Firewall Rule Modified
      EID 4946 — rule added allowing TCP 8080
      Reason : Confirmed as my own lab configuration change
      Verdict : FALSE POSITIVE — Closed with justification

L-04 | Removable Storage Mounted
      EID 6416 — USB device attached
      Reason : Virtual USB image mounted for file transfer between VMs
      Verdict : FALSE POSITIVE — Closed with justification
```

### 6 — Playbook Execution (SSH Brute-Force — M-02)

```
PLAYBOOK: SSH Brute-Force Response
══════════════════════════════════════════════════════

Step 1  DETECT
        Alert fires — >10 SSH failures in 5 minutes
        Splunk query: index=syslog "Failed password" | stats count by src_ip

Step 2  TRIAGE
        Review auth.log entries
        Confirm: source IP 192.168.56.30, target account root,
        rate: 48 attempts in 2 minutes

Step 3  CLASSIFY
        Single IP + automated rate = brute-force — TRUE POSITIVE

Step 4  CONTAIN
        Block source IP on Ubuntu firewall:
        sudo ufw deny from 192.168.56.30 to any port 22
        sudo ufw status → rule confirmed active

Step 5  VERIFY
        New SSH attempt from 192.168.56.30:
        Connection refused — containment confirmed

Step 6  DOCUMENT
        IOC: 192.168.56.30 — blocked
        Action: UFW rule added — timestamp logged

Step 7  CLOSE
        Alert closed — TRUE POSITIVE — Contained
══════════════════════════════════════════════════════
```

### 7 — Lab Summary

```
┌─────────────────────────────────────────────────┐
│  LAB SUMMARY                                    │
│                                                 │
│  Total Alerts Triaged    :  15                  │
│  High Severity           :   5  (all TRUE POS)  │
│  Medium Severity         :   6  (5 TRUE POS)    │
│  Low Severity            :   4  (all FALSE POS) │
│                                                 │
│  Playbooks Executed      :   8                  │
│  Escalations Raised      :   5                  │
│  False Positive Rate     :  27%                 │
└─────────────────────────────────────────────────┘
```

---

## Key Learning Points

- Confirming an alert fired correctly before investigating prevents wasted time chasing phantom events
- Severity must reflect impact — a single successful admin login at 2am is more critical than 50 failed ones at midday
- Documenting false positives with clear justification is just as important as true positives — it shows analytical reasoning
- Internal source IPs in alerts are often more dangerous than external ones — they are already inside the perimeter
- Playbooks make triage faster and reduce the chance of missing a step

---

## Skills Demonstrated

`VirtualBox` `Lab Design` `Splunk` `Sysmon` `Windows Event Logs` `Linux Syslog` `Alert Triage` `True/False Positive Analysis` `Playbook Execution` `Brute-Force Detection` `Lateral Movement Detection` `Persistence Detection` `Severity Classification` `Escalation Procedure` `nmap` `Metasploit` `Hydra`

---

*Home lab cybersecurity portfolio — [Windows Auth Log Analysis](../windows-auth-log-analysis) | [Phishing Email Investigation](../phishing-email-investigation)*
