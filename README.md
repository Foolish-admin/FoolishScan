# Foolish Scan v2.3 (Gold Master)
### Context-Aware CTF & Lab Reconnaissance Tool

**Author:** Foolish-admin  
**Co-Author:** Context-Aware AI (Gemini)  
**License:** Authorized Penetration Testing / Lab Use Only  
**Version:** 2.3 (Final Gold Master)

---

## 📖 Overview
**Foolish Scan** is not just a port scanner. It is a **Reasoning Engine** designed for Capture The Flag (CTF) challenges and Offensive Security labs (TryHackMe, HackTheBox, OSCP).

While standard tools like Nmap report *what* is open, Foolish Scan reports *what to do next*. It uses a rule-based **Inference Engine** to analyze open ports, banners, and scripts, automatically synthesizing a prioritized "Kill Chain" of attack vectors.

It is designed to behave like a junior pentester sitting next to you: identifying low-hanging fruit, flagging critical vulnerabilities, and suggesting specific tools for specific technologies.

## ✨ Key Features

* **🧠 Inference Engine:** Analyzes relationships between ports (e.g., "Port 80 + /wp-login" → "Run WPScan").
* **🚨 Critical Vulnerability Promotion:** Automatically detects "VULNERABLE" states in script output (e.g., EternalBlue, Drupalgeddon) and flags them as **CRITICAL**.
* **🛡️ Context-Aware Safety:** Distinguishes between Windows and Linux targets. It will never suggest Windows exploits (like BlueKeep) on a Linux Samba server.
* **🕸️ Web Intelligence:** Detects CMS types (WordPress, Drupal, Joomla) and Login Portals automatically.
* **📂 Infrastructure Logic:** Smart handling of NFS exports (`showmount`), Anonymous FTP loot, and DNS redirection issues.
* **⚡ Single-File Portability:** Zero external configuration files. Pure Python 3. Drop it on a pivot box and run.

---

## 🛠️ Installation

Foolish Scan requires **Python 3** and the **Rich** library for console visualization. It depends on **Nmap** being installed on the system.

```bash
# 1. Install System Dependency
sudo apt update && sudo apt install nmap

# 2. Install Python Dependency
pip3 install rich

# 3. Download/Save the script
# Save the code as foolish_scan.py
chmod +x foolish_scan.py

```

---

## 🚀 Usage

Foolish Scan needs `sudo` to perform SYN scans and OS detection effectively.

### Standard Scan (Recommended)

Performs a fast discovery, followed by detailed script scanning and reasoning.

```bash
sudo python3 foolish_scan.py <TARGET_IP>

```

### Concurrent Mode

Increase threads for faster scanning (default is 2).

```bash
sudo python3 foolish_scan.py <TARGET_IP> --concurrency 4

```

---

## 🧠 The Reasoning Logic (How it Thinks)

Foolish Scan divides its "Brain" into four logical sectors. Understanding this helps you interpret the **"ATTACK PATH SYNTHESIS"** table at the end of the report.

### Sector A: Red Alert (Critical CVEs)

* **Trigger:** Nmap scripts return "State: VULNERABLE".
* **Action:** Promoted to **CRITICAL**.
* **Examples:** MS17-010 (EternalBlue), Drupalgeddon, Shellshock, vsftpd 2.3.4 Backdoor.

### Sector B: Web Intelligence

* **Trigger:** CMS signatures or Login panels found on HTTP ports.
* **Action:** Suggests specialized scanners rather than generic tools.
* **Examples:**
* `wp-login.php` found → Suggests `wpscan`.
* `generator: drupal` found → Suggests `droopescan`.
* Redirect loop / `.local` domain → Suggests editing `/etc/hosts`.



### Sector C: Infrastructure & Loot

* **Trigger:** File sharing protocols or sensitive file extensions.
* **Action:** Suggests enumeration or loot extraction.
* **Examples:**
* Port 2049 Open → Suggests `showmount -e`.
* Anonymous FTP with `.pcap/.kdbx` → Flags "Sensitive Data Exposure".



### Sector D: Context Safety

* **Logic:** Checks OS Family before suggesting OS-specific exploits.
* **Benefit:** Reduces noise. Won't suggest SMB exploits on Linux, won't suggest SSH exploits on Windows unless versions match perfectly.

---

## 📊 Output Interpretation

The tool produces two main sections:

1. **📜 SYSTEM INTELLIGENCE:**
* Global facts about the target (OS, Hostname, Domain, Workgroup).
* Crucial for identifying Domain Controllers or Pivot points.


2. **🧭 ATTACK PATH SYNTHESIS:**
* A prioritized table of *Attack Vectors*.
* **Confidence:** How sure is the tool?
* `Critical`: Confirmed vulnerability.
* `High`: Configuration error or strong signature match.
* `Medium`: Standard enumeration required.
* `Low`: Advisory / Information.





---

## ✍️ Authors

* **Foolish-admin** - *Initial Work, Logic Design, and Testing*
* **Context-Aware AI (Gemini)** - *Code Generation and Reasoning Engine Logic*

---

## ⚠️ Disclaimer

**Authorized Use Only.**
This tool is intended for use in:

1. Authorized Penetration Testing engagements.
2. Academic/Learning environments (CTF, HackTheBox, TryHackMe).
3. Private Home Labs.

Do not use this tool against targets you do not have explicit permission to test.

```

```
