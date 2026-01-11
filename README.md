
# Foolish Scan v5.2 (Integrated Edition)
### Context-Aware CTF & Lab Reconnaissance Engine

**Author:** Foolish-admin  
**Co-Author:** Context-Aware AI (Gemini)  
**License:** Authorized Penetration Testing / Lab Use Only  
**Version:** 5.2 (Integrated Edition)

---

## 👋 Introduction
"Hey! I'm **Foolish Scan** (but my friends call me *Foolish*).

You're probably wondering about the name. It's simple: standard scanners are obsessed with being 'thorough' and wasting your time. I'm different. I'm 'foolish' enough to skip the boring stuff and only look for the **Kill Shot**. I don't just list ports; I give you a strategy."

---

## 📖 Overview
**Foolish Scan** is not just a port scanner. It is a **Tactical Strategy Engine** designed for Capture The Flag (CTF) challenges and Offensive Security labs (TryHackMe, HackTheBox, OSCP).

While standard tools report *data*, Foolish Scan reports *strategy*. It uses a modular **Inference Engine** to analyze open ports, banners, and headers, automatically synthesizing a prioritized "Kill Chain" of attack vectors.

**New in v5.0+:** It features an **Interactive Escalation Menu** that allows you to launch deep, targeted Nmap scripts against specific findings without leaving the tool.

---

## ✨ Key Features

* **🧠 The Strategist Engine:** Infers complex attack vectors from subtle clues.
    * *Example:* `Port 7001` Open → Flags **WebLogic T3 Deserialization**.
    * *Example:* `Fuel CMS` in title → Flags **CVE-2018-16763 (RCE)**.
    * *Example:* `Jenkins` header → Checks for **Unsecured Script Console**.
* **🎯 Goal Awareness:** It knows what "Winning" looks like. If it sees a banner like `root@server:~#` or an empty MySQL password, it flags it as **OBJECTIVE ACHIEVED**.
* **⚔️ Interactive Escalation:** After the main scan, it presents a menu of recommended "Deep Nmap Scans" (e.g., `http-tomcat-info` or `smb-vuln-ms17-010`). You choose what to run; the tool handles the execution and parsing.
* **🎨 Integrated UI:** Deep scan results are captured and rendered in beautiful, structured panels directly in the report—no more raw, ugly text dumps.
* **🛡️ Context Safety:** It won't suggest Windows EternalBlue exploits against a Linux Samba server. It knows the OS context.
* **⚡ Single-File Portability:** Zero external configuration files. Pure Python 3. Drop it on a pivot box and run.

---

## 🛠️ Installation

Foolish Scan requires **Python 3** and the **Rich** library for its beautiful console visualization. It depends on **Nmap** being installed on the system.

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

Foolish Scan works best with `sudo` to perform SYN scans and OS fingerprinting.

### Standard Scan (Recommended)

Performs a fast discovery, followed by detailed script scanning, reasoning, and the interactive menu.

```bash
sudo python3 foolish_scan.py <TARGET_IP>

```

### Concurrent Mode

Increase threads for faster scanning (default is 2). Useful for targets with many open ports.

```bash
sudo python3 foolish_scan.py <TARGET_IP> --concurrency 4

```

---

## 🧠 The Inference Logic (How it Thinks)

Foolish Scan divides its findings into logical priority sectors.

### 1. 🏆 Win Conditions (The "Game Over" Sector)

* **Trigger:** Root shells in banners, Empty Admin Passwords, Unauthenticated RCE.
* **Action:** Flags as **CRITICAL / WIN CONDITION**.
* **Examples:** Telnet root shell, Jenkins Script Console (No Auth), vsftpd 2.3.4 Backdoor.

### 2. 🚨 Mandatory Exploits (The "Kill Shots")

* **Trigger:** Specific versions or headers known to be vulnerable to reliable RCE.
* **Action:** Suggests exact exploit paths.
* **Examples:** MS17-010 (EternalBlue), WebLogic T3, Fuel CMS 1.4, Icecast Header Overflow.

### 3. 🕸️ App & Web Intelligence

* **Trigger:** Web technologies and CMS signatures.
* **Action:** Suggests specialized tools.
* **Examples:**
* `Link: .../wp-json/` → Suggests **WordPress API Enumeration**.
* `Server: MiniServ` → Checks **Webmin** version for RCE.
* `Server: Apache-Coyote` → Suggests **Tomcat Manager** brute-force.



### 4. 📂 Infrastructure & Loot

* **Trigger:** File sharing and misconfigurations.
* **Action:** Suggests mounting or downloading.
* **Examples:** NFS Exports, Anonymous FTP with `.pcap` or `.kdbx` files.

---

## 📊 Output Interpretation

The tool produces three main artifacts:

1. **📜 SYSTEM INTELLIGENCE:** Global facts (OS, Hostname, Domain) to help you understand the target environment.
2. **⚔️ ATTACK VECTORS:** Per-port breakdown of what was found, why it matters, and *exactly* what command to run next.
3. **🧭 INTERACTIVE MENU:** A selectable list of deep Nmap scripts to gather more intelligence on high-value targets immediately.

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
