#!/usr/bin/env python3
"""
[One Port, One Report] - Foolish Scan v5.2 (Integrated Edition)
Author: Foolish-admin
Co-Author: Context-Aware AI (Gemini)
License: Authorized Penetration Testing / Lab Use Only
"""
import sys
import os
import shutil
import subprocess
import threading
import argparse
import concurrent.futures
import json
import re
import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum, IntEnum
from datetime import datetime

# --- DEPENDENCY CHECK ---
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.text import Text
    from rich.table import Table
    from rich.prompt import Confirm, Prompt
    from rich.style import Style
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
except ImportError:
    print("[-] Error: 'rich' library not found.")
    print("[-] Please run: pip install rich")
    sys.exit(1)

# --- CONFIGURATION ---
DEFAULT_CONCURRENCY = 2
MAX_PORT_TIMEOUT = 600

# --- DATA MODELS ---

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    OBJECTIVE = "OBJECTIVE ACHIEVED" 

class Priority(IntEnum):
    WIN_CONDITION = 0   
    MANDATORY_EXPL = 1  
    CONFIRMED_VULN = 2  
    CONFIG_WEAKNESS = 3 
    ENUMERATION = 4     
    INFO = 5

class AttackVectorType(str, Enum):
    RCE = "RCE"
    CRED_THEFT = "CREDENTIAL_THEFT"
    ENUMERATION = "DEEP_ENUMERATION"
    MANIPULATION = "MANIPULATION"
    KNOWN_EXPLOIT = "KNOWN_EXPLOIT"
    WEB_ATTACK = "WEB_ATTACK"
    CONFIG_ISSUE = "CONFIG_ISSUE"
    PIVOT = "PIVOT_OPPORTUNITY"
    ACCESS = "IMMEDIATE_ACCESS"

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL (Fail-Safe)"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"

@dataclass
class HostFacts:
    os_family: str = "Unknown"
    os_gen: str = ""
    hostname: str = ""
    domain: str = ""
    workgroup: str = ""
    is_dc: bool = False
    clock_skew: str = ""
    filtered_ports: int = 0

@dataclass
class AttackPath:
    title: str
    vector_type: AttackVectorType
    rationale: str
    command: str
    tool: str
    confidence: str = "Medium"
    priority: Priority = Priority.ENUMERATION

@dataclass
class Service:
    name: str = "unknown"
    product: str = ""
    version: str = ""
    tunnel: str = ""

    def full_banner(self) -> str:
        parts = [p for p in [self.product, self.version] if p]
        if not parts: return self.name
        return f"{self.name} ({' '.join(parts)})"

@dataclass
class Finding:
    title: str
    category: str
    severity: Severity = Severity.INFO
    description: str = ""

@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: Service = field(default_factory=Service)
    findings: List[Finding] = field(default_factory=list)
    attack_paths: List[AttackPath] = field(default_factory=list)
    status: ScanStatus = ScanStatus.PENDING

@dataclass
class Target:
    ip: str
    ports: Dict[int, Port] = field(default_factory=dict)
    facts: HostFacts = field(default_factory=HostFacts)
    discovered_creds: List[str] = field(default_factory=list) 
    
    def add_port(self, number: int) -> Port:
        if number not in self.ports: self.ports[number] = Port(number=number)
        return self.ports[number]

# --- 1. TASK ENGINE ---

class TaskEngine:
    def __init__(self, mode: str = "ctf"):
        self.mode = mode
        self.TIMEOUT_DEFAULT = 300
        self.TIMEOUT_HTTP = 600
        self.TIMEOUT_SMB = 600

        self.RULES = {
            "ftp": { "safe": ["default", "ftp-anon", "ftp-syst", "banner"], "aggr": ["ftp-vsftpd-backdoor", "vulners"], "timeout": self.TIMEOUT_DEFAULT },
            "ssh": { "safe": ["default", "ssh2-enum-algos", "ssh-hostkey", "banner"], "aggr": ["vulners"], "timeout": self.TIMEOUT_DEFAULT },
            "http": { "safe": ["default", "http-title", "http-methods", "http-headers", "http-enum", "http-robots.txt"], "aggr": ["http-vuln-cve*", "http-drupal-enum", "http-wordpress-enum", "http-shellshock", "vulners"], "timeout": self.TIMEOUT_HTTP },
            "smb": { "safe": ["default", "smb-os-discovery", "smb-enum-shares", "smb-protocols", "smb-security-mode"], "aggr": ["smb-vuln*", "vulners"], "timeout": self.TIMEOUT_SMB },
            "dns": { "safe": ["default", "dns-recursion"], "aggr": ["dns-zone-transfer"], "timeout": self.TIMEOUT_DEFAULT },
            "mysql": { "safe": ["default", "mysql-info", "mysql-empty-password"], "aggr": ["vulners"], "timeout": self.TIMEOUT_DEFAULT },
            "rdp": { "safe": ["default", "rdp-enum-encryption", "rdp-ntlm-info"], "aggr": ["rdp-vuln-bluekeep"], "timeout": self.TIMEOUT_DEFAULT },
            "nfs": { "safe": ["default", "nfs-showmount", "nfs-ls"], "aggr": [], "timeout": self.TIMEOUT_DEFAULT },
            "snmp": { "safe": ["default", "snmp-interfaces", "snmp-processes", "snmp-netstat"], "aggr": ["snmp-brute"], "timeout": self.TIMEOUT_DEFAULT },
            "pop3": { "safe": ["default", "pop3-capabilities", "pop3-ntlm-info"], "aggr": [], "timeout": self.TIMEOUT_DEFAULT },
            "imap": { "safe": ["default", "imap-capabilities", "imap-ntlm-info"], "aggr": [], "timeout": self.TIMEOUT_DEFAULT }
        }

    def _infer_service(self, port: int) -> str:
        p = int(port)
        if p in [80, 443, 8080, 8000, 8443]: return "http"
        if p == 445: return "smb"
        if p == 21: return "ftp"
        if p == 22: return "ssh"
        if p == 2049: return "nfs"
        if p == 3306: return "mysql"
        if p == 3389: return "rdp"
        if p == 161: return "snmp"
        if p in [110, 995]: return "pop3"
        if p in [143, 993]: return "imap"
        return "default"

    def get_task(self, port: int, service_name: str = "unknown", retry_mode: bool = False) -> dict:
        if retry_mode:
            return {"port": port, "service": "fail_safe", "scripts": "default,banner,version", "timeout": self.TIMEOUT_DEFAULT + 60}

        svc = service_name.lower()
        rule_key = "default"

        if "http" in svc or "apache" in svc or "nginx" in svc: rule_key = "http"
        elif "microsoft-ds" in svc or "smb" in svc: rule_key = "smb"
        elif "ftp" in svc: rule_key = "ftp"
        elif "ssh" in svc: rule_key = "ssh"
        elif "nfs" in svc: rule_key = "nfs"
        elif "mysql" in svc: rule_key = "mysql"
        elif "rdp" in svc: rule_key = "rdp"
        elif "snmp" in svc: rule_key = "snmp"
        elif "pop3" in svc: rule_key = "pop3"
        elif "imap" in svc: rule_key = "imap"
        elif svc in self.RULES: rule_key = svc
        elif svc == "unknown": rule_key = self._infer_service(port)

        scripts = ["default", "banner", "version"]
        timeout = self.TIMEOUT_DEFAULT
        
        if rule_key in self.RULES:
            rule = self.RULES[rule_key]
            scripts = rule["safe"] + (rule["aggr"] if self.mode == "ctf" else [])
            timeout = rule.get("timeout", self.TIMEOUT_DEFAULT)

        return {"port": port, "service": rule_key, "scripts": ",".join(list(set(scripts))), "timeout": timeout}

# --- 2. FACT NORMALIZATION ---

class FactNormalizer:
    def normalize(self, target: Target):
        self._infer_os(target)
        self._infer_role(target)

    def _infer_os(self, target: Target):
        if target.facts.os_family == "Unknown":
            for p in target.ports.values():
                banner = p.service.full_banner().lower()
                if "windows" in banner or "microsoft" in banner: target.facts.os_family = "Windows"
                elif "ubuntu" in banner or "debian" in banner or "linux" in banner: target.facts.os_family = "Linux"
                
                if "windows 7" in banner: target.facts.os_gen = "7"
                elif "server 2008" in banner: target.facts.os_gen = "2008"
                elif "server 2012" in banner: target.facts.os_gen = "2012"
                elif "server 2016" in banner: target.facts.os_gen = "2016"
                elif "windows 10" in banner: target.facts.os_gen = "10"

    def _infer_role(self, target: Target):
        if 88 in target.ports and 445 in target.ports:
            target.facts.is_dc = True

# --- 3. INFERENCE ENGINE (The Strategist) ---

class InferenceEngine:
    def analyze(self, target: Target):
        for port_num, port in target.ports.items():
            self._analyze_port(target, port)
        self._analyze_cross_protocol(target)

    def _analyze_port(self, target: Target, port: Port):
        svc = port.service.name.lower()
        prod = port.service.product.lower()
        f_dump = " ".join([f"{f.title} {f.description}" for f in port.findings]).lower()

        # --- SECTOR 1: GOAL AWARENESS ---
        if "root@" in f_dump or "uid=0" in f_dump or "#" in port.service.full_banner():
            port.attack_paths.append(AttackPath("ROOT SHELL DETECTED", AttackVectorType.ACCESS, "Banner indicates a root shell is already open.", f"nc {target.ip} {port.number}", "Netcat", "Critical", Priority.WIN_CONDITION))
            return 

        if "empty password" in f_dump and ("root" in f_dump or "admin" in f_dump):
            port.attack_paths.append(AttackPath("Empty Administrative Password", AttackVectorType.ACCESS, "Account allows login with no password.", f"mysql -u root -h {target.ip}", "Client", "Critical", Priority.WIN_CONDITION))

        # --- SECTOR 2: MANDATORY CONTEXT & EXPLOITS ---
        if (port.number == 445 or "smb" in svc) and target.facts.os_family == "Windows":
            if any(x in target.facts.os_gen for x in ["7", "2008", "vista"]):
                port.attack_paths.append(AttackPath("Legacy Windows Exploit (EternalBlue)", AttackVectorType.KNOWN_EXPLOIT, f"OS Context ({target.facts.os_gen}) implies high MS17-010 risk.", f"nmap --script smb-vuln-ms17-010 -p {port.number} {target.ip}", "Nmap", "Critical", Priority.MANDATORY_EXPL))

        if port.number == 7001 or "weblogic" in prod:
            port.attack_paths.append(AttackPath("WebLogic T3 Deserialization", AttackVectorType.KNOWN_EXPLOIT, "WebLogic port detected. T3 protocol often vulnerable.", f"nmap --script weblogic-t3-info -p {port.number} {target.ip}", "Nmap", "Critical", Priority.MANDATORY_EXPL))

        if "miniserv" in f_dump or "miniserv" in prod:
            port.attack_paths.append(AttackPath("Webmin MiniServ Vulnerability", AttackVectorType.KNOWN_EXPLOIT, "Webmin detected. Check for Unauth RCE (CVE-2019-15107).", f"nmap --script http-vuln-cve2019-15107 -p {port.number} {target.ip}", "Nmap", "High", Priority.MANDATORY_EXPL))

        # --- SECTOR 3: CMS INTELLIGENCE ---
        if "http" in svc or port.number in [80, 443, 8080, 8443, 8000, 8180]:
            if "wordpress" in f_dump or "wp-login" in f_dump or "wp-json" in f_dump:
                if "wp-json" in f_dump:
                    port.attack_paths.append(AttackPath("WordPress API User Enum", AttackVectorType.ENUMERATION, "REST API exposed. Enumerate users quietly.", f"nmap --script http-wordpress-users -p {port.number} {target.ip}", "Nmap", "High", Priority.CONFIRMED_VULN))
                port.attack_paths.append(AttackPath("WordPress Detected", AttackVectorType.WEB_ATTACK, "WordPress signature found.", f"wpscan --url http://{target.ip}:{port.number}", "WPScan", "High", Priority.CONFIRMED_VULN))

            if "drupal" in f_dump:
                port.attack_paths.append(AttackPath("Drupal Detected", AttackVectorType.WEB_ATTACK, "Drupal signature found.", f"droopescan scan drupal -u http://{target.ip}:{port.number}", "Droopescan", "High", Priority.CONFIRMED_VULN))

            if "bolt" in f_dump or "bolt" in prod:
                port.attack_paths.append(AttackPath("Bolt CMS Detected", AttackVectorType.KNOWN_EXPLOIT, "Bolt CMS signature found.", "searchsploit bolt cms", "ExploitDB", "High", Priority.CONFIRMED_VULN))

            if "fuel" in f_dump:
                port.attack_paths.append(AttackPath("Fuel CMS Detected", AttackVectorType.KNOWN_EXPLOIT, "Fuel CMS detected. Check for CVE-2018-16763 RCE.", "searchsploit fuel cms", "ExploitDB", "High", Priority.MANDATORY_EXPL))

            # [FIXED] Updated Tomcat Scripts to standard ones
            if "apache-coyote" in f_dump or "tomcat" in prod:
                port.attack_paths.append(AttackPath("Apache Tomcat Manager", AttackVectorType.CRED_THEFT, "Tomcat detected. Check for default creds/AJP.", f"nmap --script http-tomcat-info,ajp-auth -p {port.number} {target.ip}", "Nmap", "High", Priority.CONFIG_WEAKNESS))

            if any(x in f_dump for x in ["login", "admin", "signin", "wp-login", "auth"]):
                port.attack_paths.append(AttackPath("Login Portal Detected", AttackVectorType.CRED_THEFT, "Authentication endpoint exposed.", f"Go to http://{target.ip}:{port.number}", "Browser", "High", Priority.CONFIG_WEAKNESS))

            port.attack_paths.append(AttackPath("Web Directory Enumeration", AttackVectorType.ENUMERATION, "Web service detected.", f"gobuster dir -u http://{target.ip}:{port.number} -w common.txt", "Gobuster", "Medium", Priority.ENUMERATION))

        # --- SECTOR 4: FILE & AUTH SERVICES ---
        if "ftp" in svc:
            if "anonymous ftp login allowed" in f_dump:
                port.attack_paths.append(AttackPath("Anonymous FTP Access", AttackVectorType.ENUMERATION, "Read-only access found.", f"ftp {target.ip}", "FTP", "High", Priority.CONFIG_WEAKNESS))
                if any(ext in f_dump for ext in [".pcap", ".kdbx", ".conf", ".rsa", "id_rsa", ".txt", ".bak", ".php"]):
                    port.attack_paths.append(AttackPath("Sensitive Data Exposure", AttackVectorType.CRED_THEFT, "Sensitive file extensions detected in FTP listing.", f"wget -r ftp://{target.ip}", "Wget", "Critical", Priority.MANDATORY_EXPL))

        if port.number in [445, 139] or "smb" in svc:
            port.attack_paths.append(AttackPath("SMB Null Session", AttackVectorType.ENUMERATION, "Attempt list shares.", f"smbclient -L //{target.ip} -N", "smbclient", "Medium", Priority.ENUMERATION))

        if "nfs" in svc or port.number == 2049:
            port.attack_paths.append(AttackPath("NFS Export Enumeration", AttackVectorType.ENUMERATION, "NFS Service detected.", f"showmount -e {target.ip}", "System Client", "High", Priority.CONFIG_WEAKNESS))

    def _analyze_cross_protocol(self, target: Target):
        if target.discovered_creds:
            creds_str = ", ".join(target.discovered_creds)
            for port in target.ports.values():
                if port.number == 22:
                    port.attack_paths.append(AttackPath("Credential Reuse (SSH)", AttackVectorType.CRED_THEFT, f"Try known creds ({creds_str}) on SSH.", "hydra...", "Hydra", "High", Priority.CONFIRMED_VULN))

# --- 4. DEEP PARSER ---

class NmapParser:
    def __init__(self):
        self.BAD_VERSIONS = {
            "vsftpd 2.3.4": ("CVE-2011-2523", "Backdoor Command Execution"),
            "ProFTPD 1.3.1": ("CVE-2010-4221", "Stack Overflow"),
            "Samba 3.0.20": ("CVE-2007-2447", "Username Map Script RCE"),
        }

    def parse(self, xml_content: str, target: Target, is_partial: bool):
        if not xml_content or "TIMEOUT" in xml_content or "ERROR" in xml_content: return

        try:
            root = ET.fromstring(xml_content)
            
            for extra in root.findall(".//extraports"):
                if extra.get("state") == "filtered":
                    count = int(extra.get("count", 0))
                    target.facts.filtered_ports += count

            for script in root.findall(".//hostscript/script"):
                sid = script.get("id", "")
                output = script.get("output", "").strip()
                if "smb" in sid or "nbstat" in sid:
                    self._attach_to_port(target, [445, 139], sid, output, "SYSTEM")
                    if "os-discovery" in sid: self._extract_os_facts(output, target)
                elif "rdp" in sid:
                    self._attach_to_port(target, [3389], sid, output, "SYSTEM")
                elif "clock" in sid:
                    target.facts.clock_skew = output.splitlines()[0] if output else "Unknown"

            for port_elem in root.findall(".//port"):
                pid = int(port_elem.get("portid"))
                if pid not in target.ports: continue
                
                port = target.ports[pid]
                port.status = ScanStatus.PARTIAL if is_partial else ScanStatus.COMPLETE

                svc = port_elem.find("service")
                if svc is not None:
                    port.service.name = svc.get("name", "unknown")
                    port.service.product = svc.get("product", "")
                    port.service.version = svc.get("version", "")
                    port.service.tunnel = svc.get("tunnel", "")

                full_ver = f"{port.service.product} {port.service.version}".strip()
                for bad_ver, (cve, desc) in self.BAD_VERSIONS.items():
                    if bad_ver in full_ver:
                        port.findings.append(Finding(f"{cve} (Version Match)", "VULN", Severity.CRITICAL, desc))

                for script in port_elem.findall("script") + port_elem.findall("service/script"):
                    sid = script.get("id", "")
                    out = script.get("output", "").strip()
                    if out: self._create_finding(port, sid, out)

        except ET.ParseError: pass

    def _attach_to_port(self, target: Target, port_list: List[int], title: str, output: str, cat: str):
        for pid in port_list:
            if pid in target.ports:
                target.ports[pid].findings.append(Finding(title, cat, Severity.INFO, output))

    def _extract_os_facts(self, output: str, target: Target):
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("OS:"):
                target.facts.os_family = "Windows"
                raw_gen = line.replace("OS:", "").strip()
                if raw_gen.lower().startswith("windows"): 
                    raw_gen = raw_gen[7:].strip()
                target.facts.os_gen = raw_gen
            elif line.startswith("Computer name:"):
                target.facts.hostname = line.replace("Computer name:", "").strip()
            elif line.startswith("Workgroup:"):
                target.facts.workgroup = line.replace("Workgroup:", "").strip()
            elif line.startswith("Domain name:"):
                target.facts.domain = line.replace("Domain name:", "").strip()

    def _create_finding(self, port: Port, title: str, output: str):
        category = "ENUM"
        severity = Severity.INFO
        t_lower = title.lower()
        o_upper = output.upper()

        if "vuln" in t_lower or "cve-" in t_lower:
            category = "VULN"
            severity = Severity.HIGH
            if "vulners" in t_lower:
                lines = output.splitlines()
                filtered = [l for l in lines if "* CVE" in l or "CVE-" in l]
                output = "\n".join(filtered[:5]) if filtered else output[:200]
            if "VULNERABLE" in o_upper: severity = Severity.CRITICAL
        elif "ftp-anon" in t_lower and "ALLOWED" in o_upper:
            category = "AUTH"
            severity = Severity.CRITICAL
        elif "smb-security-mode" in t_lower:
            category = "CONFIG"
            severity = Severity.MEDIUM if "DISABLED" in o_upper else Severity.INFO

        port.findings.append(Finding(title, category, severity, output))

# --- 5. SCANNER ---

class Scanner:
    def __init__(self, target_ip: str, engine: TaskEngine, concurrency: int = 2):
        self.target = target_ip
        self.engine = engine
        self.concurrency = concurrency
        self.console = Console()

    def scan_discovery(self) -> List[Tuple[int, str]]:
        self.console.print("[dim][*] Attempting standard discovery (Ping enabled)...[/dim]")
        cmd = ["nmap", "-sS", "-p-", "--min-rate", "1000", "-T4", "-n", "-oX", "-", self.target]
        if os.geteuid() != 0: cmd[1] = "-sT"

        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            if "Host seems down" in result.stdout or not result.stdout.strip():
                self.console.print("[yellow][!] Target blocked ping. Switching to -Pn (Firewall Bypass)...[/yellow]")
                cmd.insert(1, "-Pn")
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            return self._parse_discovery(result.stdout)
        except Exception:
            return []

    def _parse_discovery(self, xml_data: str) -> List[Tuple[int, str]]:
        ports = []
        try:
            root = ET.fromstring(xml_data)
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    pid = int(port.get("portid"))
                    svc_tag = port.find("service")
                    svc_name = svc_tag.get("name") if svc_tag is not None else "unknown"
                    ports.append((pid, svc_name))
        except ET.ParseError: pass
        return sorted(ports, key=lambda x: x[0])

    def scan_port(self, port: Port) -> str:
        task = self.engine.get_task(port.number, port.service.name, retry_mode=False)
        xml_out = self._run_nmap(task)
        if "TIMEOUT" in xml_out or "ERROR" in xml_out or not xml_out:
            task = self.engine.get_task(port.number, port.service.name, retry_mode=True)
            return self._run_nmap(task)
        return xml_out

    def _run_nmap(self, task: dict) -> str:
        cmd = ["nmap", "-sV", "--version-all", "-Pn", "-p", str(task["port"]), "--script", task["scripts"], "-oX", "-", self.target]
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            stdout, _ = process.communicate(timeout=task["timeout"])
            return stdout
        except subprocess.TimeoutExpired:
            process.kill()
            return "TIMEOUT"
        except Exception as e:
            return f"ERROR: {str(e)}"

# --- 6. REPORTER (Classic Table) ---

class Reporter:
    def __init__(self):
        self.console = Console()
        self.lock = threading.Lock()
        self.attack_vectors: List[Tuple[int, AttackPath]] = []

    def print_system_intelligence(self, target: Target):
        facts = target.facts
        firewall_msg = ""
        if facts.filtered_ports > 100:
            firewall_msg = f"\n[bold red]⚠️  FIREWALL DETECTED:[/bold red] {facts.filtered_ports} filtered ports found."

        grid = Table.grid(padding=1)
        grid.add_column(style="cyan", justify="right")
        grid.add_column(style="white")
        
        if facts.os_family != "Unknown": grid.add_row("OS Family:", f"{facts.os_family} {facts.os_gen}")
        if facts.hostname: grid.add_row("Hostname:", facts.hostname)
        if facts.workgroup: grid.add_row("Workgroup:", facts.workgroup)
        if facts.domain: grid.add_row("Domain:", facts.domain)
        if facts.is_dc: grid.add_row("Role:", "[bold red]DOMAIN CONTROLLER[/bold red]")
        
        self.console.print(Panel(grid, title="[bold blue]📜 SYSTEM INTELLIGENCE[/bold blue]", border_style="blue", expand=False))
        if firewall_msg: self.console.print(firewall_msg)
        self.console.print("")

    def print_port(self, port: Port):
        with self.lock:
            style = "bold white"
            if port.status == ScanStatus.PARTIAL: style = "dim white"
            elif any(f.severity == Severity.CRITICAL for f in port.findings): style = "bold red"

            status_str = " [FAIL-SAFE MODE]" if port.status == ScanStatus.PARTIAL else ""
            header = f"PORT {port.number}/{port.protocol.upper()} — {port.service.full_banner()}{status_str}"
            root = Tree(f"[{style}]{header}[/{style}]")

            for f in port.findings:
                f_style = "red blink" if f.severity == Severity.CRITICAL else "white"
                lines = f.description.splitlines() if f.description else []
                preview = lines[0] if lines else "See report"
                node = root.add(f"[{f_style}]{f.title}[/{f_style}]: [dim]{preview}[/dim]")
                if len(lines) > 1: node.add(Text("\n".join(lines[1:]), style="dim cyan"))

            if port.attack_paths:
                v_branch = root.add("[bold yellow]⚔️ ATTACK VECTORS[/bold yellow]")
                for path in port.attack_paths:
                    if (port.number, path) not in self.attack_vectors:
                        self.attack_vectors.append((port.number, path))
                    # Distinguish between Nmap automated suggestions and Manual ideas
                    if path.command.startswith("nmap"):
                        v_branch.add(f"[cyan]Suggested Deep Nmap Scan:[/cyan] [white]{path.title}[/white]")
                    else:
                        v_branch.add(f"[yellow]{path.title}[/yellow] -> [italic white]{path.command}[/italic white]")

            self.console.print(Panel(root, border_style="blue", expand=False))
            self.console.print("")

    def print_summary(self):
        if not self.attack_vectors: return
        sorted_vectors = sorted(self.attack_vectors, key=lambda x: x[0])

        self.console.print("\n[bold yellow]=== 🧭 ATTACK PATH SYNTHESIS ===[/bold yellow]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Port", style="cyan")
        table.add_column("Confidence")
        table.add_column("Vector", style="white")
        table.add_column("Rationale", style="dim white")
        
        seen_vectors = set()
        for p, path in sorted_vectors:
            unique_key = (p, path.title)
            if unique_key in seen_vectors: continue
            seen_vectors.add(unique_key)

            c_style = "red" if path.confidence == "Critical" else "green"
            if path.confidence == "High": c_style = "yellow"
            table.add_row(str(p), f"[{c_style}]{path.confidence}[/{c_style}]", path.title, path.rationale)
        self.console.print(table)
        self.console.print("")

    def save_report(self, target: Target):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"foolish_scan_{target.ip}_{ts}.json"
        txt_file = f"foolish_scan_{target.ip}_{ts}.txt"

        data = {"target": target.ip, "facts": asdict(target.facts), "ports": {p: asdict(target.ports[p]) for p in target.ports}}
        with open(json_file, "w") as f: json.dump(data, f, indent=4, default=str)

        with open(txt_file, "w") as f:
            f.write(f"Foolish Scan v5.2 Report - Target: {target.ip}\n")
            f.write(f"OS: {target.facts.os_family} {target.facts.os_gen}\n")
            f.write("="*50 + "\n\n")
            for pid, port in target.ports.items():
                f.write(f"PORT {pid} ({port.service.name})\n")
                f.write(f"  Banner: {port.service.full_banner()}\n")
                for finding in port.findings:
                    f.write(f"  [{finding.severity}] {finding.title}\n")
                    for line in finding.description.splitlines(): f.write(f"      {line}\n")
                if port.attack_paths:
                    f.write("  [Attack Vectors]\n")
                    for a in port.attack_paths: f.write(f"      - {a.title}: {a.command}\n")
                f.write("\n" + "-"*30 + "\n\n")
        self.console.print(f"[bold green][✓] Reports saved: {json_file}, {txt_file}[/bold green]")

    def get_attack_vectors(self):
        return sorted(self.attack_vectors, key=lambda x: x[0])

# --- 7. INTERACTIVE MENU ---

class TimeEstimator:
    @staticmethod
    def estimate(cmd: str) -> str:
        cmd = cmd.lower()
        if "nmap" in cmd and "script" in cmd: return "~2-5 mins"
        return "Unknown"

class InteractiveMenu:
    def __init__(self, console: Console, attack_vectors: List[Tuple[int, AttackPath]], target_obj: Target, parser: NmapParser, reporter: Reporter):
        self.console = console
        self.vectors = attack_vectors
        self.target = target_obj
        self.parser = parser
        self.reporter = reporter

    def run(self):
        if not self.vectors: return

        # Filter strictly for Nmap commands
        runnable_options = []
        seen = set()
        for idx, (port, path) in enumerate(self.vectors):
            if path.command.startswith("nmap"):
                if (port, path.title) not in seen:
                    runnable_options.append((port, path))
                    seen.add((port, path.title))

        if not runnable_options:
            return

        while True:
            self.console.print("\n[bold yellow]=== 🧭 NMAP INTELLIGENCE ESCALATION ===[/bold yellow]")
            self.console.print("[dim]Select an optional Nmap deep scan to gather more information.[/dim]\n")
            
            for i, (port, path) in enumerate(runnable_options):
                cmd = path.command
                idx_str = f"[bold cyan][{i + 1}][/bold cyan]"
                time_est = f"[dim]({TimeEstimator.estimate(cmd)})[/dim]"
                
                self.console.print(f"{idx_str} Port {port}: [bold white]{path.title}[/bold white] {time_est}")
                self.console.print(f"    └── Cmd: [green]{cmd}[/green]")

            self.console.print("\n[bold cyan][Enter][/bold cyan] Exit without running additional scans")
            
            choice = Prompt.ask("\n[?] Select option(s) to execute (e.g. 1, 3) or [Enter] to exit", default="").strip().lower()
            
            if choice == "" or choice == 'e':
                break
            
            self.console.print(f"[>] You selected: {choice}")

            # Parse selections
            selections = [s.strip() for s in re.split(r'[,\s]+', choice) if s.strip().isdigit()]
            
            for sel in selections:
                sel_idx = int(sel)
                if 1 <= sel_idx <= len(runnable_options):
                    port_num, path = runnable_options[sel_idx - 1]
                    target_cmd = path.command
                    
                    self.console.print(f"\n[bold green][*] Launching Deep Scan on Port {port_num}...[/bold green]")
                    
                    # [UI UPDATE] Capture XML instead of showing raw output
                    try:
                        # Ensure we request XML output
                        parts = shlex.split(target_cmd)
                        # Remove existing -oX or output files if present to avoid conflict (naive check)
                        if "-oX" not in parts:
                            parts.extend(["-oX", "-"])
                        
                        process = subprocess.Popen(parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[progress.description]{task.description}"),
                            TimeElapsedColumn(),
                            console=self.console
                        ) as progress:
                            task = progress.add_task(f"[cyan]Scanning Port {port_num}...[/cyan]", total=None)
                            stdout, stderr = process.communicate()
                        
                        if stdout and "<?xml" in stdout:
                            # Reprocess the output
                            self.parser.parse(stdout, self.target, is_partial=False)
                            # Reprint the specific port panel with new findings
                            self.console.print(f"\n[bold green][✓] Updated Intelligence for Port {port_num}:[/bold green]")
                            self.reporter.print_port(self.target.ports[port_num])
                        else:
                            self.console.print(f"[yellow][!] No structured data returned. Raw Output:[/yellow]\n{stdout}")
                            if stderr: self.console.print(f"[red]{stderr}[/red]")

                    except Exception as e:
                        self.console.print(f"[red][!] Execution failed: {e}[/red]")
                    
                    Prompt.ask("\nPress Enter to return to menu...")
                else:
                    self.console.print(f"[red][!] Invalid option: {sel}[/red]")

# --- MAIN ---

def main():
    parser = argparse.ArgumentParser(description="Foolish Scan v5.2 (Integrated Edition)")
    parser.add_argument("target", help="Target IP")
    parser.add_argument("--mode", choices=["fast", "ctf"], default="ctf")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    args = parser.parse_args()

    if not shutil.which("nmap"):
        print("[-] Error: Nmap not found.")
        sys.exit(1)

    console = Console()
    console.print(f"[bold green][*] Starting Foolish Scan v5.2 against {args.target}[/bold green]")

    engine = TaskEngine(args.mode)
    scanner = Scanner(args.target, engine, args.concurrency)
    xml_parser = NmapParser()
    normalizer = FactNormalizer()
    inference = InferenceEngine()
    reporter = Reporter()
    target_obj = Target(args.target)

    # Phase 1: Discovery
    with console.status("[bold blue]Phase 1: Discovery Scan...[/bold blue]"):
        discovered = scanner.scan_discovery()

    if not discovered:
        console.print("[red][!] No open ports found. Exiting.[/red]")
        sys.exit(0)

    formatted_ports = [f"{p}/{s}" for p, s in discovered]
    console.print(f"[+] Found {len(discovered)} open ports: {', '.join(formatted_ports)}\n")
    
    for p, s in discovered: 
        port = target_obj.add_port(p)
        if s != "unknown": port.service.name = s

    # Phase 2: Deep Scan
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} Ports"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task_id = progress.add_task("[cyan]Deep Scanning Ports...[/cyan]", total=len(discovered))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                future_to_port = {executor.submit(scanner.scan_port, target_obj.ports[p]): target_obj.ports[p] for p, s in discovered}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        progress.update(task_id, advance=1, description=f"[cyan]Deep Scanning... (Finished Port {port.number})[/cyan]")
                        xml_data = future.result()
                        is_partial = "fail_safe" in str(xml_data).lower()
                        xml_parser.parse(xml_data, target_obj, is_partial)
                    except Exception as e:
                        console.print(f"[red][!] Logic Error Port {port.number}: {e}[/red]")
    except KeyboardInterrupt:
        sys.exit(1)

    # Phase 3: Logic & Reporting
    normalizer.normalize(target_obj)
    inference.analyze(target_obj)

    reporter.print_system_intelligence(target_obj)
    for p in sorted(target_obj.ports):
        reporter.print_port(target_obj.ports[p])
    
    reporter.print_summary()
    
    # Phase 4: Interactive Escalation (New v5.2 Feature - UI Integrated)
    vectors = reporter.get_attack_vectors()
    if vectors:
        # Pass dependencies to menu so it can parse/print results
        menu = InteractiveMenu(console, vectors, target_obj, xml_parser, reporter)
        menu.run()

    console.print("")

    if Confirm.ask("[?] Do you want to save the report?(y/N)", default=False, show_default=False,   show_choices=False):
        reporter.save_report(target_obj)
    
    console.print("[bold green][✓] Scan Complete.[/bold green]")

if __name__ == "__main__":
    main()
