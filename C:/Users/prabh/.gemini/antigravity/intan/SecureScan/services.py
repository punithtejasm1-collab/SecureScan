"""
SecureScan - Service Detection & Vulnerability Recommendation Engine
"""

COMMON_SERVICES = {
    20: {"name": "FTP-Data", "protocol": "TCP", "risk": "Low", "desc": "File Transfer Protocol (Data Transfer)"},
    21: {"name": "FTP", "protocol": "TCP", "risk": "Medium", "desc": "File Transfer Protocol (Control)"},
    22: {"name": "SSH", "protocol": "TCP", "risk": "Low", "desc": "Secure Shell Remote Access"},
    23: {"name": "Telnet", "protocol": "TCP", "risk": "High", "desc": "Unencrypted Telnet Text Communications"},
    25: {"name": "SMTP", "protocol": "TCP", "risk": "Medium", "desc": "Simple Mail Transfer Protocol"},
    53: {"name": "DNS", "protocol": "TCP/UDP", "risk": "Low", "desc": "Domain Name System Domain Resolution"},
    67: {"name": "DHCP", "protocol": "UDP", "risk": "Low", "desc": "DHCP Server"},
    68: {"name": "DHCP", "protocol": "UDP", "risk": "Low", "desc": "DHCP Client"},
    69: {"name": "TFTP", "protocol": "UDP", "risk": "High", "desc": "Trivial File Transfer Protocol (No Auth)"},
    80: {"name": "HTTP", "protocol": "TCP", "risk": "Low", "desc": "Hypertext Transfer Protocol (Web)"},
    110: {"name": "POP3", "protocol": "TCP", "risk": "Medium", "desc": "Post Office Protocol v3"},
    111: {"name": "RPCBIND", "protocol": "TCP/UDP", "risk": "Medium", "desc": "SUN Remote Procedure Call"},
    123: {"name": "NTP", "protocol": "UDP", "risk": "Low", "desc": "Network Time Protocol"},
    135: {"name": "MSRPC", "protocol": "TCP", "risk": "Medium", "desc": "Microsoft RPC Endpoint Mapper"},
    137: {"name": "NetBIOS-NS", "protocol": "UDP", "risk": "Medium", "desc": "NetBIOS Name Service"},
    138: {"name": "NetBIOS-DGM", "protocol": "UDP", "risk": "Medium", "desc": "NetBIOS Datagram Service"},
    139: {"name": "NetBIOS-SSN", "protocol": "TCP", "risk": "Medium", "desc": "NetBIOS Session Service"},
    143: {"name": "IMAP", "protocol": "TCP", "risk": "Medium", "desc": "Internet Message Access Protocol"},
    161: {"name": "SNMP", "protocol": "UDP", "risk": "Medium", "desc": "Simple Network Management Protocol"},
    389: {"name": "LDAP", "protocol": "TCP", "risk": "Medium", "desc": "Lightweight Directory Access Protocol"},
    443: {"name": "HTTPS", "protocol": "TCP", "risk": "Info", "desc": "Secure Hypertext Transfer Protocol"},
    445: {"name": "SMB", "protocol": "TCP", "risk": "Critical", "desc": "Microsoft Directory Services / SMB File Share"},
    465: {"name": "SMTPS", "protocol": "TCP", "risk": "Low", "desc": "Secure SMTP Mail"},
    514: {"name": "Syslog", "protocol": "UDP", "risk": "Low", "desc": "Syslog Event Logging"},
    587: {"name": "SMTP Submission", "protocol": "TCP", "risk": "Low", "desc": "Authenticated Mail Submission"},
    993: {"name": "IMAPS", "protocol": "TCP", "risk": "Low", "desc": "Encrypted IMAP Email"},
    995: {"name": "POP3S", "protocol": "TCP", "risk": "Low", "desc": "Encrypted POP3 Email"},
    1433: {"name": "MSSQL", "protocol": "TCP", "risk": "High", "desc": "Microsoft SQL Server Database"},
    1521: {"name": "Oracle DB", "protocol": "TCP", "risk": "High", "desc": "Oracle Database Listener"},
    2049: {"name": "NFS", "protocol": "TCP/UDP", "risk": "High", "desc": "Network File System Share"},
    3306: {"name": "MySQL", "protocol": "TCP", "risk": "High", "desc": "MySQL Relational Database"},
    3389: {"name": "RDP", "protocol": "TCP", "risk": "Critical", "desc": "Remote Desktop Protocol"},
    5432: {"name": "PostgreSQL", "protocol": "TCP", "risk": "High", "desc": "PostgreSQL Relational Database"},
    5900: {"name": "VNC", "protocol": "TCP", "risk": "High", "desc": "Virtual Network Computing Remote Desktop"},
    6379: {"name": "Redis", "protocol": "TCP", "risk": "High", "desc": "Redis In-Memory Key-Value Store"},
    8080: {"name": "HTTP-Proxy", "protocol": "TCP", "risk": "Low", "desc": "HTTP Alternate / Proxy Web Server"},
    8443: {"name": "HTTPS-Alt", "protocol": "TCP", "risk": "Low", "desc": "HTTPS Alternate Web Server"},
    9000: {"name": "SonarQube / Web", "protocol": "TCP", "risk": "Medium", "desc": "SonarQube Code Quality / PHP-FPM Service"},
    9200: {"name": "Elasticsearch", "protocol": "TCP", "risk": "High", "desc": "Elasticsearch REST API"},
    27017: {"name": "MongoDB", "protocol": "TCP", "risk": "High", "desc": "MongoDB NoSQL Database Engine"}
}

SECURITY_RECOMMENDATIONS = {
    21: {
        "title": "FTP Service Exposed (Port 21)",
        "severity": "Medium",
        "impact": "FTP transmits credentials and data in cleartext across the network.",
        "action": "Disable unencrypted FTP and replace it with SFTP (Port 22) or FTPS."
    },
    22: {
        "title": "SSH Publicly Accessible (Port 22)",
        "severity": "Low",
        "impact": "Standard target for automated password brute-force and credential stuffing attacks.",
        "action": "Enforce SSH Key authentication, change default port 22, and restrict IP ranges via firewall or Fail2ban."
    },
    23: {
        "title": "CRITICAL: Unencrypted Telnet Active (Port 23)",
        "severity": "High",
        "impact": "Telnet passes usernames and passwords in plain text, enabling trivial packet sniffing.",
        "action": "Disable Telnet service completely and migrate all remote administration to SSH."
    },
    25: {
        "title": "SMTP Mail Relay Exposed (Port 25)",
        "severity": "Medium",
        "impact": "Unsecured mail servers can be leveraged as open relays for spam distribution.",
        "action": "Ensure SMTP authentication is strictly required and disable open relay capabilities."
    },
    69: {
        "title": "TFTP Service Detected (Port 69)",
        "severity": "High",
        "impact": "TFTP lacks authentication mechanisms, allowing unauthorized file downloads.",
        "action": "Restrict TFTP access to trusted local management VLANs or disable if unused."
    },
    445: {
        "title": "CRITICAL: Microsoft SMB Share Exposed (Port 445)",
        "severity": "Critical",
        "impact": "Exposed SMB services are prime targets for ransomware (e.g. WannaCry, EternalBlue exploits).",
        "action": "Block Port 445 on external WAN firewalls immediately and restrict SMB to internal subnets."
    },
    1433: {
        "title": "MSSQL Database Listening (Port 1433)",
        "severity": "High",
        "impact": "Direct database exposure increases vulnerability to SQL injection and dictionary attacks.",
        "action": "Bind MSSQL to localhost (127.0.0.1) or restrict access through a secure VPN tunnel."
    },
    3306: {
        "title": "MySQL Database Publicly Accessible (Port 3306)",
        "severity": "High",
        "impact": "Publicly accessible databases are prone to automated credential scanning and data exfiltration.",
        "action": "Ensure `bind-address = 127.0.0.1` in my.cnf and restrict remote connections to authorized hosts."
    },
    3389: {
        "title": "CRITICAL: Remote Desktop (RDP) Exposed (Port 3389)",
        "severity": "Critical",
        "impact": "Exposed RDP is one of the top vector entry points for ransomware initial access.",
        "action": "Place RDP behind a VPN, mandate Multi-Factor Authentication (MFA), and enable Network Level Authentication (NLA)."
    },
    5432: {
        "title": "PostgreSQL Database Service Active (Port 5432)",
        "severity": "High",
        "impact": "Direct internet exposure of PostgreSQL exposes stored credentials and sensitive databases.",
        "action": "Update pg_hba.conf to whitelist trusted IPs only and enforce SSL encryption."
    },
    5900: {
        "title": "VNC Desktop Sharing Active (Port 5900)",
        "severity": "High",
        "impact": "VNC implementations often suffer from weak authentication or cleartext session transport.",
        "action": "Tunnel VNC sessions over SSH or VPN and set strong passwords."
    },
    6379: {
        "title": "Redis Server Unprotected (Port 6379)",
        "severity": "High",
        "impact": "Unauthenticated Redis instances allow remote code execution and key dumps.",
        "action": "Bind Redis to localhost, enable `requirepass` password authentication, and block external port 6379."
    },
    27017: {
        "title": "MongoDB NoSQL Database Exposed (Port 27017)",
        "severity": "High",
        "impact": "Exposed MongoDB instances without mandatory auth are frequently wiped or ransomed.",
        "action": "Enable MongoDB security authorization (`security.authorization: enabled`) and restrict IP access."
    }
}

def get_service_info(port):
    """Retrieve service information for a given port number."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    return {
        "name": f"Unknown Service",
        "protocol": "TCP",
        "risk": "Info",
        "desc": f"Custom or unassigned service on port {port}"
    }

def get_security_recommendations(open_ports):
    """Generate tailored security recommendations based on list of open ports."""
    recs = []
    for port in open_ports:
        if port in SECURITY_RECOMMENDATIONS:
            rec = SECURITY_RECOMMENDATIONS[port].copy()
            rec["port"] = port
            recs.append(rec)
    
    # Generic baseline recommendation if no critical ports found
    if not recs and open_ports:
        recs.append({
            "port": "General",
            "title": "Enforce Strict Firewall Rules",
            "severity": "Low",
            "impact": "Exposed open ports expand system attack surfaces.",
            "action": "Implement a default-deny firewall policy and close any non-essential listening ports."
        })
    elif not open_ports:
        recs.append({
            "port": "Baseline",
            "title": "No Open Ports Detected",
            "severity": "Info",
            "impact": "The target system did not expose any responsive TCP ports in the scanned range.",
            "action": "Maintain current firewall configuration and conduct regular periodic audits."
        })
    return recs
