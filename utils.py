"""
SecureScan - Helper Utilities (DNS, Validation, Ping, OS Fingerprinting)
"""
import socket
import re
import platform
import subprocess
import time

def validate_target(target_str):
    """
    Validates IP address or domain name.
    Returns (is_valid, resolved_ip, hostname_or_error)
    """
    target_str = target_str.strip()
    if not target_str:
        return False, None, "Target cannot be empty."

    # Remove protocol prefix if entered
    target_str = re.sub(r'^https?://', '', target_str, flags=re.IGNORECASE)
    target_str = target_str.split('/')[0].split(':')[0]

    # Check IPv4
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, target_str):
        parts = target_str.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return True, target_str, target_str

    # Resolve domain hostname
    try:
        ip = socket.gethostbyname(target_str)
        return True, ip, target_str
    except socket.gaierror:
        return False, None, f"Could not resolve domain/IP address: '{target_str}'"

def reverse_dns_lookup(ip):
    """Performs reverse DNS lookup to obtain domain name for an IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, Exception):
        return "Unknown Host / No PTR record"

def ping_target(ip_or_host):
    """
    Performs quick latency and ping check using socket connection or system ping.
    Returns dict: {'alive': bool, 'rtt_ms': float}
    """
    start_time = time.time()
    try:
        # Try quick TCP connect on common ports
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        res = s.connect_ex((ip_or_host, 80))
        if res == 0:
            s.close()
            rtt = round((time.time() - start_time) * 1000, 2)
            return {"alive": True, "rtt_ms": rtt}
        s.close()

        # Fallback to ICMP ping command
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '1000', ip_or_host]
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        rtt = round((time.time() - start_time) * 1000, 2)
        alive = (output.returncode == 0)
        return {"alive": alive, "rtt_ms": rtt if alive else 0.0}
    except Exception:
        return {"alive": False, "rtt_ms": 0.0}

def guess_os_heuristics(banners, open_ports, ttl=None):
    """
    Provides an estimated Operating System guess based on banner signatures & open ports.
    """
    banner_str = " ".join([str(b) for b in banners.values()]).lower()
    
    if "ubuntu" in banner_str or "debian" in banner_str:
        return "Linux (Ubuntu/Debian)"
    if "centos" in banner_str or "red hat" in banner_str or "rhel" in banner_str:
        return "Linux (RedHat/CentOS)"
    if "microsoft" in banner_str or "iis" in banner_str or 3389 in open_ports or 135 in open_ports:
        return "Windows Server / Windows Desktop"
    if "freebsd" in banner_str or "openbsd" in banner_str:
        return "BSD Unix"
    if "cisco" in banner_str:
        return "Cisco IOS / Network Device"
    if 22 in open_ports or 80 in open_ports or 443 in open_ports:
        return "Linux / Unix-like OS (Likely)"
        
    return "Generic OS / Firewalled Device"
