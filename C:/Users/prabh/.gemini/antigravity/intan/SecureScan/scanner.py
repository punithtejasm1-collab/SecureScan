"""
SecureScan - Multi-Threaded Socket Scanner Core Engine
"""
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from services import get_service_info, get_security_recommendations
from utils import reverse_dns_lookup, guess_os_heuristics

class ScannerEngine:
    def __init__(self, scan_id, target_ip, target_host, start_port, end_port, timeout=1.0, max_threads=50):
        self.scan_id = scan_id
        self.target_ip = target_ip
        self.target_host = target_host
        self.start_port = int(start_port)
        self.end_port = int(end_port)
        self.timeout = float(timeout)
        self.max_threads = int(max_threads)
        
        self.total_ports = self.end_port - self.start_port + 1
        self.scanned_ports_count = 0
        self.open_ports_count = 0
        self.closed_ports_count = 0
        self.filtered_ports_count = 0
        
        self.is_running = False
        self.stop_requested = False
        self.results = []
        self.banners = {}
        self.open_port_numbers = []
        self.start_time = None
        self.end_time = None

    def grab_banner(self, s, port):
        """Attempts to grab service banner string from responsive open port socket."""
        try:
            # Send HTTP HEAD request for web ports
            if port in [80, 8080, 8443]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                s.sendall(b"\r\n")
            
            s.settimeout(1.0)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                # Clean up banner line breaks
                first_line = banner.split('\n')[0].strip()
                return first_line[:120]
        except Exception:
            pass
        return ""

    def scan_port(self, port):
        """Scans a single TCP port using non-blocking socket."""
        if self.stop_requested:
            return None

        result = {
            "port": port,
            "status": "Closed",
            "service": "Unknown",
            "protocol": "TCP",
            "response_time_ms": 0.0,
            "banner": "",
            "risk_level": "Low"
        }

        service_meta = get_service_info(port)
        result["service"] = service_meta["name"]
        result["protocol"] = service_meta["protocol"]
        result["risk_level"] = service_meta["risk"]

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        start_t = time.time()
        
        try:
            conn_res = s.connect_ex((self.target_ip, port))
            rtt = round((time.time() - start_t) * 1000, 2)
            result["response_time_ms"] = rtt

            if conn_res == 0:
                result["status"] = "Open"
                banner = self.grab_banner(s, port)
                result["banner"] = banner
                if banner:
                    self.banners[port] = banner
                self.open_port_numbers.append(port)
                self.open_ports_count += 1
            else:
                result["status"] = "Closed"
                self.closed_ports_count += 1
        except socket.timeout:
            result["status"] = "Filtered"
            result["response_time_ms"] = round(self.timeout * 1000, 2)
            self.filtered_ports_count += 1
        except Exception:
            result["status"] = "Closed"
            self.closed_ports_count += 1
        finally:
            s.close()
            self.scanned_ports_count += 1

        return result

    def execute_scan(self, progress_callback=None):
        """Executes multi-threaded port scan across specified port range."""
        self.is_running = True
        self.start_time = time.time()
        
        ports_to_scan = list(range(self.start_port, self.end_port + 1))
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports_to_scan}
            
            for future in as_completed(future_to_port):
                if self.stop_requested:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    res = future.result()
                    if res:
                        self.results.append(res)
                        if progress_callback:
                            progress_callback(self.get_current_status())
                except Exception:
                    pass

        self.end_time = time.time()
        self.is_running = False
        
        # Sort results by port number ascending
        self.results.sort(key=lambda x: x["port"])
        return self.results

    def calculate_risk_score(self):
        """Computes dynamic security risk score (0-100) based on exposed services."""
        if not self.open_port_numbers:
            return 0
        
        score = 0
        critical_ports = {445: 35, 3389: 30, 23: 25, 21: 15, 1433: 20, 3306: 15, 6379: 20, 27017: 20, 5900: 20}
        for port in self.open_port_numbers:
            if port in critical_ports:
                score += critical_ports[port]
            else:
                score += 5
        return min(score, 100)

    def get_summary(self):
        """Generates comprehensive scan execution summary payload."""
        duration = round(self.end_time - self.start_time, 2) if (self.start_time and self.end_time) else 0.0
        risk_score = self.calculate_risk_score()
        reverse_dns = reverse_dns_lookup(self.target_ip)
        os_guess = guess_os_heuristics(self.banners, self.open_port_numbers)
        recommendations = get_security_recommendations(self.open_port_numbers)

        return {
            "scan_id": self.scan_id,
            "target": self.target_host,
            "ip": self.target_ip,
            "reverse_dns": reverse_dns,
            "start_port": self.start_port,
            "end_port": self.end_port,
            "total_ports": self.total_ports,
            "scanned_ports": self.scanned_ports_count,
            "open_ports_count": self.open_ports_count,
            "closed_ports_count": self.closed_ports_count,
            "filtered_ports_count": self.filtered_ports_count,
            "duration_seconds": duration,
            "risk_score": risk_score,
            "os_guess": os_guess,
            "threads_used": self.max_threads,
            "timeout_sec": self.timeout,
            "open_ports": self.open_port_numbers,
            "recommendations": recommendations,
            "results": self.results
        }

    def get_current_status(self):
        """Returns real-time progress update metrics for web dashboard socket/polling."""
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        pct = round((self.scanned_ports_count / self.total_ports) * 100, 1) if self.total_ports > 0 else 0
        speed = round(self.scanned_ports_count / elapsed, 1) if elapsed > 0 else 0
        remaining_ports = self.total_ports - self.scanned_ports_count
        eta_sec = round(remaining_ports / speed, 1) if speed > 0 else 0

        # Fetch latest open port results
        open_items = [r for r in self.results if r["status"] == "Open"]

        return {
            "scan_id": self.scan_id,
            "is_running": self.is_running,
            "progress_pct": pct,
            "scanned_ports": self.scanned_ports_count,
            "total_ports": self.total_ports,
            "open_ports_count": self.open_ports_count,
            "closed_ports_count": self.closed_ports_count,
            "filtered_ports_count": self.filtered_ports_count,
            "elapsed_sec": round(elapsed, 1),
            "speed_ports_per_sec": speed,
            "eta_sec": eta_sec,
            "active_threads": self.max_threads if self.is_running else 0,
            "latest_open_results": open_items
        }

    def stop(self):
        """Triggers cancel flag to stop current scan gracefully."""
        self.stop_requested = True
        self.is_running = False
