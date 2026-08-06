"""
SecureScan - SQLite Database Engine
"""
import sqlite3
import os
import json
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(__file__), 'database')
DB_PATH = os.path.join(DB_DIR, 'scans.db')

def get_connection():
    """Returns sqlite3 connection with dict-like row factory."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite database tables if they do not exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            ip TEXT NOT NULL,
            reverse_dns TEXT,
            start_port INTEGER,
            end_port INTEGER,
            total_ports INTEGER,
            open_ports_count INTEGER,
            closed_ports_count INTEGER,
            filtered_ports_count INTEGER,
            duration_seconds REAL,
            risk_score INTEGER,
            os_guess TEXT,
            threads_used INTEGER,
            timeout_sec REAL,
            recommendations_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL,
            service TEXT,
            protocol TEXT,
            response_time_ms REAL,
            banner TEXT,
            risk_level TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    # Insert default settings if empty
    default_settings = {
        "default_threads": "50",
        "default_timeout": "1.0",
        "default_port_preset": "common",
        "default_start_port": "1",
        "default_end_port": "1000",
        "dark_mode": "true",
        "auto_save_reports": "true"
    }

    for k, v in default_settings.items():
        cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

    conn.commit()
    conn.close()

def save_scan(summary_data):
    """Saves a completed scan summary and all its port results to SQLite."""
    conn = get_connection()
    cursor = conn.cursor()

    rec_json = json.dumps(summary_data.get("recommendations", []))

    cursor.execute('''
        INSERT INTO scans (
            id, target, ip, reverse_dns, start_port, end_port, total_ports,
            open_ports_count, closed_ports_count, filtered_ports_count,
            duration_seconds, risk_score, os_guess, threads_used, timeout_sec,
            recommendations_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    ''', (
        summary_data["scan_id"],
        summary_data["target"],
        summary_data["ip"],
        summary_data.get("reverse_dns", ""),
        summary_data["start_port"],
        summary_data["end_port"],
        summary_data["total_ports"],
        summary_data["open_ports_count"],
        summary_data["closed_ports_count"],
        summary_data["filtered_ports_count"],
        summary_data["duration_seconds"],
        summary_data["risk_score"],
        summary_data.get("os_guess", "Unknown OS"),
        summary_data.get("threads_used", 50),
        summary_data.get("timeout_sec", 1.0),
        rec_json
    ))

    # Insert detailed port results
    for res in summary_data.get("results", []):
        cursor.execute('''
            INSERT INTO scan_results (
                scan_id, port, status, service, protocol, response_time_ms, banner, risk_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            summary_data["scan_id"],
            res["port"],
            res["status"],
            res["service"],
            res["protocol"],
            res["response_time_ms"],
            res.get("banner", ""),
            res["risk_level"]
        ))

    conn.commit()
    conn.close()

def get_all_scans():
    """Retrieves all past scan records from database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY created_at DESC')
    rows = cursor.fetchall()
    scans = [dict(r) for r in rows]
    conn.close()
    return scans

def get_scan(scan_id):
    """Retrieves a single scan and its detailed port results."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None

    scan_data = dict(scan_row)
    if scan_data.get("recommendations_json"):
        try:
            scan_data["recommendations"] = json.loads(scan_data["recommendations_json"])
        except Exception:
            scan_data["recommendations"] = []
    else:
        scan_data["recommendations"] = []

    cursor.execute('SELECT * FROM scan_results WHERE scan_id = ? ORDER BY port ASC', (scan_id,))
    result_rows = cursor.fetchall()
    scan_data["results"] = [dict(r) for r in result_rows]

    conn.close()
    return scan_data

def delete_scan(scan_id):
    """Deletes a scan and associated results from SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_results WHERE scan_id = ?', (scan_id,))
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    return True

def get_dashboard_stats():
    """Calculates overall metrics & chart data for dashboard visualization."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) as total_scans FROM scans')
    total_scans = cursor.fetchone()['total_scans']

    cursor.execute('SELECT SUM(open_ports_count) as total_open, SUM(closed_ports_count) as total_closed, SUM(filtered_ports_count) as total_filtered, AVG(duration_seconds) as avg_duration FROM scans')
    sum_row = cursor.fetchone()

    total_open = sum_row['total_open'] or 0
    total_closed = sum_row['total_closed'] or 0
    total_filtered = sum_row['total_filtered'] or 0
    avg_duration = round(sum_row['avg_duration'] or 0.0, 2)

    # Get last scan
    cursor.execute('SELECT * FROM scans ORDER BY created_at DESC LIMIT 1')
    last_scan_row = cursor.fetchone()
    last_scan = dict(last_scan_row) if last_scan_row else None

    # Get most common open services across all scans
    cursor.execute('''
        SELECT service, COUNT(*) as count 
        FROM scan_results 
        WHERE status = 'Open' 
        GROUP BY service 
        ORDER BY count DESC 
        LIMIT 6
    ''')
    service_rows = cursor.fetchall()
    common_services = [{"service": r["service"], "count": r["count"]} for r in service_rows]

    # Get recent scans list for timeline widget
    cursor.execute('SELECT id, target, ip, open_ports_count, total_ports, duration_seconds, risk_score, created_at FROM scans ORDER BY created_at DESC LIMIT 5')
    recent_scans = [dict(r) for r in cursor.fetchall()]

    conn.close()

    # overall security status
    if total_scans == 0:
        security_status = "No Scans Recorded"
        status_color = "info"
    else:
        avg_risk = sum([s['risk_score'] for s in recent_scans]) / max(len(recent_scans), 1)
        if avg_risk > 60:
            security_status = "HIGH RISK DETECTED"
            status_color = "danger"
        elif avg_risk > 25:
            security_status = "MODERATE THREATS"
            status_color = "warning"
        else:
            security_status = "SECURE / LOW RISK"
            status_color = "success"

    return {
        "total_scans": total_scans,
        "total_open_ports": total_open,
        "total_closed_ports": total_closed,
        "total_filtered_ports": total_filtered,
        "avg_duration": avg_duration,
        "last_scan": last_scan,
        "common_services": common_services,
        "recent_scans": recent_scans,
        "security_status": security_status,
        "status_color": status_color
    }

def get_settings():
    """Fetches user preference settings."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM settings')
    rows = cursor.fetchall()
    conn.close()
    return {r['key']: r['value'] for r in rows}

def save_settings(settings_dict):
    """Updates user preference settings in SQLite."""
    conn = get_connection()
    cursor = conn.cursor()
    for k, v in settings_dict.items():
        cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (k, str(v)))
    conn.commit()
    conn.close()
    return True
