"""
SecureScan - Advanced Multi-Threaded Network Port Scanner
Flask Web Server & REST API Entrypoint
"""
import os
import uuid
import threading
from flask import Flask, render_template, request, jsonify, send_file
from database import init_db, save_scan, get_all_scans, get_scan, delete_scan, get_dashboard_stats, get_settings, save_settings
from scanner import ScannerEngine
from utils import validate_target
from report import generate_pdf_report, generate_csv_report, generate_json_report

app = Flask(__name__)
app.secret_key = 'securescan_cyber_secret_key'

# In-memory registry for background active scan execution engines
active_scanners = {}

# Initialize SQLite database schema
init_db()

@app.before_request
def setup():
    """Ensure database tables exist before handling requests."""
    pass


# --- Page Web Routes ---

@app.route('/')
def page_dashboard():
    return render_template('dashboard.html')

@app.route('/scanner')
def page_scanner():
    target_preset = request.args.get('target', '')
    return render_template('scanner.html', target_preset=target_preset)

@app.route('/history')
def page_history():
    return render_template('history.html')

@app.route('/report')
@app.route('/report/<scan_id>')
def page_report(scan_id=None):
    return render_template('report.html')

@app.route('/settings')
def page_settings():
    return render_template('settings.html')

# --- REST API Endpoints ---

@app.route('/api/scan/start', methods=['POST'])
def api_start_scan():
    data = request.get_json() or {}
    target_raw = data.get('target', '')
    start_port = data.get('start_port', 1)
    end_port = data.get('end_port', 1000)
    timeout = data.get('timeout', 1.0)
    threads = data.get('threads', 50)

    # Validate target IP or domain
    is_valid, resolved_ip, host_or_err = validate_target(target_raw)
    if not is_valid:
        return jsonify({"error": host_or_err}), 400

    scan_id = str(uuid.uuid4())[:8]

    engine = ScannerEngine(
        scan_id=scan_id,
        target_ip=resolved_ip,
        target_host=target_raw,
        start_port=start_port,
        end_port=end_port,
        timeout=timeout,
        max_threads=threads
    )

    active_scanners[scan_id] = engine

    # Run scan in background thread
    def run_worker():
        summary = engine.execute_scan()
        summary_payload = engine.get_summary()
        save_scan(summary_payload)

    worker_thread = threading.Thread(target=run_worker, daemon=True)
    worker_thread.start()

    return jsonify({
        "scan_id": scan_id,
        "target": target_raw,
        "ip": resolved_ip,
        "total_ports": engine.total_ports
    })

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def api_scan_status(scan_id):
    if scan_id in active_scanners:
        engine = active_scanners[scan_id]
        return jsonify(engine.get_current_status())

    # Fallback to database if completed scan
    db_scan = get_scan(scan_id)
    if db_scan:
        return jsonify({
            "scan_id": scan_id,
            "is_running": False,
            "progress_pct": 100.0,
            "scanned_ports": db_scan["total_ports"],
            "total_ports": db_scan["total_ports"],
            "open_ports_count": db_scan["open_ports_count"],
            "closed_ports_count": db_scan["closed_ports_count"],
            "filtered_ports_count": db_scan["filtered_ports_count"],
            "elapsed_sec": db_scan["duration_seconds"],
            "speed_ports_per_sec": 0,
            "eta_sec": 0,
            "active_threads": 0,
            "latest_open_results": [r for r in db_scan.get("results", []) if r["status"] == "Open"]
        })

    return jsonify({"error": "Scan ID not found"}), 404

@app.route('/api/scan/stop/<scan_id>', methods=['POST'])
def api_stop_scan(scan_id):
    if scan_id in active_scanners:
        active_scanners[scan_id].stop()
        return jsonify({"message": "Scan stopping requested."})
    return jsonify({"error": "Active scan ID not found"}), 404

@app.route('/api/scans', methods=['GET'])
def api_get_scans():
    scans = get_all_scans()
    return jsonify(scans)

@app.route('/api/scans/<scan_id>', methods=['GET'])
def api_get_scan_detail(scan_id):
    scan_detail = get_scan(scan_id)
    if scan_detail:
        return jsonify(scan_detail)
    return jsonify({"error": "Scan record not found"}), 404

@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    delete_scan(scan_id)
    if scan_id in active_scanners:
        del active_scanners[scan_id]
    return jsonify({"message": "Scan record deleted successfully."})

@app.route('/api/reports/download/<scan_id>/<fmt>', methods=['GET'])
def api_download_report(scan_id, fmt):
    scan_detail = get_scan(scan_id)
    if not scan_detail:
        return jsonify({"error": "Scan report not found"}), 404

    fmt = fmt.lower()
    if fmt == 'pdf':
        file_path, filename = generate_pdf_report(scan_detail)
        mimetype = 'application/pdf'
    elif fmt == 'csv':
        file_path, filename = generate_csv_report(scan_detail)
        mimetype = 'text/csv'
    elif fmt == 'json':
        file_path, filename = generate_json_report(scan_detail)
        mimetype = 'application/json'
    else:
        return jsonify({"error": "Invalid format. Supported: pdf, csv, json"}), 400

    return send_file(file_path, as_attachment=True, download_name=filename, mimetype=mimetype)

@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    stats = get_dashboard_stats()
    return jsonify(stats)

@app.route('/api/settings', methods=['GET', 'POST'])
def api_manage_settings():
    if request.method == 'POST':
        data = request.get_json() or {}
        save_settings(data)
        return jsonify({"message": "Settings updated."})
    return jsonify(get_settings())

if __name__ == '__main__':
    print("=" * 60)
    print("  SECURESCAN - ADVANCED MULTI-THREADED PORT SCANNER ENGINE")
    print("  Server listening on: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
