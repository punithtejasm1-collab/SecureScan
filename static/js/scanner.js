/* Scanner Execution & Real-Time Live Results Engine */
let currentScanId = null;
let pollInterval = null;
let scanResults = [];
let activeFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scanner-form');
  const btnStart = document.getElementById('btn-start-scan');
  const btnStop = document.getElementById('btn-stop-scan');
  const btnClear = document.getElementById('btn-clear-results');
  const progressSection = document.getElementById('scan-progress-section');

  // Presets
  document.getElementById('preset-top20').addEventListener('click', () => {
    document.getElementById('start-port-input').value = 1;
    document.getElementById('end-port-input').value = 100;
  });
  document.getElementById('preset-top100').addEventListener('click', () => {
    document.getElementById('start-port-input').value = 1;
    document.getElementById('end-port-input').value = 500;
  });
  document.getElementById('preset-all1000').addEventListener('click', () => {
    document.getElementById('start-port-input').value = 1;
    document.getElementById('end-port-input').value = 1000;
  });

  // Filter Buttons
  document.getElementById('filter-all').addEventListener('click', (e) => setFilter('all', e.target));
  document.getElementById('filter-open').addEventListener('click', (e) => setFilter('Open', e.target));
  document.getElementById('filter-closed').addEventListener('click', (e) => setFilter('Closed', e.target));

  // Search input
  document.getElementById('table-search').addEventListener('input', () => renderTable());

  // Form Submission -> Start Scan
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = document.getElementById('target-input').value.trim();
    const startPort = parseInt(document.getElementById('start-port-input').value);
    const endPort = parseInt(document.getElementById('end-port-input').value);
    const timeout = parseFloat(document.getElementById('timeout-select').value);
    const threads = parseInt(document.getElementById('threads-select').value);

    if (!target) return alert('Please enter a target IP address or hostname.');
    if (startPort > endPort) return alert('Start Port cannot be greater than End Port.');

    // UI Updates
    btnStart.disabled = true;
    btnStop.classList.remove('d-none');
    progressSection.classList.remove('d-none');
    scanResults = [];
    renderTable();

    try {
      const res = await fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, start_port: startPort, end_port: endPort, timeout, threads })
      });
      const data = await res.json();

      if (!res.ok) {
        alert(data.error || 'Failed to start scan.');
        resetScanUI();
        return;
      }

      currentScanId = data.scan_id;
      pollInterval = setInterval(pollProgress, 400);

    } catch (err) {
      alert('Network error initiating scan: ' + err.message);
      resetScanUI();
    }
  });

  // Stop Scan
  btnStop.addEventListener('click', async () => {
    if (!currentScanId) return;
    btnStop.disabled = true;
    try {
      await fetch(`/api/scan/stop/${currentScanId}`, { method: 'POST' });
      document.getElementById('status-text').innerText = 'Scan Stopping...';
    } catch (err) {
      console.error('Stop request error:', err);
    }
  });

  // Clear Results
  btnClear.addEventListener('click', () => {
    scanResults = [];
    renderTable();
    progressSection.classList.add('d-none');
    document.getElementById('btn-export-report').classList.add('disabled');
  });

  async function pollProgress() {
    if (!currentScanId) return;
    try {
      const res = await fetch(`/api/scan/status/${currentScanId}`);
      const data = await res.json();

      // Update progress metrics
      document.getElementById('progress-pct-label').innerText = `${data.progress_pct}%`;
      document.getElementById('progress-bar-inner').style.width = `${data.progress_pct}%`;
      document.getElementById('eta-label').innerText = `${data.eta_sec}s`;
      document.getElementById('speed-label').innerText = `${data.speed_ports_per_sec} p/s`;
      
      document.getElementById('metric-threads').innerText = data.active_threads;
      document.getElementById('metric-scanned').innerText = `${data.scanned_ports} / ${data.total_ports}`;
      document.getElementById('metric-open').innerText = data.open_ports_count;
      document.getElementById('metric-closed').innerText = data.closed_ports_count;
      document.getElementById('metric-filtered').innerText = data.filtered_ports_count;

      if (data.latest_open_results) {
        scanResults = data.latest_open_results;
        renderTable();
      }

      if (!data.is_running) {
        clearInterval(pollInterval);
        document.getElementById('status-text').innerText = 'Scan Completed';
        resetScanUI();

        // Fetch complete scan payload to render full table
        const scanRes = await fetch(`/api/scans/${currentScanId}`);
        const fullData = await scanRes.json();
        scanResults = fullData.results || [];
        renderTable();

        // Enable report export button
        const exportBtn = document.getElementById('btn-export-report');
        exportBtn.href = `/report/${currentScanId}`;
        exportBtn.classList.remove('disabled');
      }

    } catch (err) {
      console.error('Polling progress error:', err);
    }
  }

  function resetScanUI() {
    btnStart.disabled = false;
    btnStop.classList.add('d-none');
    btnStop.disabled = false;
  }

  function setFilter(filterType, element) {
    activeFilter = filterType;
    document.querySelectorAll('.btn-group .btn').forEach(b => b.classList.remove('active'));
    element.classList.add('active');
    renderTable();
  }

  function renderTable() {
    const tbody = document.getElementById('results-tbody');
    const searchTerm = document.getElementById('table-search').value.toLowerCase();

    let filtered = scanResults.filter(r => {
      if (activeFilter !== 'all' && r.status !== activeFilter) return false;
      if (searchTerm) {
        const portStr = r.port.toString();
        const serviceStr = (r.service || '').toLowerCase();
        const bannerStr = (r.banner || '').toLowerCase();
        return portStr.includes(searchTerm) || serviceStr.includes(searchTerm) || bannerStr.includes(searchTerm);
      }
      return true;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted py-4">No matching port results found.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(r => {
      let badgeClass = 'badge-closed';
      if (r.status === 'Open') badgeClass = 'badge-open';
      else if (r.status === 'Filtered') badgeClass = 'badge-filtered';

      let riskColor = 'text-neon-blue';
      if (r.risk_level === 'High' || r.risk_level === 'Critical') riskColor = 'text-neon-red';
      else if (r.risk_level === 'Medium') riskColor = 'text-neon-yellow';

      return `
        <tr>
          <td><strong class="text-light">Port ${r.port}</strong></td>
          <td><span class="badge ${badgeClass}">${r.status}</span></td>
          <td><span class="text-neon-blue">${r.service}</span></td>
          <td><code>${r.protocol}</code></td>
          <td><small class="text-muted">${r.response_time_ms} ms</small></td>
          <td><span class="fw-bold ${riskColor}">${r.risk_level}</span></td>
          <td><small class="text-muted">${r.banner || '-'}</small></td>
        </tr>
      `;
    }).join('');
  }
});
