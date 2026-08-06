/* Dashboard Chart.js Integration */
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const response = await fetch('/api/stats');
    const data = await response.json();

    document.getElementById('stat-total-scans').innerText = data.total_scans;
    document.getElementById('stat-open-ports').innerText = data.total_open_ports;
    document.getElementById('stat-closed-ports').innerText = data.total_closed_ports + data.total_filtered_ports;
    document.getElementById('stat-avg-duration').innerText = data.avg_duration + 's';

    const statusBadge = document.getElementById('security-status-badge');
    statusBadge.innerText = data.security_status;
    statusBadge.className = `badge bg-${data.status_color} p-2 px-3 fs-6 mb-2`;

    // Render Recent Scans Table
    const tbody = document.getElementById('recent-scans-tbody');
    if (data.recent_scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted py-3">No scan records found in database. Run a scan to get started.</td></tr>`;
    } else {
      tbody.innerHTML = data.recent_scans.map(s => `
        <tr>
          <td><strong class="text-light">${s.target}</strong></td>
          <td><code>${s.ip}</code></td>
          <td><span class="badge badge-open">${s.open_ports_count} Open</span></td>
          <td><span class="badge ${s.risk_score > 50 ? 'badge-closed' : 'badge-open'}">${s.risk_score}/100</span></td>
          <td><small class="text-muted">${s.created_at}</small></td>
          <td>
            <a href="/report/${s.id}" class="btn btn-sm btn-cyber-outline py-0 px-2" title="View Audit Report">
              <i class="fa-solid fa-file-contract"></i> Report
            </a>
          </td>
        </tr>
      `).join('');
    }

    // Chart 1: Donut Port Status Distribution
    const ctx1 = document.getElementById('portStatusChart').getContext('2d');
    new Chart(ctx1, {
      type: 'doughnut',
      data: {
        labels: ['Open Ports', 'Closed Ports', 'Filtered Ports'],
        datasets: [{
          data: [data.total_open_ports, data.total_closed_ports, data.total_filtered_ports],
          backgroundColor: ['#00FF88', '#FF3366', '#FFB800'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: '#94A3B8', font: { family: 'Inter' } } }
        }
      }
    });

    // Chart 2: Top Services Bar Chart
    const ctx2 = document.getElementById('topServicesChart').getContext('2d');
    const serviceLabels = data.common_services.map(s => s.service);
    const serviceCounts = data.common_services.map(s => s.count);

    new Chart(ctx2, {
      type: 'bar',
      data: {
        labels: serviceLabels.length > 0 ? serviceLabels : ['None Discovered Yet'],
        datasets: [{
          label: 'Discovered Occurrences',
          data: serviceCounts.length > 0 ? serviceCounts : [0],
          backgroundColor: '#00C8FF',
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#94A3B8' }, grid: { display: false } },
          y: { ticks: { color: '#94A3B8', stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.05)' } }
        },
        plugins: {
          legend: { labels: { color: '#94A3B8' } }
        }
      }
    });

  } catch (err) {
    console.error('Failed to load dashboard statistics:', err);
  }
});
