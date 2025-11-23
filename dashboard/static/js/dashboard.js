// SentraOS Dashboard JavaScript - Updated

// Chart.js instances
let systemChart = null;
let networkChart = null;

// Data storage
const cpuData = [];
const memoryData = [];
const networkSendData = [];
const networkRecvData = [];
const timeLabels = [];
const maxDataPoints = 20;

// Initialize charts
function initCharts() {
    const systemCtx = document.getElementById('systemChart');
    const networkCtx = document.getElementById('networkChart');
    
    if (!systemCtx || !networkCtx) {
        console.error('Chart canvases not found');
        return;
    }

    systemChart = new Chart(systemCtx.getContext('2d'), {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [
                {
                    label: 'CPU %',
                    data: cpuData,
                    borderColor: 'rgb(59, 130, 246)',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Memory %',
                    data: memoryData,
                    borderColor: 'rgb(16, 185, 129)',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            }
        }
    });

    networkChart = new Chart(networkCtx.getContext('2d'), {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [
                {
                    label: 'Send (MB/s)',
                    data: networkSendData,
                    borderColor: 'rgb(239, 68, 68)',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Receive (MB/s)',
                    data: networkRecvData,
                    borderColor: 'rgb(168, 85, 247)',
                    backgroundColor: 'rgba(168, 85, 247, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            }
        }
    });
    
    console.log('Charts initialized successfully');
}

// Fetch and update metrics
async function updateMetrics() {
    try {
        const response = await fetch('/api/metrics/current');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const metrics = await response.json();
        
        // Update stat cards
        const cpuStat = document.getElementById('cpu-stat');
        const memoryStat = document.getElementById('memory-stat');
        const diskStat = document.getElementById('disk-stat');
        
        if (cpuStat) cpuStat.textContent = `${metrics.cpu.usage_percent.toFixed(1)}%`;
        if (memoryStat) memoryStat.textContent = `${metrics.memory.percent.toFixed(1)}%`;
        if (diskStat) diskStat.textContent = `${metrics.disk.percent.toFixed(1)}%`;

        // Update chart data
        const timeLabel = new Date().toLocaleTimeString();
        
        if (timeLabels.length >= maxDataPoints) {
            timeLabels.shift();
            cpuData.shift();
            memoryData.shift();
            networkSendData.shift();
            networkRecvData.shift();
        }

        timeLabels.push(timeLabel);
        cpuData.push(metrics.cpu.usage_percent);
        memoryData.push(metrics.memory.percent);
        networkSendData.push(metrics.network.send_rate_mbps);
        networkRecvData.push(metrics.network.recv_rate_mbps);

        // Update charts
        if (systemChart) systemChart.update();
        if (networkChart) networkChart.update();
        
        console.log('Metrics updated:', metrics);

    } catch (error) {
        console.error('Error updating metrics:', error);
    }
}

// Fetch and display alerts
async function updateAlerts() {
    try {
        const response = await fetch('/api/alerts?limit=10');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const alerts = await response.json();

        const container = document.getElementById('alerts-container');
        
        if (!container) {
            console.error('Alerts container not found');
            return;
        }
        
        if (alerts.length === 0) {
            container.innerHTML = '<p class="text-muted">No alerts</p>';
        } else {
            container.innerHTML = alerts.map(alert => `
                <div class="alert-item severity-${alert.severity}">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <strong>${alert.type.toUpperCase()}</strong>
                            <span class="badge bg-${getSeverityColor(alert.severity)} ms-2">${alert.severity}</span>
                        </div>
                        <small class="text-muted">${new Date(alert.timestamp).toLocaleString()}</small>
                    </div>
                    <p class="mb-0 mt-2">${alert.message}</p>
                </div>
            `).join('');
        }

        // Update alert count
        const alertCount = document.getElementById('alert-count');
        if (alertCount) alertCount.textContent = alerts.length;
        
        console.log('Alerts updated:', alerts.length);

    } catch (error) {
        console.error('Error updating alerts:', error);
    }
}

// Fetch and display scan results
async function updateScans() {
    try {
        const response = await fetch('/api/security/scans?limit=5');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const scans = await response.json();

        const container = document.getElementById('scan-results');
        
        if (!container) {
            console.error('Scan results container not found');
            return;
        }
        
        if (scans.length === 0) {
            container.innerHTML = '<p class="text-muted">No recent scans</p>';
        } else {
            container.innerHTML = scans.map(scan => `
                <div class="scan-result risk-${scan.risk_level}">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div>
                            <strong>${scan.target}</strong>
                            <span class="badge bg-${getRiskColor(scan.risk_level)} ms-2">${scan.risk_level} risk</span>
                        </div>
                        <small class="text-muted">${new Date(scan.timestamp).toLocaleString()}</small>
                    </div>
                    <div>
                        <small><i class="fas fa-network-wired"></i> Open Ports: ${scan.open_ports.length}</small> |
                        <small><i class="fas fa-exclamation-triangle"></i> Vulnerabilities: ${scan.vulnerabilities.length}</small>
                    </div>
                    ${scan.vulnerabilities.length > 0 ? `
                        <div class="mt-2">
                            ${scan.vulnerabilities.slice(0, 2).map(v => `
                                <div style="font-size: 0.85rem; padding: 5px; background: rgba(239, 68, 68, 0.1); border-radius: 5px; margin-top: 5px;">
                                    <i class="fas fa-bug"></i> ${v.name} - ${v.description}
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            `).join('');
        }
        
        console.log('Scans updated:', scans.length);

    } catch (error) {
        console.error('Error updating scans:', error);
    }
}

// Fetch and display network connections
async function updateConnections() {
    try {
        const response = await fetch('/api/network/connections');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const connections = await response.json();

        const tbody = document.getElementById('connections-body');
        
        if (!tbody) {
            console.error('Connections tbody not found');
            return;
        }
        
        if (connections.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No active connections</td></tr>';
        } else {
            tbody.innerHTML = connections.slice(0, 10).map(conn => `
                <tr>
                    <td><code>${conn.local_address}</code></td>
                    <td><code>${conn.remote_address}</code></td>
                    <td><span class="badge bg-success">${conn.status}</span></td>
                    <td>${conn.pid || 'N/A'}</td>
                </tr>
            `).join('');
        }
        
        console.log('Connections updated:', connections.length);

    } catch (error) {
        console.error('Error updating connections:', error);
    }
}

// Run security scan
async function runSecurityScan() {
    const button = event.target.closest('button');
    const originalHTML = button.innerHTML;
    button.innerHTML = '<span class="spinner"></span> Scanning...';
    button.disabled = true;

    try {
        const response = await fetch('/api/security/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: 'localhost',
                type: 'quick'
            })
        });

        const result = await response.json();
        
        if (result.error) {
            alert('Scan error: ' + result.error);
        } else {
            // Refresh scan results
            await updateScans();
            alert('Scan completed successfully!');
        }

    } catch (error) {
        console.error('Error running scan:', error);
        alert('Failed to run security scan: ' + error.message);
    } finally {
        button.innerHTML = originalHTML;
        button.disabled = false;
    }
}

// Helper functions
function getSeverityColor(severity) {
    const colors = {
        low: 'info',
        medium: 'warning',
        high: 'danger',
        critical: 'dark'
    };
    return colors[severity] || 'secondary';
}

function getRiskColor(risk) {
    const colors = {
        low: 'success',
        medium: 'warning',
        high: 'danger'
    };
    return colors[risk] || 'secondary';
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', async () => {
    console.log('Dashboard initializing...');
    
    // Initialize charts first
    initCharts();
    
    // Initial data load - wait for first metrics
    console.log('Loading initial data...');
    await updateMetrics();
    await updateAlerts();
    await updateScans();
    await updateConnections();
    
    // Load initial metrics for charts (populate with some data)
    for (let i = 0; i < 5; i++) {
        setTimeout(() => {
            updateMetrics();
        }, i * 1000); // Every 1 second for first 5 seconds
    }

    // Then start regular updates
    setInterval(updateMetrics, 3000);
    setInterval(updateAlerts, 5000);
    setInterval(updateScans, 10000);
    setInterval(updateConnections, 5000);
    
    console.log('Dashboard initialized successfully');
});