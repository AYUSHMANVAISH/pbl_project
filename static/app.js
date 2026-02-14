

let attackPieChart = null;
let detectionBarChart = null;
let liveInterval = null;
let anomalyData = [];

document.addEventListener('DOMContentLoaded', () => {
    checkStatus();
    initCharts();
});

async function checkStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        if (data.loaded) {
            updateStatus('online', `Analysis loaded: ${data.records.toLocaleString()} records, ${data.ports.toLocaleString()} ports`);
            loadDashboard();
        } else {
            updateStatus('offline', 'No analysis loaded. Click "Run Analysis" to start.');
        }
    } catch (error) {
        updateStatus('error', 'Error connecting to server');
    }
}

function updateStatus(status, text) {
    const indicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');

    indicator.className = 'status-indicator ' + status;
    statusText.textContent = text;
}

async function runAnalysis() {
    const btn = document.getElementById('analyzeBtn');
    btn.disabled = true;
    btn.innerHTML = '⏳ Analyzing...';
    updateStatus('loading', 'Running ML analysis on dataset...');

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sample_frac: 0.1 })
        });

        const data = await response.json();

        if (data.success) {
            updateStatus('online', 'Analysis complete!');
            loadDashboard();
        } else {
            updateStatus('error', 'Analysis failed: ' + data.error);
        }
    } catch (error) {
        updateStatus('error', 'Error: ' + error.message);
    }

    btn.disabled = false;
    btn.innerHTML = '🔍 Run Analysis';
}

async function loadDashboard() {
    await Promise.all([
        loadStats(),
        loadAnomalies()
    ]);
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        if (data.mode === 'flow') {
            document.getElementById('totalPorts').textContent = data.total_ports.toLocaleString();

            const maliciousCount = data.malicious_ports || 0;
            document.getElementById('totalAlerts').textContent = maliciousCount.toLocaleString();

            document.getElementById('precision').textContent =
                ((data.metrics.precision || 0) * 100).toFixed(1) + '%';
            document.getElementById('recall').textContent =
                ((data.metrics.recall || 0) * 100).toFixed(1) + '%';

            document.getElementById('cmTP').textContent = data.confusion_matrix?.true_positive ?? '-';
            document.getElementById('cmTN').textContent = data.confusion_matrix?.true_negative ?? '-';
            document.getElementById('cmFP').textContent = data.confusion_matrix?.false_positive ?? '-';
            document.getElementById('cmFN').textContent = data.confusion_matrix?.false_negative ?? '-';

            if (data.threat_counts && Object.keys(data.threat_counts).length > 0) {
                updatePieChart(data.threat_counts);
            }
            if (data.per_attack && Object.keys(data.per_attack).length > 0) {
                updateBarChart(data.per_attack);
            }
        } else {
            document.getElementById('totalPorts').textContent = data.total_ports.toLocaleString();

            const alertCount = Object.entries(data.attack_counts || {})
                .filter(([k, v]) => k !== 'Normal Traffic')
                .reduce((sum, [k, v]) => sum + v, 0);
            document.getElementById('totalAlerts').textContent = alertCount.toLocaleString();

            document.getElementById('precision').textContent =
                ((data.metrics.precision || 0) * 100).toFixed(1) + '%';
            document.getElementById('recall').textContent =
                ((data.metrics.recall || 0) * 100).toFixed(1) + '%';

            document.getElementById('cmTP').textContent = data.confusion_matrix?.true_positive || '-';
            document.getElementById('cmTN').textContent = data.confusion_matrix?.true_negative || '-';
            document.getElementById('cmFP').textContent = data.confusion_matrix?.false_positive || '-';
            document.getElementById('cmFN').textContent = data.confusion_matrix?.false_negative || '-';

            updatePieChart(data.attack_counts || {});
            if (data.per_attack) {
                updateBarChart(data.per_attack);
            }
        }

    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadAnomalies() {
    try {
        const response = await fetch('/api/anomalies?limit=20');
        anomalyData = await response.json();

        const tbody = document.getElementById('anomaliesBody');
        tbody.innerHTML = '';

        anomalyData.forEach(item => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${item.port}</strong></td>
                <td>${item.score.toFixed(3)}</td>
                <td><span class="badge ${getBadgeClass(item.decision)}">${item.decision}</span></td>
                <td>${item.request_rate.toFixed(0)}</td>
            `;
            tbody.appendChild(row);
        });

    } catch (error) {
        console.error('Error loading anomalies:', error);
    }
}

function getBadgeClass(decision) {
    if (decision.includes('DDoS') || decision.includes('Attack')) return 'danger';
    if (decision.includes('High Volume') || decision.includes('Anomalous')) return 'warning';
    return 'success';
}

function initCharts() {
    const pieCtx = document.getElementById('attackPieChart').getContext('2d');
    attackPieChart = new Chart(pieCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#ef4444', '#f59e0b', '#8b5cf6', '#06b6d4', '#10b981', '#3b82f6'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#9ca3af', padding: 15 }
                }
            }
        }
    });

    const barCtx = document.getElementById('detectionBarChart').getContext('2d');
    detectionBarChart = new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Detection Rate %',
                data: [],
                backgroundColor: 'rgba(59, 130, 246, 0.7)',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            indexAxis: 'y',
            scales: {
                x: {
                    max: 100,
                    grid: { color: 'rgba(255,255,255,0.1)' },
                    ticks: { color: '#9ca3af' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#9ca3af' }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function updatePieChart(attackCounts) {
    const labels = Object.keys(attackCounts);
    const values = Object.values(attackCounts);

    attackPieChart.data.labels = labels;
    attackPieChart.data.datasets[0].data = values;
    attackPieChart.update();
}

function updateBarChart(perAttack) {
    const labels = Object.keys(perAttack);
    const values = labels.map(k => perAttack[k].detection_rate);

    detectionBarChart.data.labels = labels;
    detectionBarChart.data.datasets[0].data = values;
    detectionBarChart.update();
}

async function startLiveMode() {
    try {
        const statusResp = await fetch('/api/status');
        const statusData = await statusResp.json();
        if (!statusData.loaded) {
            updateStatus('error', '⚠️ Run Analysis first before starting Live Mode');
            return;
        }
    } catch (e) {
        updateStatus('error', 'Cannot connect to server');
        return;
    }

    document.getElementById('liveBtn').style.display = 'none';
    document.getElementById('stopBtn').style.display = 'inline-flex';
    updateStatus('live', '🔴 LIVE - Scanning network flows in real-time...');

    const feed = document.getElementById('liveFeed');
    feed.innerHTML = '';

    liveInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/live');
            const item = await response.json();
            if (item.error) return;
            addLiveFeedItem(item);
        } catch (e) {
            console.error('Live feed error:', e);
        }
    }, 1200);
}

function stopLiveMode() {
    clearInterval(liveInterval);
    document.getElementById('liveBtn').style.display = 'inline-flex';
    document.getElementById('stopBtn').style.display = 'none';
    updateStatus('online', 'Live mode stopped');
}

function addLiveFeedItem(item) {
    const feed = document.getElementById('liveFeed');
    const div = document.createElement('div');

    let feedClass = 'info';
    let icon = 'ℹ️';

    const decision = item.decision || 'Unknown';

    if (decision.includes('Attack') || decision.includes('Threat') || decision.includes('DDoS')) {
        feedClass = 'danger';
        icon = '🚨';
    } else if (decision.includes('Suspected') || decision.includes('Anomalous') || decision.includes('Medium')) {
        feedClass = 'warning';
        icon = '⚠️';
    } else if (decision.includes('Normal')) {
        feedClass = 'success';
        icon = '✅';
    }

    const time = new Date().toLocaleTimeString();
    const scoreStr = item.score !== undefined ? item.score.toFixed(3) : '-';
    const label = item.label ? ` | GT: ${item.label}` : '';

    div.className = `feed-item ${feedClass}`;
    div.innerHTML = `
        <strong>${icon} ${time}</strong> | Port ${item.port} |
        Score: ${scoreStr} | <strong>${decision}</strong>${label}
    `;

    feed.insertBefore(div, feed.firstChild);

    while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}
