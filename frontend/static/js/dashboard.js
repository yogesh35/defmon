/* ── Mini SIEM + SOAR — Dashboard JavaScript ─────────────────────── */

const API = '';   // same origin
let ws = null;
let map = null;
let mapMarkers = [];
let chartTimeline = null;
let chartAttacks = null;
let chartSeverity = null;

// ── Initialization ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('footer-year').textContent = new Date().getFullYear();
    startClock();
    initMap();
    connectWebSocket();
    refreshAll();
    setInterval(refreshAll, 10000); // refresh every 10s
});

function startClock() {
    const el = document.getElementById('clock');
    setInterval(() => {
        el.textContent = new Date().toLocaleTimeString();
    }, 1000);
}

// ── WebSocket ───────────────────────────────────────────────────────
function connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${proto}://${location.host}/ws/live-feed`);

    ws.onopen = () => {
        document.getElementById('ws-status').className = 'ws-dot connected';
    };
    ws.onclose = () => {
        document.getElementById('ws-status').className = 'ws-dot disconnected';
        setTimeout(connectWebSocket, 3000);
    };
    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'alert') {
            addToLiveFeed(msg.data);
            // Quick KPI bump
            const el = document.getElementById('kpi-alerts');
            el.textContent = parseInt(el.textContent || '0') + 1;
        }
    };
}

function addToLiveFeed(data) {
    const feed = document.getElementById('live-feed');
    const sevColors = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
    const item = document.createElement('div');
    item.className = 'feed-item';
    item.innerHTML = `
        <span class="feed-time">${formatTime(data.timestamp)}</span>
        <span>${sevColors[data.severity] || '⚪'}</span>
        <span class="feed-msg">
            <strong>${data.rule_name}</strong> from
            <code>${data.source_ip}</code>
            ${data.country ? `(${data.country})` : ''}
            — ${data.actions_taken?.join(', ') || ''}
            ${data.mitre_technique ? `<span style="color:var(--text-dim)">[${data.mitre_technique}]</span>` : ''}
        </span>
    `;
    feed.prepend(item);
    // Keep max 100 items
    while (feed.children.length > 100) feed.removeChild(feed.lastChild);

    // Add map marker
    if (data.latitude && data.longitude) {
        addMapMarker(data);
    }
}

// ── Map ─────────────────────────────────────────────────────────────
function initMap() {
    map = L.map('geo-map', {
        center: [20, 0], zoom: 2,
        zoomControl: true, attributionControl: false,
    });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 18,
    }).addTo(map);
}

function addMapMarker(data) {
    const color = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[data.severity] || '#3b82f6';
    const marker = L.circleMarker([data.latitude, data.longitude], {
        radius: 6, color: color, fillColor: color, fillOpacity: 0.7, weight: 1,
    }).addTo(map);
    marker.bindPopup(`<b>${data.source_ip}</b><br>${data.country || ''}<br>${data.rule_name || ''}`);
    mapMarkers.push(marker);
}

function loadGeoPoints(points) {
    // Clear old markers
    mapMarkers.forEach(m => map.removeLayer(m));
    mapMarkers = [];
    points.forEach(p => {
        addMapMarker({ latitude: p.lat, longitude: p.lng, severity: p.severity,
                       source_ip: p.ip, country: p.country, rule_name: `${p.count} alerts` });
    });
}

// ── Data Loading ────────────────────────────────────────────────────
async function refreshAll() {
    try {
        const stats = await fetchJSON('/api/stats');
        updateKPIs(stats);
        updateCharts(stats);
        loadGeoPoints(stats.geo_points || []);
        renderAlerts(stats.recent_alerts || []);
        loadIncidents();
        loadActions();
    } catch (e) {
        console.error('Refresh failed:', e);
    }
}

async function fetchJSON(url) {
    const res = await fetch(API + url);
    return res.json();
}

function updateKPIs(stats) {
    document.getElementById('kpi-logs').textContent = formatNum(stats.total_logs);
    document.getElementById('kpi-alerts').textContent = formatNum(stats.total_alerts);
    document.getElementById('kpi-open').textContent = formatNum(stats.open_alerts);
    document.getElementById('kpi-incidents').textContent = formatNum(stats.total_incidents);
    document.getElementById('kpi-blocked').textContent = formatNum(stats.total_blocked);
}

// ── Charts ──────────────────────────────────────────────────────────
function updateCharts(stats) {
    // Timeline
    const tl = stats.timeline || [];
    const tlData = { labels: tl.map(t => t.time), datasets: [{
        label: 'Alerts', data: tl.map(t => t.count),
        borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.15)',
        fill: true, tension: 0.3,
    }]};
    if (chartTimeline) { chartTimeline.data = tlData; chartTimeline.update(); }
    else {
        chartTimeline = new Chart(document.getElementById('chart-timeline'), {
            type: 'line', data: tlData,
            options: { responsive: true, scales: { y: { beginAtZero: true, ticks: { color: '#94a3b8' } },
                       x: { ticks: { color: '#94a3b8', maxRotation: 45 } } },
                       plugins: { legend: { display: false } } },
        });
    }

    // Attack type distribution
    const rules = stats.by_rule || {};
    const ruleLabels = Object.keys(rules);
    const ruleColors = ruleLabels.map((_, i) => [
        '#ef4444','#f97316','#eab308','#22c55e','#06b6d4','#8b5cf6','#ec4899','#64748b'
    ][i % 8]);
    const attackData = { labels: ruleLabels, datasets: [{
        data: Object.values(rules), backgroundColor: ruleColors,
    }]};
    if (chartAttacks) { chartAttacks.data = attackData; chartAttacks.update(); }
    else {
        chartAttacks = new Chart(document.getElementById('chart-attacks'), {
            type: 'doughnut', data: attackData,
            options: { responsive: true, plugins: {
                legend: { position: 'right', labels: { color: '#e2e8f0', font: { size: 11 } } }
            }},
        });
    }

    // Severity breakdown
    const sevOrder = ['critical', 'high', 'medium', 'low'];
    const sevColors = ['#ef4444', '#f97316', '#eab308', '#22c55e'];
    const sev = stats.by_severity || {};
    const sevData = { labels: sevOrder, datasets: [{
        data: sevOrder.map(s => sev[s] || 0), backgroundColor: sevColors,
    }]};
    if (chartSeverity) { chartSeverity.data = sevData; chartSeverity.update(); }
    else {
        chartSeverity = new Chart(document.getElementById('chart-severity'), {
            type: 'bar', data: sevData,
            options: { responsive: true, indexAxis: 'y',
                       scales: { x: { beginAtZero: true, ticks: { color: '#94a3b8' } },
                                 y: { ticks: { color: '#94a3b8' } } },
                       plugins: { legend: { display: false } } },
        });
    }

    // Top IPs table
    renderTopIPs(stats.top_ips || []);
}

// ── Tables ──────────────────────────────────────────────────────────
function renderAlerts(alerts) {
    const tbody = document.querySelector('#table-alerts tbody');
    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td>${formatTime(a.timestamp)}</td>
            <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
            <td>${a.rule_name}</td>
            <td><code>${a.source_ip}</code></td>
            <td title="${escapeHtml(a.description)}">${truncate(a.description, 60)}</td>
            <td>${a.mitre_technique || '—'}</td>
            <td><span class="badge badge-${a.status}">${a.status}</span></td>
        </tr>
    `).join('');
}

function renderTopIPs(ips) {
    const tbody = document.querySelector('#table-ips tbody');
    tbody.innerHTML = ips.map(ip => `
        <tr>
            <td><code>${ip.ip}</code></td>
            <td>${ip.count}</td>
            <td><button class="btn-sm" onclick="blockIP('${ip.ip}')">Block</button></td>
        </tr>
    `).join('');
}

async function loadAlerts() {
    const sev = document.getElementById('filter-severity').value;
    const ip = document.getElementById('filter-ip').value;
    let url = '/api/alerts?limit=50';
    if (sev) url += `&severity=${sev}`;
    if (ip) url += `&source_ip=${ip}`;
    const alerts = await fetchJSON(url);
    renderAlerts(alerts);
}

async function loadIncidents() {
    const incidents = await fetchJSON('/api/incidents?limit=20');
    const tbody = document.querySelector('#table-incidents tbody');
    tbody.innerHTML = incidents.map(i => `
        <tr>
            <td><code>${i.id.substring(0,8)}…</code></td>
            <td>${formatTime(i.created_at)}</td>
            <td><span class="badge badge-${i.severity}">${i.severity}</span></td>
            <td>${truncate(i.title, 50)}</td>
            <td><span class="badge badge-${i.status}">${i.status}</span></td>
            <td>${i.mitre_technique || '—'}</td>
        </tr>
    `).join('');
}

async function loadActions() {
    const actions = await fetchJSON('/api/response-actions?limit=30');
    const tbody = document.querySelector('#table-actions tbody');
    tbody.innerHTML = actions.map(a => `
        <tr>
            <td>${formatTime(a.timestamp)}</td>
            <td><span class="badge badge-${a.action_type === 'block_ip' ? 'critical' : 'medium'}">${a.action_type}</span></td>
            <td><code>${a.target}</code></td>
            <td>${truncate(a.detail, 80)}</td>
        </tr>
    `).join('');
}

async function loadLogs() {
    const ip = document.getElementById('log-ip').value;
    const url_contains = document.getElementById('log-url').value;
    const source = document.getElementById('log-source').value;
    let u = '/api/logs?limit=100';
    if (ip) u += `&source_ip=${ip}`;
    if (url_contains) u += `&url_contains=${encodeURIComponent(url_contains)}`;
    if (source) u += `&log_source=${source}`;
    const logs = await fetchJSON(u);
    const tbody = document.querySelector('#table-logs tbody');
    tbody.innerHTML = logs.map(l => `
        <tr>
            <td>${formatTime(l.timestamp)}</td>
            <td><code>${l.source_ip}</code></td>
            <td>${l.method}</td>
            <td title="${escapeHtml(l.url)}">${truncate(l.url, 60)}</td>
            <td>${l.status_code}</td>
            <td>${l.log_source}</td>
        </tr>
    `).join('');
}

async function blockIP(ip) {
    // This is visual-only — actual blocking is handled by SOAR playbooks
    alert(`IP ${ip} is already being managed by SOAR automation.`);
}

// ── Utilities ───────────────────────────────────────────────────────
function formatTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleTimeString();
}

function formatNum(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return String(n);
}

function truncate(s, len) {
    if (!s) return '';
    return s.length > len ? s.substring(0, len) + '…' : s;
}

function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
