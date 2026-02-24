/* ── Defmon — Dashboard JavaScript ────────────────────────────────── */

const API = '';   // same origin
let ws = null;
let map = null;
let mapMarkers = [];
let chartTimeline = null;
let chartAttacks = null;
let chartSeverity = null;
let authToken = null;
let currentUser = null;

// ── Initialization ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('footer-year').textContent = new Date().getFullYear();

    // Check for saved session
    const saved = localStorage.getItem('defmon_token');
    if (saved) {
        authToken = saved;
        currentUser = JSON.parse(localStorage.getItem('defmon_user') || '{}');
        showDashboard();
    }
});

// ── Authentication ──────────────────────────────────────────────────
async function handleLogin(event) {
    event.preventDefault();
    const username = document.getElementById('login-user').value;
    const password = document.getElementById('login-pass').value;
    const errorEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    btn.disabled = true;
    btn.textContent = 'Signing in…';
    errorEl.textContent = '';

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) {
            errorEl.textContent = data.detail || 'Login failed';
            return;
        }
        authToken = data.token;
        currentUser = data.user;
        localStorage.setItem('defmon_token', authToken);
        localStorage.setItem('defmon_user', JSON.stringify(currentUser));
        showDashboard();
    } catch (e) {
        errorEl.textContent = 'Connection error';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Sign In';
    }
}

function handleLogout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('defmon_token');
    localStorage.removeItem('defmon_user');
    document.getElementById('login-page').style.display = 'flex';
    document.getElementById('dashboard-page').style.display = 'none';
    if (ws) ws.close();
}

function showDashboard() {
    document.getElementById('login-page').style.display = 'none';
    document.getElementById('dashboard-page').style.display = 'block';
    document.getElementById('user-info').textContent =
        `${currentUser.full_name || currentUser.username} (${currentUser.role})`;
    startClock();
    initMap();
    connectWebSocket();
    refreshAll();
    setInterval(refreshAll, 10000);
}

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
        if (authToken) setTimeout(connectWebSocket, 3000);
    };
    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'alert') {
            addToLiveFeed(msg.data);
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
    while (feed.children.length > 100) feed.removeChild(feed.lastChild);

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
        loadLockedAccounts();
        loadThreatIntel();
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
    document.getElementById('kpi-locked').textContent = formatNum(stats.total_locked_accounts || 0);
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

    renderTopIPs(stats.top_ips || []);
}

// ── Tables ──────────────────────────────────────────────────────────
function renderAlerts(alerts) {
    const tbody = document.querySelector('#table-alerts tbody');
    tbody.innerHTML = alerts.map(a => `
        <tr class="clickable" onclick="openAlertDetail('${a.id}')">
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
            <td><button class="btn-sm btn-ti" onclick="lookupThreatIPDirect('${ip.ip}')">🕵️ Intel</button></td>
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
        <tr class="clickable" onclick="openIncidentDetail('${i.id}')">
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
            <td><span class="badge badge-${a.action_type === 'block_ip' ? 'critical' : a.action_type === 'lock_account' ? 'high' : 'medium'}">${a.action_type}</span></td>
            <td><code>${a.target}</code></td>
            <td>${truncate(a.detail, 80)}</td>
        </tr>
    `).join('');
}

async function loadLockedAccounts() {
    const accounts = await fetchJSON('/api/locked-accounts');
    const tbody = document.querySelector('#table-locked tbody');
    tbody.innerHTML = accounts.map(a => `
        <tr>
            <td><strong>${a.username}</strong></td>
            <td><code>${a.source_ip || '—'}</code></td>
            <td>${truncate(a.reason, 60)}</td>
            <td>${formatTime(a.locked_at)}</td>
            <td>
                ${a.status === 'locked'
                    ? `<button class="btn-sm btn-unlock" onclick="unlockAccount(${a.id})">🔓 Unlock</button>`
                    : '<span class="badge badge-low">unlocked</span>'}
            </td>
        </tr>
    `).join('');
}

async function unlockAccount(id) {
    await fetch(`/api/locked-accounts/${id}`, { method: 'DELETE' });
    loadLockedAccounts();
}

async function loadThreatIntel() {
    const data = await fetchJSON('/api/threat-intel');
    const stats = data.stats || {};
    const el = document.getElementById('threat-intel-stats');
    el.innerHTML = `
        <div class="ti-stat"><span class="ti-num">${stats.total_indicators || 0}</span> Total Indicators</div>
        <div class="ti-stat"><span class="ti-num ti-mal">${stats.by_reputation?.malicious || 0}</span> Malicious</div>
        <div class="ti-stat"><span class="ti-num ti-sus">${stats.by_reputation?.suspicious || 0}</span> Suspicious</div>
    `;
}

async function lookupThreatIP() {
    const ip = document.getElementById('ti-lookup-ip').value.trim();
    if (!ip) return;
    lookupThreatIPDirect(ip);
}

async function lookupThreatIPDirect(ip) {
    const data = await fetchJSON(`/api/threat-intel/lookup/${ip}`);
    const el = document.getElementById('ti-lookup-result');
    if (!data.found) {
        el.innerHTML = `<div class="ti-result ti-clean">✅ <code>${ip}</code> — No threat data found (clean)</div>`;
    } else {
        const d = data.data;
        el.innerHTML = `
            <div class="ti-result ti-${d.reputation}">
                <strong>${d.reputation.toUpperCase()}</strong> — <code>${ip}</code><br>
                Source: ${d.source} | Tags: ${(d.tags || []).join(', ') || 'none'}
            </div>
        `;
    }
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
        <tr class="clickable" onclick="openLogDetail(${l.id})">
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
    alert(`IP ${ip} is already being managed by SOAR automation.`);
}

async function exportReport(type, format) {
    window.open(`/api/reports/${type}?format=${format}`, '_blank');
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

// ── Detail Modals ───────────────────────────────────────────────
function openModal(id) {
    document.getElementById(id).classList.add('open');
    document.addEventListener('keydown', _escClose);
}
function closeModal(id) {
    document.getElementById(id).classList.remove('open');
    document.removeEventListener('keydown', _escClose);
}
function _escClose(e) {
    if (e.key === 'Escape') {
        ['log-modal','alert-modal','incident-modal'].forEach(closeModal);
    }
}

function detailRow(key, val) {
    const empty = (val === null || val === undefined || val === '');
    return `
        <div class="detail-key">${key}</div>
        <div class="detail-val${empty ? ' detail-empty' : ''}">${empty ? 'none' : escapeHtml(String(val))}</div>
    `;
}
function detailSection(title) {
    return `<div class="detail-section-title">${title}</div>`;
}

async function openLogDetail(id) {
    const log = await fetchJSON(`/api/logs/${id}`);
    const statusColor = log.status_code >= 500 ? 'var(--critical)' : log.status_code >= 400 ? 'var(--medium)' : 'var(--low)';
    document.getElementById('log-modal-body').innerHTML = `
        <div class="detail-grid">
            ${detailSection('Request')}
            ${detailRow('ID', log.id)}
            ${detailRow('Timestamp', log.timestamp)}
            ${detailRow('Log Source', log.log_source)}
            ${detailRow('Method', log.method)}
            ${detailRow('URL', log.url)}
            ${detailRow('Status Code', log.status_code)}
            ${detailRow('POST Body', log.body)}
            ${detailSection('Client')}
            ${detailRow('Source IP', log.source_ip)}
            ${detailRow('User Agent', log.user_agent)}
            ${detailRow('Country', log.country)}
            ${detailRow('City', log.city)}
            ${detailRow('Latitude', log.latitude)}
            ${detailRow('Longitude', log.longitude)}
            ${detailSection('Raw Log Line')}
            ${detailRow('raw_line', log.raw_line)}
        </div>
    `;
    openModal('log-modal');
}

async function openAlertDetail(id) {
    const a = await fetchJSON(`/api/alerts/${id}`);
    document.getElementById('alert-modal-body').innerHTML = `
        <div class="detail-grid">
            ${detailSection('Alert Info')}
            ${detailRow('ID', a.id)}
            ${detailRow('Timestamp', a.timestamp)}
            ${detailRow('Rule ID', a.rule_id)}
            ${detailRow('Rule Name', a.rule_name)}
            ${detailRow('Severity', a.severity)}
            ${detailRow('Risk Score', a.risk_score)}
            ${detailRow('Status', a.status)}
            ${detailSection('Attack Details')}
            ${detailRow('Source IP', a.source_ip)}
            ${detailRow('Country', a.country)}
            ${detailRow('Latitude', a.latitude)}
            ${detailRow('Longitude', a.longitude)}
            ${detailRow('Description', a.description)}
            ${detailSection('MITRE ATT\u0026CK')}
            ${detailRow('Tactic', a.mitre_tactic)}
            ${detailRow('Technique', a.mitre_technique)}
            ${detailRow('Name', a.mitre_name)}
            ${detailSection('Evidence / Raw Log')}
            ${detailRow('evidence', a.evidence)}
            ${detailSection('Analyst Notes')}
            ${detailRow('Incident ID', a.incident_id)}
            ${detailRow('Notes', a.analyst_notes)}
        </div>
    `;
    openModal('alert-modal');
}

async function openIncidentDetail(id) {
    const i = await fetchJSON(`/api/incidents/${id}`);
    document.getElementById('incident-modal-body').innerHTML = `
        <div class="detail-grid">
            ${detailSection('Incident Info')}
            ${detailRow('ID', i.id)}
            ${detailRow('Created At', i.created_at)}
            ${detailRow('Updated At', i.updated_at)}
            ${detailRow('Title', i.title)}
            ${detailRow('Severity', i.severity)}
            ${detailRow('Status', i.status)}
            ${detailRow('Attack Type', i.attack_type)}
            ${detailSection('Source / Context')}
            ${detailRow('Source IP', i.source_ip)}
            ${detailRow('Description', i.description)}
            ${detailSection('MITRE ATT\u0026CK')}
            ${detailRow('Tactic', i.mitre_tactic)}
            ${detailRow('Technique', i.mitre_technique)}
            ${detailSection('Analyst Notes')}
            ${detailRow('Notes', i.analyst_notes)}
        </div>
    `;
    openModal('incident-modal');
}
