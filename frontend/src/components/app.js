/* ═══════════════════════════════════════════════════
   CyberNest - Frontend Application
   ═══════════════════════════════════════════════════ */

const API_BASE = '/api/v1';

// ─── Navigation ───

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        const page = item.dataset.page;
        if (!page) return;
        navigateTo(page);
    });
});

document.querySelectorAll('.view-all').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        navigateTo(link.dataset.page);
    });
});

function navigateTo(page) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');

    // Update page
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(`page-${page}`)?.classList.add('active');

    // Update title
    const titles = {
        dashboard: 'Dashboard',
        alerts: 'Alerts',
        events: 'Log Explorer',
        rules: 'Detection Rules',
        incidents: 'Incidents',
        playbooks: 'Playbooks',
        responses: 'Auto Response',
        sources: 'Log Sources',
        settings: 'Settings',
    };
    document.getElementById('pageTitle').textContent = titles[page] || page;

    // Load data for page
    if (page === 'dashboard') loadDashboard();
    if (page === 'alerts') loadAlerts();
    if (page === 'events') loadEvents();
    if (page === 'incidents') loadIncidents();
}

// ─── Mobile Menu ───

document.getElementById('menuToggle')?.addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
});

// ─── API Helpers ───

async function apiGet(endpoint) {
    try {
        const resp = await fetch(`${API_BASE}${endpoint}`);
        if (!resp.ok) throw new Error(`API error: ${resp.status}`);
        return await resp.json();
    } catch (err) {
        console.error(`API GET ${endpoint}:`, err);
        return null;
    }
}

async function apiPost(endpoint, data) {
    try {
        const resp = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (!resp.ok) throw new Error(`API error: ${resp.status}`);
        return await resp.json();
    } catch (err) {
        console.error(`API POST ${endpoint}:`, err);
        return null;
    }
}

async function apiPatch(endpoint, data) {
    try {
        const resp = await fetch(`${API_BASE}${endpoint}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        if (!resp.ok) throw new Error(`API error: ${resp.status}`);
        return await resp.json();
    } catch (err) {
        console.error(`API PATCH ${endpoint}:`, err);
        return null;
    }
}

// ─── Dashboard ───

async function loadDashboard() {
    const stats = await apiGet('/dashboard/stats');
    if (!stats) return;

    document.getElementById('statEvents').textContent = formatNumber(stats.total_events);
    document.getElementById('statAlerts').textContent = formatNumber(stats.open_alerts);
    document.getElementById('statCritical').textContent = formatNumber(stats.critical_alerts);
    document.getElementById('statIncidents').textContent = formatNumber(stats.active_incidents);
    document.getElementById('statPlaybooks').textContent = formatNumber(stats.playbook_runs_today);
    document.getElementById('alertBadge').textContent = stats.open_alerts;

    // Recent alerts
    const alertsContainer = document.getElementById('recentAlertsTable');
    if (stats.recent_alerts && stats.recent_alerts.length > 0) {
        alertsContainer.innerHTML = stats.recent_alerts.map(a => `
            <div class="alert-item">
                <span class="severity ${a.severity}">${a.severity}</span>
                <div class="alert-info">
                    <div class="alert-title">${escapeHtml(a.title)}</div>
                    <div class="alert-time">${formatTime(a.created_at)}</div>
                </div>
            </div>
        `).join('');
    }

    // Render charts
    renderSeverityChart(stats.alerts_by_severity);
    renderTimelineChart(stats.events_per_hour);
}

// ─── Alerts ───

async function loadAlerts() {
    const severity = document.getElementById('alertSeverityFilter')?.value || '';
    const status = document.getElementById('alertStatusFilter')?.value || '';
    let endpoint = '/alerts?limit=100';
    if (severity) endpoint += `&severity=${severity}`;
    if (status) endpoint += `&status=${status}`;

    const alerts = await apiGet(endpoint);
    const tbody = document.getElementById('alertsTableBody');
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No alerts to display</td></tr>';
        return;
    }

    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td>#${a.id}</td>
            <td><span class="severity ${a.severity}">${a.severity}</span></td>
            <td>${escapeHtml(a.title)}</td>
            <td><span class="status ${a.status}">${a.status}</span></td>
            <td>${a.assigned_to || '—'}</td>
            <td>${formatTime(a.created_at)}</td>
            <td>
                <button class="cyber-btn sm" onclick="acknowledgeAlert(${a.id})">Ack</button>
                <button class="cyber-btn sm" onclick="escalateAlert(${a.id})">Escalate</button>
            </td>
        </tr>
    `).join('');
}

function refreshAlerts() { loadAlerts(); }

async function acknowledgeAlert(id) {
    await apiPatch(`/alerts/${id}`, { status: 'acknowledged' });
    loadAlerts();
}

async function escalateAlert(id) {
    // Create incident from alert
    const alert = await apiGet(`/alerts/${id}`);
    if (!alert) return;
    await apiPost('/incidents', {
        title: `Escalated: ${alert.title}`,
        severity: alert.severity,
        description: alert.description,
        alert_ids: [id],
    });
    await apiPatch(`/alerts/${id}`, { status: 'investigating' });
    loadAlerts();
}

// ─── Events ───

async function loadEvents() {
    const events = await apiGet('/events?limit=100');
    const tbody = document.getElementById('eventsTableBody');
    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No events to display. Ingest logs to get started.</td></tr>';
        return;
    }

    tbody.innerHTML = events.map(e => `
        <tr>
            <td>${formatTime(e.timestamp)}</td>
            <td><span class="severity ${e.severity}">${e.severity}</span></td>
            <td>${e.src_ip || '—'}</td>
            <td>${e.dst_ip || '—'}</td>
            <td>${e.hostname || '—'}</td>
            <td>${escapeHtml((e.message || '').substring(0, 80))}</td>
        </tr>
    `).join('');
}

function searchEvents() {
    const query = document.getElementById('eventSearch').value;
    const severity = document.getElementById('eventSeverityFilter').value;
    let endpoint = `/events?limit=100`;
    if (query) endpoint += `&search=${encodeURIComponent(query)}`;
    if (severity) endpoint += `&severity=${severity}`;
    apiGet(endpoint).then(events => {
        const tbody = document.getElementById('eventsTableBody');
        if (!events || events.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No matching events found</td></tr>';
            return;
        }
        tbody.innerHTML = events.map(e => `
            <tr>
                <td>${formatTime(e.timestamp)}</td>
                <td><span class="severity ${e.severity}">${e.severity}</span></td>
                <td>${e.src_ip || '—'}</td>
                <td>${e.dst_ip || '—'}</td>
                <td>${e.hostname || '—'}</td>
                <td>${escapeHtml((e.message || '').substring(0, 80))}</td>
            </tr>
        `).join('');
    });
}

// ─── Incidents ───

async function loadIncidents() {
    const incidents = await apiGet('/incidents?limit=50');
    const tbody = document.getElementById('incidentsTableBody');
    if (!incidents || incidents.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No incidents</td></tr>';
        return;
    }

    tbody.innerHTML = incidents.map(inc => `
        <tr>
            <td>#${inc.id}</td>
            <td><span class="severity ${inc.severity}">${inc.severity}</span></td>
            <td>${escapeHtml(inc.title)}</td>
            <td><span class="status ${inc.status}">${inc.status}</span></td>
            <td>${inc.assigned_to || '—'}</td>
            <td>${formatTime(inc.created_at)}</td>
            <td>
                <button class="cyber-btn sm" onclick="viewIncident(${inc.id})">View</button>
            </td>
        </tr>
    `).join('');
}

async function viewIncident(id) {
    const incident = await apiGet(`/incidents/${id}`);
    if (!incident) return;
    alert(`Incident #${incident.id}\n\nTitle: ${incident.title}\nSeverity: ${incident.severity}\nStatus: ${incident.status}\n\nTimeline: ${incident.timeline.length} entries`);
}

// ─── Modals ───

function openIngestModal() {
    document.getElementById('ingestModal').classList.add('active');
}

function openIncidentModal() {
    document.getElementById('incidentModal').classList.add('active');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
}

async function submitIngestLog() {
    const rawLog = document.getElementById('ingestLogInput').value.trim();
    if (!rawLog) return;

    const result = await apiPost('/events/ingest', { raw_log: rawLog });
    if (result) {
        closeModal('ingestModal');
        document.getElementById('ingestLogInput').value = '';
        loadEvents();
        loadDashboard();
        if (result.alerts_triggered > 0) {
            showNotification(`${result.alerts_triggered} alert(s) triggered!`, 'warning');
        } else {
            showNotification('Log ingested successfully', 'success');
        }
    }
}

async function submitIncident() {
    const data = {
        title: document.getElementById('incidentTitle').value,
        severity: document.getElementById('incidentSeverity').value,
        description: document.getElementById('incidentDescription').value,
        assigned_to: document.getElementById('incidentAssign').value || null,
    };
    if (!data.title) return;

    const result = await apiPost('/incidents', data);
    if (result) {
        closeModal('incidentModal');
        loadIncidents();
        showNotification('Incident created', 'success');
    }
}

// ─── Charts (Simple Canvas) ───

function renderSeverityChart(data) {
    const canvas = document.getElementById('severityChart');
    if (!canvas || !data) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth - 40;
    const h = canvas.height = 180;

    ctx.clearRect(0, 0, w, h);

    const colors = {
        critical: '#ff3355',
        high: '#ff8c00',
        medium: '#ffd700',
        low: '#00d4ff',
        info: '#7a8ba0',
    };

    const entries = Object.entries(data).filter(([, v]) => v > 0);
    const total = entries.reduce((s, [, v]) => s + v, 0) || 1;

    if (entries.length === 0) {
        ctx.fillStyle = '#4a5568';
        ctx.font = '14px Inter';
        ctx.textAlign = 'center';
        ctx.fillText('No alert data', w / 2, h / 2);
        return;
    }

    // Draw donut chart
    const cx = w / 2;
    const cy = h / 2;
    const r = Math.min(w, h) / 2 - 20;
    let startAngle = -Math.PI / 2;

    entries.forEach(([sev, count]) => {
        const sliceAngle = (count / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, startAngle + sliceAngle);
        ctx.arc(cx, cy, r * 0.6, startAngle + sliceAngle, startAngle, true);
        ctx.closePath();
        ctx.fillStyle = colors[sev] || '#7a8ba0';
        ctx.fill();
        startAngle += sliceAngle;
    });

    // Center text
    ctx.fillStyle = '#e0e6ed';
    ctx.font = 'bold 24px JetBrains Mono';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 8);
    ctx.font = '11px Inter';
    ctx.fillStyle = '#7a8ba0';
    ctx.fillText('total', cx, cy + 14);
}

function renderTimelineChart(data) {
    const canvas = document.getElementById('eventTimelineChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement.clientWidth - 40;
    const h = canvas.height = 180;

    ctx.clearRect(0, 0, w, h);

    // Generate sample data if empty
    const points = data && data.length > 0
        ? data.map(d => d.count)
        : Array.from({ length: 24 }, () => Math.floor(Math.random() * 50));

    const max = Math.max(...points, 1);
    const stepX = w / (points.length - 1 || 1);

    // Draw grid lines
    ctx.strokeStyle = 'rgba(30, 48, 72, 0.5)';
    ctx.lineWidth = 1;
    for (let i = 0; i < 4; i++) {
        const y = (h / 4) * i + 10;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
    }

    // Draw line
    ctx.beginPath();
    ctx.strokeStyle = '#00d4ff';
    ctx.lineWidth = 2;
    points.forEach((p, i) => {
        const x = i * stepX;
        const y = h - (p / max) * (h - 20) - 10;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Draw fill
    ctx.lineTo((points.length - 1) * stepX, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, 'rgba(0, 212, 255, 0.15)');
    grad.addColorStop(1, 'rgba(0, 212, 255, 0)');
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw dots
    points.forEach((p, i) => {
        const x = i * stepX;
        const y = h - (p / max) * (h - 20) - 10;
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fillStyle = '#00d4ff';
        ctx.fill();
    });
}

// ─── Notifications ───

function showNotification(message, type = 'info') {
    const notif = document.createElement('div');
    notif.style.cssText = `
        position: fixed; top: 20px; right: 20px; z-index: 2000;
        padding: 14px 20px; border-radius: 10px; font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace; animation: fadeIn 0.3s ease;
        border: 1px solid; backdrop-filter: blur(10px);
    `;

    const colors = {
        success: { bg: 'rgba(0, 255, 136, 0.1)', border: '#00ff88', color: '#00ff88' },
        warning: { bg: 'rgba(255, 140, 0, 0.1)', border: '#ff8c00', color: '#ff8c00' },
        error: { bg: 'rgba(255, 51, 85, 0.1)', border: '#ff3355', color: '#ff3355' },
        info: { bg: 'rgba(0, 212, 255, 0.1)', border: '#00d4ff', color: '#00d4ff' },
    };

    const c = colors[type] || colors.info;
    notif.style.background = c.bg;
    notif.style.borderColor = c.border;
    notif.style.color = c.color;
    notif.textContent = message;

    document.body.appendChild(notif);
    setTimeout(() => notif.remove(), 4000);
}

// ─── Particle Background ───

function initParticles() {
    const canvas = document.getElementById('particleCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    const particles = Array.from({ length: 40 }, () => ({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        size: Math.random() * 2 + 0.5,
    }));

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        particles.forEach(p => {
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0) p.x = canvas.width;
            if (p.x > canvas.width) p.x = 0;
            if (p.y < 0) p.y = canvas.height;
            if (p.y > canvas.height) p.y = 0;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 212, 255, 0.3)';
            ctx.fill();
        });

        // Draw connections
        particles.forEach((a, i) => {
            particles.slice(i + 1).forEach(b => {
                const dx = a.x - b.x;
                const dy = a.y - b.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 150) {
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                    ctx.strokeStyle = `rgba(0, 212, 255, ${0.1 * (1 - dist / 150)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            });
        });

        requestAnimationFrame(animate);
    }
    animate();
}

// ─── WebSocket Live Feed ───

let ws = null;

function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}/ws/alerts/live`);

    ws.onopen = () => {
        console.log('[CyberNest] WebSocket connected');
        document.querySelector('.pulse-dot')?.style.setProperty('background', '#00ff88');
    };

    ws.onmessage = (event) => {
        const alert = JSON.parse(event.data);
        showNotification(`New Alert: ${alert.title}`, alert.severity === 'critical' ? 'error' : 'warning');
        loadDashboard();
    };

    ws.onclose = () => {
        console.log('[CyberNest] WebSocket disconnected, reconnecting...');
        setTimeout(connectWebSocket, 5000);
    };

    ws.onerror = () => {
        console.log('[CyberNest] WebSocket error');
    };
}

// ─── Utilities ───

function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return String(n);
}

function formatTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleString('en-US', {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false,
    });
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ─── Init ───

document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    loadDashboard();
    connectWebSocket();

    // Filter change listeners
    document.getElementById('alertSeverityFilter')?.addEventListener('change', loadAlerts);
    document.getElementById('alertStatusFilter')?.addEventListener('change', loadAlerts);
});
