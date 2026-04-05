/* ═══════════════════════════════���═══════════════════
   CyberNest SIEM — Enterprise Dashboard JS
   ═══════════════════════════════════════════════════ */
const API = '/api/v1';
let charts = {};
let currentAlertFilter = '';
let currentIncidentFilter = '';

// ─── Navigation ───
document.querySelectorAll('.nav-link').forEach(el => {
    el.addEventListener('click', () => navigateTo(el.dataset.page));
});
document.querySelectorAll('.panel-link').forEach(el => {
    el.addEventListener('click', () => navigateTo(el.dataset.page));
});
document.getElementById('sidebarToggle')?.addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
});

const PAGE_NAMES = {
    dashboard: 'Security Dashboard', alerts: 'Alert Management', events: 'Event Explorer',
    threats: 'Threat Intelligence', rules: 'Detection Rules', mitre: 'MITRE ATT&CK',
    incidents: 'Incident Response', playbooks: 'SOAR Playbooks', sources: 'Log Sources', settings: 'Settings'
};

function navigateTo(page) {
    document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
    document.querySelector(`.nav-link[data-page="${page}"]`)?.classList.add('active');
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(`page-${page}`)?.classList.add('active');
    document.getElementById('pageLabel').textContent = PAGE_NAMES[page] || page;
    document.getElementById('sidebar').classList.remove('open');
    loadPageData(page);
}

function loadPageData(page) {
    if (page === 'dashboard') loadDashboard();
    else if (page === 'alerts') loadAlerts();
    else if (page === 'events') loadEvents();
    else if (page === 'threats') loadThreats();
    else if (page === 'rules') loadRules();
    else if (page === 'mitre') loadMitre();
    else if (page === 'incidents') loadIncidents();
    else if (page === 'playbooks') loadPlaybooks();
    else if (page === 'sources') loadSources();
}

// ─── API ───
async function api(endpoint) {
    try { const r = await fetch(`${API}${endpoint}`); return r.ok ? await r.json() : null; }
    catch { return null; }
}
async function apiPost(endpoint, data) {
    try { const r = await fetch(`${API}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }); return r.ok ? await r.json() : null; }
    catch { return null; }
}
async function apiPatch(endpoint, data) {
    try { const r = await fetch(`${API}${endpoint}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }); return r.ok ? await r.json() : null; }
    catch { return null; }
}

// ─── Dashboard ───
async function loadDashboard() {
    const [stats, attackers, targets, hosts, trend, categories] = await Promise.all([
        api('/dashboard/stats'), api('/analytics/top-attackers'), api('/analytics/top-targets'),
        api('/analytics/top-hosts'), api('/analytics/alert-trend'), api('/analytics/events-by-category')
    ]);
    if (!stats) return;

    // KPIs
    animateValue('kpiEvents', stats.total_events);
    animateValue('kpiAlerts', stats.open_alerts);
    animateValue('kpiCritical', stats.critical_alerts);
    animateValue('kpiIncidents', stats.active_incidents);
    animateValue('kpiPlaybooks', stats.playbook_runs_today);
    document.getElementById('navAlertBadge').textContent = stats.open_alerts;
    document.getElementById('notifCount').textContent = stats.open_alerts;

    // EPS simulation
    document.getElementById('epsCounter').textContent = Math.floor(stats.total_events / 24);

    // Source count
    const sources = await api('/sources');
    if (sources) animateValue('kpiSources', sources.length);

    // Charts
    renderTimelineChart(stats.events_per_hour);
    renderSeverityDonut(stats.alerts_by_severity);
    renderAlertTrend(trend);
    renderCategoryChart(categories);

    // Tables
    renderIPTable('topAttackers', attackers);
    renderIPTable('topTargets', targets);
    renderHostTable('topHosts', hosts);
    renderDashAlerts(stats.recent_alerts);

    // MITRE mini
    const mitre = await api('/analytics/mitre-coverage');
    renderMitreMini(mitre);
}

function animateValue(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    const diff = target - start;
    const duration = 600;
    const startTime = performance.now();
    function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + diff * eased);
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function renderTimelineChart(data) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;
    if (charts.timeline) charts.timeline.destroy();
    const labels = data.map(d => d.hour);
    const values = data.map(d => d.count);
    charts.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Events', data: values, fill: true,
                borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,.1)',
                borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, tension: .4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(42,58,85,.3)' }, ticks: { color: '#555d6e', font: { size: 10, family: 'JetBrains Mono' }, maxTicksLimit: 12 } },
                y: { grid: { color: 'rgba(42,58,85,.3)' }, ticks: { color: '#555d6e', font: { size: 10, family: 'JetBrains Mono' } }, beginAtZero: true }
            },
            interaction: { intersect: false, mode: 'index' }
        }
    });
}

function renderSeverityDonut(data) {
    const ctx = document.getElementById('severityDonut');
    if (!ctx) return;
    if (charts.severity) charts.severity.destroy();
    const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#06b6d4', info: '#8b949e' };
    const labels = Object.keys(data);
    const values = Object.values(data);
    charts.severity = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{
                data: values, backgroundColor: labels.map(l => colors[l] || '#555'),
                borderWidth: 0, hoverOffset: 6
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '65%',
            plugins: {
                legend: { display: false },
                tooltip: { titleFont: { family: 'JetBrains Mono' }, bodyFont: { family: 'JetBrains Mono' } }
            }
        }
    });
    // Legend
    const legend = document.getElementById('severityLegend');
    if (legend) {
        legend.innerHTML = labels.map(l =>
            `<span class="leg-item"><span class="leg-dot" style="background:${colors[l]}"></span>${l}: ${data[l]}</span>`
        ).join('');
    }
}

function renderAlertTrend(data) {
    const ctx = document.getElementById('alertTrendChart');
    if (!ctx || !data) return;
    if (charts.trend) charts.trend.destroy();
    charts.trend = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.map(d => d.date),
            datasets: [{
                label: 'Alerts', data: data.map(d => d.count),
                backgroundColor: 'rgba(59,130,246,.6)', borderRadius: 4, barThickness: 24
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#555d6e', font: { size: 10 } } },
                y: { grid: { color: 'rgba(42,58,85,.3)' }, ticks: { color: '#555d6e', font: { size: 10 } }, beginAtZero: true }
            }
        }
    });
}

function renderCategoryChart(data) {
    const ctx = document.getElementById('categoryChart');
    if (!ctx || !data) return;
    if (charts.category) charts.category.destroy();
    const palette = ['#3b82f6', '#06b6d4', '#22c55e', '#eab308', '#f97316', '#a855f7', '#ef4444'];
    charts.category = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.map(d => d.category),
            datasets: [{ data: data.map(d => d.count), backgroundColor: palette.slice(0, data.length), borderWidth: 0 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '55%',
            plugins: { legend: { position: 'right', labels: { color: '#8b949e', font: { size: 11 }, padding: 8, boxWidth: 12 } } }
        }
    });
}

function renderIPTable(containerId, data) {
    const el = document.getElementById(containerId);
    if (!el || !data) return;
    if (!data.length) { el.innerHTML = '<div class="loading-state">No data</div>'; return; }
    const max = data[0]?.count || 1;
    el.innerHTML = data.map(d => `
        <div class="ip-row">
            <span class="ip-addr">${esc(d.ip)}</span>
            <div class="ip-bar"><div class="ip-bar-fill" style="width:${(d.count/max*100).toFixed(0)}%"></div></div>
            <span class="ip-count">${d.count}</span>
        </div>
    `).join('');
}

function renderHostTable(containerId, data) {
    const el = document.getElementById(containerId);
    if (!el || !data) return;
    if (!data.length) { el.innerHTML = '<div class="loading-state">No data</div>'; return; }
    const max = data[0]?.count || 1;
    el.innerHTML = data.map(d => `
        <div class="ip-row">
            <span class="ip-addr">${esc(d.hostname)}</span>
            <div class="ip-bar"><div class="ip-bar-fill" style="width:${(d.count/max*100).toFixed(0)}%"></div></div>
            <span class="ip-count">${d.count}</span>
        </div>
    `).join('');
}

function renderDashAlerts(alerts) {
    const tbody = document.getElementById('dashRecentAlerts');
    if (!tbody) return;
    if (!alerts?.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">No recent alerts</td></tr>'; return; }
    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td><span class="sev sev-${a.severity}">${a.severity}</span></td>
            <td>${esc(a.title)}</td>
            <td><span class="stat stat-${a.status}">${a.status}</span></td>
            <td style="font-family:var(--font-mono)">${a.ioc_data?.src_ip || '—'}</td>
            <td style="font-family:var(--font-mono)">${fmtTime(a.created_at)}</td>
        </tr>
    `).join('');
}

function renderMitreMini(data) {
    const el = document.getElementById('mitreMini');
    if (!el || !data) return;
    el.innerHTML = Object.entries(data).map(([tactic, techs]) => `
        <div class="mitre-tactic-card">
            <div class="mitre-tactic-name">${esc(tactic)}</div>
            <div class="mitre-tech-list">
                ${techs.map(t => `<span class="mitre-tech ${t.severity === 'critical' ? 'crit' : t.severity === 'high' ? 'high' : ''}" title="${esc(t.rule)}">${esc(t.technique)}</span>`).join('')}
            </div>
        </div>
    `).join('');
}

// ─── Alerts Page ───
async function loadAlerts() {
    let url = '/alerts?limit=100';
    if (currentAlertFilter && currentAlertFilter !== 'all') url += `&status=${currentAlertFilter}`;
    const sev = document.getElementById('alertSevFilter')?.value;
    if (sev) url += `&severity=${sev}`;
    const alerts = await api(url);
    const tbody = document.getElementById('alertsTableBody');
    if (!alerts?.length) { tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No alerts found</td></tr>'; return; }
    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td style="font-family:var(--font-mono)">${a.id}</td>
            <td><span class="sev sev-${a.severity}">${a.severity}</span></td>
            <td>${esc(a.title)}</td>
            <td><span class="stat stat-${a.status}">${a.status}</span></td>
            <td>${a.assigned_to || '—'}</td>
            <td style="font-family:var(--font-mono)">${fmtTime(a.created_at)}</td>
            <td>
                <button class="btn btn-xs btn-outline" onclick="ackAlert(${a.id})">Ack</button>
                <button class="btn btn-xs btn-primary" onclick="escalateAlert(${a.id})">Escalate</button>
            </td>
        </tr>
    `).join('');
}

function filterAlerts(status) {
    currentAlertFilter = status;
    document.querySelectorAll('#page-alerts .pill').forEach(p => p.classList.toggle('active', p.dataset.filter === status));
    loadAlerts();
}

async function ackAlert(id) {
    await apiPatch(`/alerts/${id}`, { status: 'acknowledged' });
    toast('Alert acknowledged', 'success');
    loadAlerts();
}

async function escalateAlert(id) {
    const alert = await api(`/alerts/${id}`);
    if (!alert) return;
    await apiPost('/incidents', { title: `Escalated: ${alert.title}`, severity: alert.severity, description: alert.description, alert_ids: [id] });
    await apiPatch(`/alerts/${id}`, { status: 'investigating' });
    toast('Alert escalated to incident', 'warning');
    loadAlerts();
}

document.getElementById('alertSevFilter')?.addEventListener('change', loadAlerts);

// ─── Events Page ───
async function loadEvents() {
    const events = await api('/events?limit=100');
    renderEventsTable(events);
}

function searchEvents() {
    const q = document.getElementById('eventSearchInput')?.value || '';
    const sev = document.getElementById('evtSevFilter')?.value || '';
    let url = '/events?limit=100';
    if (q) url += `&search=${encodeURIComponent(q)}`;
    if (sev) url += `&severity=${sev}`;
    api(url).then(renderEventsTable);
}

function renderEventsTable(events) {
    const tbody = document.getElementById('eventsTableBody');
    const count = document.getElementById('eventCount');
    if (!events?.length) { tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No events found</td></tr>'; if (count) count.textContent = '0 events'; return; }
    if (count) count.textContent = `${events.length} events`;
    tbody.innerHTML = events.map(e => `
        <tr>
            <td>${fmtTime(e.timestamp)}</td>
            <td><span class="sev sev-${e.severity}">${e.severity}</span></td>
            <td>${e.src_ip || '—'}</td>
            <td>${e.dst_ip || '—'}</td>
            <td>${e.hostname || '—'}</td>
            <td title="${esc(e.message || '')}">${esc((e.message || '').substring(0, 100))}</td>
        </tr>
    `).join('');
}

// ─── Threats Page ───
async function loadThreats() {
    const [attackers, targets, sevData] = await Promise.all([
        api('/analytics/top-attackers'), api('/analytics/top-targets'), api('/analytics/events-by-severity')
    ]);
    renderIPTable('threatAttackers', attackers);
    renderIPTable('threatTargets', targets);
    const ctx = document.getElementById('threatSevChart');
    if (ctx && sevData) {
        if (charts.threatSev) charts.threatSev.destroy();
        const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#06b6d4', info: '#8b949e' };
        charts.threatSev = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sevData.map(d => d.severity),
                datasets: [{ data: sevData.map(d => d.count), backgroundColor: sevData.map(d => colors[d.severity] || '#555'), borderRadius: 4 }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: { x: { grid: { color: 'rgba(42,58,85,.3)' }, ticks: { color: '#555d6e' } }, y: { grid: { display: false }, ticks: { color: '#c9d1d9', font: { size: 11 } } } }
            }
        });
    }
}

// ─── Rules Page ───
async function loadRules() {
    const rules = await api('/rules');
    const el = document.getElementById('rulesList');
    if (!rules?.length) { el.innerHTML = '<div class="loading-state">No detection rules configured</div>'; return; }
    el.innerHTML = rules.map(r => `
        <div class="rule-card">
            <div class="rule-sev"><span class="sev sev-${r.severity?.value || r.severity}">${r.severity?.value || r.severity}</span></div>
            <div class="rule-body">
                <div class="rule-name">${esc(r.name)}</div>
                <div class="rule-desc">${esc(r.description || '')}</div>
                <div class="rule-meta">
                    <span>${r.mitre_tactic || 'N/A'}</span>
                    <span>${r.mitre_technique || 'N/A'}</span>
                </div>
            </div>
            <div class="rule-toggle">
                <label class="switch"><input type="checkbox" ${r.enabled ? 'checked' : ''}><span class="switch-slider"></span></label>
            </div>
        </div>
    `).join('');
}

// ─── MITRE Page ───
async function loadMitre() {
    const data = await api('/analytics/mitre-coverage');
    const el = document.getElementById('mitreMatrix');
    if (!el || !data) return;
    el.innerHTML = Object.entries(data).map(([tactic, techs]) => `
        <div class="mitre-tactic-card">
            <div class="mitre-tactic-name">${esc(tactic)}</div>
            <div class="mitre-tech-list">
                ${techs.map(t => `<span class="mitre-tech ${t.severity === 'critical' ? 'crit' : t.severity === 'high' ? 'high' : ''}" title="${esc(t.rule)}">${esc(t.technique)}</span>`).join('')}
            </div>
        </div>
    `).join('');
}

// ─── Incidents Page ───
async function loadIncidents() {
    let url = '/incidents?limit=50';
    if (currentIncidentFilter) url += `&status=${currentIncidentFilter}`;
    const incidents = await api(url);
    const tbody = document.getElementById('incidentsTableBody');
    if (!incidents?.length) { tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No incidents</td></tr>'; return; }
    tbody.innerHTML = incidents.map(inc => `
        <tr>
            <td style="font-family:var(--font-mono)">${inc.id}</td>
            <td><span class="sev sev-${inc.severity}">${inc.severity}</span></td>
            <td>${esc(inc.title)}</td>
            <td><span class="stat stat-${inc.status}">${inc.status}</span></td>
            <td>${inc.assigned_to || '—'}</td>
            <td style="font-family:var(--font-mono)">${fmtTime(inc.created_at)}</td>
            <td><button class="btn btn-xs btn-outline" onclick="viewIncident(${inc.id})">View</button></td>
        </tr>
    `).join('');
}

function filterIncidents(status) {
    currentIncidentFilter = status;
    document.querySelectorAll('#page-incidents .pill').forEach(p => p.classList.remove('active'));
    event.target.classList.add('active');
    loadIncidents();
}

async function viewIncident(id) {
    const inc = await api(`/incidents/${id}`);
    if (!inc) return;
    const tl = inc.timeline.map(t => `  [${t.timestamp?.slice(0, 19) || ''}] ${t.action}: ${t.details}`).join('\n');
    alert(`INCIDENT #${inc.id}\n\nTitle: ${inc.title}\nSeverity: ${inc.severity}\nStatus: ${inc.status}\nAssigned: ${inc.assigned_to || 'Unassigned'}\n\nTimeline:\n${tl}`);
}

// ─── Playbooks Page ───
const PB_ICONS = { 'Block Malicious IP': 'fa-ban', 'Disable Compromised Account': 'fa-user-slash', 'Isolate Infected Host': 'fa-laptop-medical', 'Phishing Response': 'fa-envelope-open-text', 'IOC Enrichment': 'fa-magnifying-glass-plus', 'Incident Report Generator': 'fa-file-lines' };

async function loadPlaybooks() {
    const [playbooks, runs] = await Promise.all([api('/playbooks'), api('/playbooks/runs')]);
    const grid = document.getElementById('playbookGrid');
    if (grid && playbooks?.length) {
        grid.innerHTML = playbooks.map(pb => `
            <div class="pb-card">
                <div class="pb-card-top">
                    <div class="pb-icon"><i class="fas ${PB_ICONS[pb.name] || 'fa-play'}"></i></div>
                    <h4>${esc(pb.name)}</h4>
                </div>
                <p>${esc(pb.description || '')}</p>
                <div class="pb-tags">
                    <span class="pb-tag">${pb.trigger_type}</span>
                    <span class="pb-tag">${pb.steps?.length || 0} steps</span>
                </div>
                <div class="pb-footer">
                    <span class="pb-trigger">${pb.enabled ? 'ENABLED' : 'DISABLED'}</span>
                    <button class="btn btn-xs btn-primary" onclick="runPlaybook(${pb.id})"><i class="fas fa-play"></i> Run</button>
                </div>
            </div>
        `).join('');
    }
    const tbody = document.getElementById('playbookRunsBody');
    if (tbody && runs?.length) {
        tbody.innerHTML = runs.map(r => `
            <tr>
                <td style="font-family:var(--font-mono)">${r.id}</td>
                <td>${r.playbook_id}</td>
                <td><span class="stat stat-${r.status === 'completed' ? 'resolved' : r.status === 'failed' ? 'new' : 'investigating'}">${r.status}</span></td>
                <td style="font-family:var(--font-mono)">${fmtTime(r.started_at)}</td>
                <td style="font-family:var(--font-mono)">${r.completed_at ? fmtTime(r.completed_at) : '—'}</td>
                <td>${r.step_results?.length || 0}</td>
            </tr>
        `).join('');
    }
}

async function runPlaybook(id) {
    const result = await apiPost(`/playbooks/${id}/run`, {});
    if (result) {
        toast(`Playbook executed: ${result.status}`, result.status === 'completed' ? 'success' : 'error');
        loadPlaybooks();
    }
}

// ─── Sources Page ───
const SRC_ICONS = { syslog: 'fa-scroll', agent: 'fa-desktop', api: 'fa-plug', file: 'fa-file-lines' };

async function loadSources() {
    const sources = await api('/sources');
    const grid = document.getElementById('sourceGrid');
    if (!grid) return;
    if (!sources?.length) { grid.innerHTML = '<div class="loading-state">No log sources configured</div>'; return; }
    grid.innerHTML = sources.map(s => `
        <div class="src-card">
            <div class="src-icon"><i class="fas ${SRC_ICONS[s.source_type] || 'fa-server'}"></i></div>
            <div class="src-info">
                <div class="src-name">${esc(s.name)}</div>
                <div class="src-meta">${s.source_type}${s.host ? ' • ' + s.host : ''}${s.port ? ':' + s.port : ''}</div>
            </div>
            <div class="src-status ${s.enabled ? 'active' : 'inactive'}"></div>
        </div>
    `).join('');
}

// ──��� Modals ─��─
function openIngestModal() { document.getElementById('ingestModal').classList.add('active'); }
function openIncidentModal() { document.getElementById('incidentModal').classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

async function submitIngest() {
    const raw = document.getElementById('ingestInput').value.trim();
    if (!raw) return;
    const result = await apiPost('/events/ingest', { raw_log: raw });
    if (result) {
        closeModal('ingestModal');
        document.getElementById('ingestInput').value = '';
        toast(result.alerts_triggered > 0 ? `${result.alerts_triggered} alert(s) triggered!` : 'Log ingested', result.alerts_triggered > 0 ? 'warning' : 'success');
        loadEvents();
    }
}

async function submitIncident() {
    const data = {
        title: document.getElementById('incTitle').value,
        severity: document.getElementById('incSeverity').value,
        description: document.getElementById('incDesc').value,
        assigned_to: document.getElementById('incAssign').value || null,
    };
    if (!data.title) return;
    const result = await apiPost('/incidents', data);
    if (result) { closeModal('incidentModal'); toast('Incident created', 'success'); loadIncidents(); }
}

// ─── Toast Notifications ───
function toast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

// ─── WebSocket ───
function connectWS() {
    try {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${proto}//${location.host}/ws/alerts/live`);
        ws.onmessage = e => {
            const alert = JSON.parse(e.data);
            toast(`Alert: ${alert.title}`, 'warning');
            loadDashboard();
        };
        ws.onclose = () => setTimeout(connectWS, 5000);
    } catch {}
}

// ─── Utilities ───
function fmtTime(ts) {
    if (!ts) return '—';
    return new Date(ts).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}
function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// ─── Keyboard Shortcut ───
document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        document.getElementById('globalSearch')?.focus();
    }
});

// ─── Auto-refresh ───
let refreshInterval;
function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        const activePage = document.querySelector('.page.active')?.id?.replace('page-', '');
        if (activePage === 'dashboard') loadDashboard();
    }, 30000);
}

// ─── Init ───
document.addEventListener('DOMContentLoaded', () => {
    loadDashboard();
    connectWS();
    startAutoRefresh();
});
