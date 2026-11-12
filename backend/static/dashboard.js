// dashboard.js — PUF Drone Authentication Dashboard

const POLL_INTERVAL = 5000;
let selectedDrone = null;
let fleetData = {};

// ── SSE ──────────────────────────────────────────────────────────────────────
const es = new EventSource('/events');

es.onmessage = (e) => {
  try {
    const msg = JSON.parse(e.data);
    if (msg.type === 'auth') handleAuthEvent(msg);
    else if (msg.type === 'telemetry') handleTelemetryEvent(msg);
    else if (msg.type === 'enroll') fetchFleet();
  } catch (_) {}
};

es.onerror = () => {
  console.warn('SSE connection lost, retrying...');
};

// ── Auth event (live log row) ─────────────────────────────────────────────
function handleAuthEvent(msg) {
  prependLogRow({
    ts: msg.ts,
    device_id: msg.device_id,
    event: msg.event,
    detail: msg.detail || '',
  });
  // Update fleet card status
  if (fleetData[msg.device_id]) {
    fleetData[msg.device_id].last_event = { ts: msg.ts, event: msg.event };
    renderFleet();
  } else {
    fetchFleet();
  }
}

// ── Telemetry event ──────────────────────────────────────────────────────────
function handleTelemetryEvent(msg) {
  if (selectedDrone === msg.device_id) {
    updateTelemetryPanel(msg);
  }
  // Mark drone as LIVE
  if (fleetData[msg.device_id]) {
    fleetData[msg.device_id]._live = true;
    fleetData[msg.device_id].last_event = fleetData[msg.device_id].last_event || {};
    fleetData[msg.device_id].last_event.ts = msg.ts;
    renderFleet();
  }
}

// ── Fleet ────────────────────────────────────────────────────────────────────
async function fetchFleet() {
  try {
    const res = await fetch('/api/fleet');
    const list = await res.json();
    fleetData = {};
    list.forEach(d => { fleetData[d.device_id] = d; });
    renderFleet();
  } catch (e) {
    console.error('Fleet fetch failed', e);
  }
}

function statusBadge(device) {
  const ev = device.last_event;
  if (!ev) return { icon: '⚫', label: 'OFFLINE', cls: 'offline' };
  const age = Date.now() / 1000 - (ev.ts || 0);
  if (device._live && age < 30) return { icon: '🟢', label: 'LIVE', cls: 'live' };
  const event = ev.event || '';
  if (event === 'AUTH_OK') return { icon: '🟡', label: 'AUTH', cls: 'auth' };
  if (['REJECT', 'LOCKED', 'NONCE_REUSED', 'PUF_MISMATCH'].includes(event))
    return { icon: '🔴', label: 'DENIED', cls: 'denied' };
  return { icon: '⚫', label: 'OFFLINE', cls: 'offline' };
}

function renderFleet() {
  const container = document.getElementById('fleet-list');
  container.innerHTML = '';
  const devices = Object.values(fleetData);
  if (devices.length === 0) {
    container.innerHTML = '<div class="empty">No enrolled drones</div>';
    return;
  }
  devices.forEach(d => {
    const badge = statusBadge(d);
    const lastSeen = d.last_event ? formatTs(d.last_event.ts) : '—';
    const card = document.createElement('div');
    card.className = `drone-card ${badge.cls}${selectedDrone === d.device_id ? ' selected' : ''}`;
    card.innerHTML = `
      <div class="card-header">
        <span class="badge">${badge.icon} ${badge.label}</span>
        <span class="device-id">${escHtml(d.device_id)}</span>
      </div>
      <div class="card-meta">Last seen: ${lastSeen}</div>
      <button class="replay-btn" data-id="${escHtml(d.device_id)}" title="Simulate replay attack">
        ⚠ Replay Attack
      </button>`;
    card.addEventListener('click', (e) => {
      if (e.target.classList.contains('replay-btn')) return;
      selectDrone(d.device_id);
    });
    card.querySelector('.replay-btn').addEventListener('click', () => replayAttack(d.device_id));
    container.appendChild(card);
  });
}

function selectDrone(id) {
  selectedDrone = id;
  document.getElementById('selected-drone-label').textContent = id;
  renderFleet();
  fetchTelemetry(id);
}

// ── Telemetry panel ──────────────────────────────────────────────────────────
async function fetchTelemetry(deviceId) {
  try {
    const res = await fetch(`/api/telemetry/${encodeURIComponent(deviceId)}`);
    const readings = await res.json();
    if (readings.length > 0) {
      updateTelemetryPanel(readings[readings.length - 1]);
    } else {
      clearTelemetryPanel();
    }
  } catch (_) {}
}

function updateTelemetryPanel(data) {
  document.getElementById('telem-lat').textContent = fmtNum(data.lat, 6);
  document.getElementById('telem-lon').textContent = fmtNum(data.lon, 6);
  document.getElementById('telem-alt').textContent = fmtNum(data.alt, 1) + ' m';
  document.getElementById('telem-heading').textContent = fmtNum(data.heading, 1) + '°';
  drawAttitudeIndicator(data.heading || 0);
}

function clearTelemetryPanel() {
  ['telem-lat','telem-lon','telem-alt','telem-heading'].forEach(id => {
    document.getElementById(id).textContent = '—';
  });
  drawAttitudeIndicator(0);
}

function fmtNum(v, dec) {
  if (v === null || v === undefined) return '—';
  return Number(v).toFixed(dec);
}

// ── Attitude indicator (canvas) ──────────────────────────────────────────────
function drawAttitudeIndicator(headingDeg) {
  const canvas = document.getElementById('attitude-canvas');
  const ctx = canvas.getContext('2d');
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const r = Math.min(cx, cy) - 8;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Outer ring
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, 2 * Math.PI);
  ctx.strokeStyle = '#58a6ff';
  ctx.lineWidth = 2;
  ctx.stroke();

  // Sky / ground split rotated by heading
  ctx.save();
  ctx.translate(cx, cy);
  ctx.rotate((headingDeg * Math.PI) / 180);

  // Sky
  ctx.beginPath();
  ctx.rect(-r, -r, 2 * r, r);
  ctx.fillStyle = '#1a3a5c';
  ctx.fill();

  // Ground
  ctx.beginPath();
  ctx.rect(-r, 0, 2 * r, r);
  ctx.fillStyle = '#3b2510';
  ctx.fill();

  // Horizon line
  ctx.beginPath();
  ctx.moveTo(-r, 0);
  ctx.lineTo(r, 0);
  ctx.strokeStyle = '#f0c040';
  ctx.lineWidth = 2;
  ctx.stroke();

  ctx.restore();

  // Clip mask (circle)
  ctx.save();
  ctx.beginPath();
  ctx.arc(cx, cy, r, 0, 2 * Math.PI);
  ctx.clip();
  // Redraw border on top
  ctx.restore();

  // Crosshair
  ctx.strokeStyle = '#fff';
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(cx - 20, cy); ctx.lineTo(cx - 6, cy);
  ctx.moveTo(cx + 6, cy);  ctx.lineTo(cx + 20, cy);
  ctx.moveTo(cx, cy - 6);  ctx.lineTo(cx, cy + 6);
  ctx.stroke();

  // Heading label
  ctx.fillStyle = '#58a6ff';
  ctx.font = '11px monospace';
  ctx.textAlign = 'center';
  ctx.fillText(`HDG ${Math.round(headingDeg)}°`, cx, cy + r + 6);
}

// ── Auth Log ─────────────────────────────────────────────────────────────────
async function fetchLog() {
  try {
    const res = await fetch('/api/log');
    const rows = await res.json();
    const tbody = document.getElementById('log-tbody');
    tbody.innerHTML = '';
    // API returns newest-first
    rows.forEach(r => appendLogRow(r, tbody));
  } catch (e) {
    console.error('Log fetch failed', e);
  }
}

function logRowClass(event) {
  if (event === 'AUTH_OK') return 'log-ok';
  if (['REJECT','LOCKED','NONCE_REUSED','PUF_MISMATCH'].includes(event)) return 'log-bad';
  return 'log-warn';
}

function appendLogRow(row, tbody) {
  const tr = document.createElement('tr');
  tr.className = logRowClass(row.event);
  tr.innerHTML = `
    <td>${formatTs(row.ts)}</td>
    <td>${escHtml(row.device_id)}</td>
    <td>${escHtml(row.event)}</td>
    <td>${escHtml(row.detail || '')}</td>`;
  tbody.appendChild(tr);
}

function prependLogRow(row) {
  const tbody = document.getElementById('log-tbody');
  const tr = document.createElement('tr');
  tr.className = logRowClass(row.event);
  tr.innerHTML = `
    <td>${formatTs(row.ts)}</td>
    <td>${escHtml(row.device_id)}</td>
    <td>${escHtml(row.event)}</td>
    <td>${escHtml(row.detail || '')}</td>`;
  tr.style.animation = 'fadeIn 0.4s ease';
  tbody.prepend(tr);
  // Trim to 100 rows
  while (tbody.rows.length > 100) tbody.deleteRow(tbody.rows.length - 1);
}

// ── Replay Attack Demo ───────────────────────────────────────────────────────
async function replayAttack(deviceId) {
  const body = {
    device_id: deviceId,
    nonce: 'old-nonce-deadbeef0000000000000000000000000000000000000000000000000012345',
    ts: String(Math.floor(Date.now() / 1000)),
    mac: 'deadbeef'.repeat(8),
  };
  try {
    const res = await fetch('/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    prependLogRow({
      ts: Math.floor(Date.now() / 1000),
      device_id: deviceId,
      event: data.error || 'DEMO',
      detail: 'replay-attack-demo',
    });
  } catch (e) {
    console.error('Replay attack demo failed', e);
  }
}

// ── Utilities ────────────────────────────────────────────────────────────────
function formatTs(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false,
    hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  fetchFleet();
  fetchLog();
  drawAttitudeIndicator(0);
  setInterval(fetchFleet, POLL_INTERVAL);
});
