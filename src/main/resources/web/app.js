'use strict';

// ── Configuration ──────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 30_000; // refresh every 30 seconds

// ── DOM references ──────────────────────────────────────────────────────────

const els = {
  version:    document.getElementById('version'),
  badge:      document.getElementById('status-badge'),
  height:     document.getElementById('stat-height'),
  blockTip:   document.getElementById('stat-block-tip'),
  dbSize:     document.getElementById('stat-db-size'),
  uptime:     document.getElementById('stat-uptime'),
  lastUpdate: document.getElementById('last-updated'),
};

// ── Fetch and render ────────────────────────────────────────────────────────

async function refresh() {
  try {
    const res  = await fetch('/api/status');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    render(data);
  } catch (err) {
    setError(err.message);
  }
}

function render(data) {
  // Version
  els.version.textContent = 'v' + data.version;

  // Sync status badge
  const synced = data.synced;
  els.badge.textContent = synced ? 'Synced' : 'Syncing';
  els.badge.className   = 'status-badge ' + (synced ? 'synced' : 'syncing');

  // Stats
  els.height.textContent   = data.height.toLocaleString();
  els.blockTip.textContent = data.blockTip.toLocaleString();
  els.dbSize.textContent   = formatBytes(data.dbSizeBytes);
  els.uptime.textContent   = formatUptime(data.uptimeSeconds);

  // Remove loading state
  document.querySelectorAll('.card-value').forEach(el =>
    el.classList.remove('loading'));

  // Last updated timestamp
  els.lastUpdate.textContent = 'Updated ' + new Date().toLocaleTimeString();
}

function setError(msg) {
  els.badge.textContent = 'Offline';
  els.badge.className   = 'status-badge error';
  els.lastUpdate.textContent = 'Error: ' + msg;
}

// ── Formatters ──────────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes >= 1_073_741_824)
    return (bytes / 1_073_741_824).toFixed(1) + ' GB';
  if (bytes >= 1_048_576)
    return (bytes / 1_048_576).toFixed(0) + ' MB';
  return bytes.toLocaleString() + ' B';
}

function formatUptime(seconds) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ── Init ─────────────────────────────────────────────────────────────────────

// Set loading state on all card values
document.querySelectorAll('.card-value').forEach(el =>
  el.classList.add('loading'));

// Initial fetch then poll
refresh();
setInterval(refresh, POLL_INTERVAL_MS);
