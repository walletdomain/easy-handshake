'use strict';

// ── Configuration ─────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 30_000;
const MAX_EVENTS       = 500;

// ── DOM references ────────────────────────────────────────────────────────────

const els = {
  version:    document.getElementById('version'),
  badge:      document.getElementById('status-badge'),
  height:     document.getElementById('stat-height'),
  blockTip:   document.getElementById('stat-block-tip'),
  dbSize:     document.getElementById('stat-db-size'),
  uptime:     document.getElementById('stat-uptime'),
  lastUpdate: document.getElementById('last-updated'),
  eventsLog:  document.getElementById('events-log'),
  sseDot:     document.getElementById('sse-dot'),
  sseLabel:   document.getElementById('sse-label'),
};

// ── Status polling ────────────────────────────────────────────────────────────

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
  els.version.textContent   = 'v' + data.version;
  const synced              = data.synced;
  els.badge.textContent     = synced ? 'Synced' : 'Syncing';
  els.badge.className       = 'status-badge ' + (synced ? 'synced' : 'syncing');
  els.height.textContent    = data.height.toLocaleString();
  els.blockTip.textContent  = data.blockTip.toLocaleString();
  els.dbSize.textContent    = formatBytes(data.dbSizeBytes);
  els.uptime.textContent    = formatUptime(data.uptimeSeconds);
  document.querySelectorAll('.card-value').forEach(el => el.classList.remove('loading'));
  els.lastUpdate.textContent = 'Updated ' + new Date().toLocaleTimeString();
}

function setError(msg) {
  els.badge.textContent      = 'Offline';
  els.badge.className        = 'status-badge error';
  els.lastUpdate.textContent = 'Error: ' + msg;
}

// ── Live events (SSE) ─────────────────────────────────────────────────────────

let activeFilter  = 'ALL';
let autoScroll    = true;
let eventCount    = 0;
let eventSource   = null;

function initSSE() {
  if (eventSource) eventSource.close();

  setSseStatus('connecting');
  eventSource = new EventSource('/api/events');

  eventSource.onopen = () => {
    setSseStatus('connected');
    // Scroll to bottom after backfill arrives (small delay to let DOM update)
    setTimeout(() => {
      els.eventsLog.scrollTop = els.eventsLog.scrollHeight;
    }, 100);
  };

  eventSource.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      appendEvent(event);
    } catch (err) {
      // ignore parse errors (heartbeat comments don't trigger onmessage)
    }
  };

  eventSource.onerror = () => {
    setSseStatus('reconnecting');
    // Browser auto-reconnects SSE — just update status
    setTimeout(() => {
      if (eventSource.readyState === EventSource.CLOSED) {
        setSseStatus('disconnected');
        setTimeout(initSSE, 5000); // retry after 5s
      }
    }, 3000);
  };
}

function setSseStatus(state) {
  const dot   = els.sseDot;
  const label = els.sseLabel;
  dot.className = 'sse-dot sse-' + state;
  label.textContent = {
    connecting:   'connecting...',
    connected:    'live',
    reconnecting: 'reconnecting...',
    disconnected: 'disconnected',
  }[state] || state;
}

function appendEvent(event) {
  // Remove empty state placeholder
  const empty = els.eventsLog.querySelector('.events-empty');
  if (empty) empty.remove();

  // Apply filter
  const visible = activeFilter === 'ALL' || event.cat === activeFilter;

  const row = document.createElement('div');
  row.className = 'event-row ' + event.css;
  if (!visible) row.classList.add('event-hidden');
  row.dataset.cat = event.cat;

  const time = new Date(event.ts);
  const hh   = String(time.getHours()).padStart(2, '0');
  const mm   = String(time.getMinutes()).padStart(2, '0');
  const ss   = String(time.getSeconds()).padStart(2, '0');

  row.innerHTML =
      `<span class="event-time">${hh}:${mm}:${ss}</span>` +
      `<span class="event-icon">${event.icon}</span>` +
      `<span class="event-msg">${escHtml(event.msg)}</span>`;

  els.eventsLog.appendChild(row);
  eventCount++;

  // Trim to MAX_EVENTS
  while (els.eventsLog.children.length > MAX_EVENTS) {
    els.eventsLog.removeChild(els.eventsLog.firstChild);
  }

  if (autoScroll && visible) {
    els.eventsLog.scrollTop = els.eventsLog.scrollHeight;
  }
}

function escHtml(str) {
  return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
}

// ── Filter buttons ────────────────────────────────────────────────────────────

document.querySelectorAll('.filter-btn[data-cat]').forEach(btn => {
  btn.addEventListener('click', () => {
    activeFilter = btn.dataset.cat;
    document.querySelectorAll('.filter-btn[data-cat]').forEach(b =>
        b.classList.toggle('active', b === btn));
    // Show/hide existing rows
    els.eventsLog.querySelectorAll('.event-row').forEach(row => {
      const show = activeFilter === 'ALL' || row.dataset.cat === activeFilter;
      row.classList.toggle('event-hidden', !show);
    });
  });
});

// ── Auto-scroll toggle ────────────────────────────────────────────────────────

const scrollToggleBtn = document.getElementById('scroll-toggle');
scrollToggleBtn.addEventListener('click', () => {
  autoScroll = !autoScroll;
  scrollToggleBtn.classList.toggle('active', autoScroll);
  scrollToggleBtn.textContent = autoScroll ? '↓ Auto-scroll' : '⏸ Paused';
});
scrollToggleBtn.classList.add('active'); // starts active

// Pause auto-scroll when user manually scrolls up
els.eventsLog.addEventListener('scroll', () => {
  const log     = els.eventsLog;
  const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
  if (!atBottom && autoScroll) {
    autoScroll = false;
    scrollToggleBtn.classList.remove('active');
    scrollToggleBtn.textContent = '⏸ Paused';
  }
});

// ── Clear button ──────────────────────────────────────────────────────────────

document.getElementById('clear-btn').addEventListener('click', () => {
  els.eventsLog.innerHTML = '<div class="events-empty">Log cleared.</div>';
  eventCount = 0;
});

// ── Formatters ────────────────────────────────────────────────────────────────

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

// ── Peers panel ───────────────────────────────────────────────────────────────

async function refreshPeers() {
  try {
    const res  = await fetch('/api/peers');
    if (!res.ok) return;
    const peers = await res.json();
    renderPeers(peers);
  } catch (err) { /* ignore */ }
}

function renderPeers(peers) {
  const panel = document.getElementById('peers-panel');
  if (!panel) return;

  if (!peers || peers.length === 0) {
    panel.innerHTML = '<div class="peers-empty">No peers known yet.</div>';
    return;
  }

  // Sort: healthy first, then degraded, then backoff
  peers.sort((a, b) => {
    const rank = p => p.backoff ? 2 : p.score >= 40 ? 0 : 1;
    const dr = rank(a) - rank(b);
    return dr !== 0 ? dr : b.score - a.score;
  });

  panel.innerHTML = peers.map(p => {
    const cls    = p.backoff ? 'backoff' : p.score >= 40 ? 'healthy' : 'degraded';
    const agent  = (p.version || '').replace('/hsd:', 'hsd ').replace(/\//g, '');
    const height = p.height > 0 ? 'h=' + p.height.toLocaleString() : '—';
    const backoffTag = p.backoff
        ? '<span class="peer-backoff-tag">BACKOFF</span>' : '';
    return `<div class="peer-row">
      <span class="peer-dot ${cls}"></span>
      <span class="peer-ip">${escHtml(p.ip)}</span>
      <span class="peer-agent">${escHtml(agent)}</span>
      <span class="peer-height">${height}</span>
      <span class="peer-score ${cls}">${p.score}</span>
      ${backoffTag}
    </div>`;
  }).join('');
}

async function resetPeers() {
  const btn = document.getElementById('reset-peers-btn');
  btn.textContent = '…';
  try {
    await fetch('/api/peers/reset', { method: 'POST' });
    await refreshPeers();
    btn.textContent = '✓ Reset';
    setTimeout(() => btn.textContent = 'Reset', 2000);
  } catch (e) {
    btn.textContent = 'Reset';
  }
}

// Poll peers every 30 seconds
setInterval(refreshPeers, 30_000);
refreshPeers();

// ── Name index progress ───────────────────────────────────────────────────────

let nameIndexReady = false;

async function pollNameIndex() {
  if (nameIndexReady) return;
  try {
    const res  = await fetch('/api/nameindex');
    if (!res.ok) return;
    const data = await res.json();

    const bar = document.getElementById('nameindex-bar');
    if (!bar) return;

    if (data.ready) {
      nameIndexReady = true;
      document.getElementById('nameindex-progress').style.display = 'none';
      return;
    }

    document.getElementById('nameindex-progress').style.display = 'block';
    document.getElementById('nameindex-fill').style.width = data.pct + '%';
    document.getElementById('nameindex-pct').textContent  = data.pct + '%';
    document.getElementById('nameindex-names').textContent =
        data.names.toLocaleString() + ' names';
    document.getElementById('nameindex-blocks').textContent =
        data.progress.toLocaleString() + ' / ' + data.total.toLocaleString() + ' blocks';

    const eta = document.getElementById('nameindex-eta');
    if (data.eta > 0) {
      eta.textContent = '· ETA ' + formatUptime(data.eta);
    } else {
      eta.textContent = '';
    }
  } catch (err) { /* ignore */ }
}

// Poll every 5 seconds while building
setInterval(pollNameIndex, 5_000);
pollNameIndex();

// ── Init ──────────────────────────────────────────────────────────────────────

document.querySelectorAll('.card-value').forEach(el => el.classList.add('loading'));
refresh();
setInterval(refresh, POLL_INTERVAL_MS);
initSSE();