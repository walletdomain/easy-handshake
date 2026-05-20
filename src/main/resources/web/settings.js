'use strict';

// ── State ─────────────────────────────────────────────────────────────────────

let originalConfig = {};
let pendingChanges = {};

// Keys that require a node restart to take effect
const RESTART_REQUIRED = new Set([
  'http.port', 'http.bind', 'p2p.port',
  'dns.auth.port', 'dns.recursive.port',
  'deployment.type',
  'module.full_node', 'module.dns', 'module.miner',
]);

// ── Load config ───────────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    const res  = await fetch('/api/config');
    const data = await res.json();
    originalConfig = data.settings || {};
    renderSettings(data);
  } catch (err) {
    document.getElementById('col-left').innerHTML =
        `<div style="color:var(--danger);padding:1rem">
         Failed to load settings: ${err.message}
       </div>`;
  }
}

// ── Render ────────────────────────────────────────────────────────────────────

function renderSettings(data) {
  const s       = data.settings || {};
  const modules = data.modules  || [];

  // Left column: Deployment + Network + DNS
  document.getElementById('col-left').innerHTML =
      renderDeploymentSection(s) + renderNetworkSection(s) + renderDnsSection(s);

  // Right column: Modules + Seeds
  document.getElementById('col-right').innerHTML =
      renderModulesSection(modules) + renderSeedsSection();

  attachHandlers();
  loadSeeds();
}

function renderDeploymentSection(s) {
  const current = s['deployment.type'] || 'DESKTOP';
  const types = [
    { id: 'DESKTOP',     icon: '🖥',  label: 'Desktop',     desc: 'localhost only' },
    { id: 'HOME_SERVER', icon: '🏠',  label: 'Home server', desc: 'local network' },
    { id: 'VPS',         icon: '☁',  label: 'VPS',         desc: 'public · use firewall' },
  ];
  const options = types.map(t => `
    <label class="deploy-option ${t.id === current ? 'selected' : ''}"
           onclick="selectDeploy('${t.id}', this)">
      <input type="radio" name="deployment.type" value="${t.id}"
             ${t.id === current ? 'checked' : ''}>
      ${t.icon} ${t.label}
      <span style="font-size:0.65rem;color:var(--muted)">${t.desc}</span>
    </label>`).join('');

  return `
    <div class="settings-section">
      <div class="settings-section-title">Deployment</div>
      <div class="settings-rows">
        <div class="settings-row">
          <div class="settings-label">
            <div class="settings-label-text">Deployment type</div>
            <div class="settings-label-desc">
              Determines the default HTTP bind address
            </div>
          </div>
          <div class="settings-control">
            <div class="deploy-options" id="deploy-options">${options}</div>
          </div>
        </div>
        <div class="settings-row">
          <div class="settings-label">
            <div class="settings-label-text">HTTP bind address</div>
            <div class="settings-label-desc">
              127.0.0.1 = this machine only · 0.0.0.0 = all interfaces
            </div>
          </div>
          <div class="settings-control">
            <input class="settings-input" type="text" id="http.bind"
                   value="${esc(s['http.bind'] || '127.0.0.1')}"
                   onchange="recordChange('http.bind', this.value)">
          </div>
        </div>
      </div>
    </div>`;
}

function renderModulesSection(modules) {
  const rows = modules.map(m => {
    const planned = m.id === 'MINER';
    return `
      <div class="settings-row">
        <div class="settings-label">
          <div class="settings-label-text">${m.icon} ${m.name}</div>
          <div class="settings-label-desc" style="max-width:280px">${m.desc}</div>
        </div>
        <div class="settings-control" style="margin-left:auto;flex-shrink:0">
          ${planned
        ? `<span class="coming-soon">coming soon</span>`
        : `<label class="toggle">
                 <input type="checkbox" id="module.${m.id.toLowerCase()}"
                        ${m.enabled ? 'checked' : ''}
                        onchange="recordChange('module.${m.id.toLowerCase()}',
                                  this.checked ? 'true' : 'false')">
                 <div class="toggle-track"></div>
                 <div class="toggle-thumb"></div>
               </label>`}
        </div>
      </div>`;
  }).join('');

  return `
    <div class="settings-section">
      <div class="settings-section-title">Modules</div>
      <div class="settings-rows">${rows}</div>
    </div>`;
}

function renderNetworkSection(s) {
  return `
    <div class="settings-section">
      <div class="settings-section-title">Network</div>
      <div class="settings-rows">
        ${portRow('HTTP dashboard port', 'http.port', s['http.port'] || '8888',
      'Port for the web dashboard and REST/RPC APIs')}
        ${portRow('P2P brontide port', 'p2p.port', s['p2p.port'] || '44806',
      'Port for peer-to-peer block sync and gossip')}
      </div>
    </div>`;
}

function portRow(label, key, value, desc) {
  return `
    <div class="settings-row">
      <div class="settings-label">
        <div class="settings-label-text">${label}</div>
        <div class="settings-label-desc">${desc}</div>
      </div>
      <div class="settings-control">
        <input class="settings-input" type="number" id="${key}"
               value="${esc(value)}" min="1024" max="65535"
               onchange="recordChange('${key}', this.value)">
      </div>
    </div>`;
}

function renderDnsSection(s) {
  const upstream = s['dns.upstream'] || '';
  return `
    <div class="settings-section">
      <div class="settings-section-title">DNS</div>
      <div class="settings-rows">
        ${portRow('Authoritative port', 'dns.auth.port',
      s['dns.auth.port'] || '5349',
      'Handshake root zone authoritative nameserver')}
        ${portRow('Recursive port', 'dns.recursive.port',
      s['dns.recursive.port'] || '5350',
      'HNS-first recursive resolver for all DNS queries')}
        <div class="settings-row">
          <div class="settings-label">
            <div class="settings-label-text">Upstream DNS override</div>
            <div class="settings-label-desc">
              Fallback for ICANN queries. Leave blank to auto-detect.
              Set to your router IP if outbound port 53 is blocked (VPN users).
            </div>
          </div>
          <div class="settings-control">
            <input class="settings-input wide" type="text" id="dns.upstream"
                   value="${esc(upstream)}"
                   placeholder="e.g. 10.2.0.1 or 8.8.8.8"
                   onchange="recordChange('dns.upstream', this.value)">
          </div>
        </div>
      </div>
    </div>`;
}

// ── Interaction ───────────────────────────────────────────────────────────────

function attachHandlers() {
  document.querySelectorAll('.settings-input, .toggle input').forEach(el => {
    el.addEventListener('input', () => updateSaveButton());
  });
}

async function saveAndShowRestart() {
  await saveChanges();
  const status = document.getElementById('save-status');
  if (status && status.className.includes('ok')) {
    status.textContent = '✓ Saved — please restart the node to apply changes';
  }
}

function selectDeploy(type, clickedLabel) {
  // Update radio UI
  document.querySelectorAll('.deploy-option').forEach(l => {
    l.classList.remove('selected');
  });
  clickedLabel.classList.add('selected');

  // Auto-set bind address
  const bindMap = {
    DESKTOP: '127.0.0.1',
    HOME_SERVER: '0.0.0.0',
    VPS: '0.0.0.0',
  };
  const bindInput = document.getElementById('http.bind');
  if (bindInput) {
    bindInput.value = bindMap[type] || '127.0.0.1';
    recordChange('http.bind', bindInput.value);
  }

  recordChange('deployment.type', type);
}

function recordChange(key, value) {
  // If the new value matches the original, remove from pending — no change needed
  if (String(originalConfig[key]) === String(value)) {
    delete pendingChanges[key];
  } else {
    pendingChanges[key] = value;
  }
  updateSaveButton();
}

function updateSaveButton() {
  const btn     = document.getElementById('btn-save');
  const banner  = document.getElementById('restart-banner');
  if (!btn) return;

  const hasChanges    = Object.keys(pendingChanges).length > 0;
  const needsRestart  = Object.keys(pendingChanges).some(k => RESTART_REQUIRED.has(k));
  const hasImmediate  = Object.keys(pendingChanges).some(k => !RESTART_REQUIRED.has(k));

  // Show restart banner if any restart-required changes pending
  if (banner) banner.classList.toggle('hidden', !needsRestart);

  // Show regular save button only if there are immediate (non-restart) changes
  btn.disabled = !hasImmediate;
}

async function saveChanges() {
  const btn    = document.getElementById('btn-save');
  const status = document.getElementById('save-status');
  btn.disabled = true;
  status.textContent = 'Saving...';
  status.className   = 'save-status';

  let errors = 0;
  for (const [key, value] of Object.entries(pendingChanges)) {
    try {
      const res = await fetch('/api/config', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ key, value }),
      });
      if (!res.ok) errors++;
    } catch (err) {
      errors++;
    }
  }

  if (errors === 0) {
    pendingChanges = {};
    status.className   = 'save-status ok';
    status.textContent = '✓ Saved';
    // Hide restart banner after saving
    const banner = document.getElementById('restart-banner');
    if (banner) banner.classList.add('hidden');
    // Reload config to sync displayed values
    await loadConfig();
  } else {
    status.className   = 'save-status err';
    status.textContent = `✗ ${errors} setting(s) failed to save`;
    btn.disabled = false;
  }
}

function resetForm() {
  pendingChanges = {};
  loadConfig();
}

function renderSeedsSection() {
  return `
    <div class="settings-section">
      <div class="settings-section-title">Seed Nodes</div>
      <div id="seeds-list" style="padding:0.5rem 0">
        <div class="peers-empty">Loading seeds...</div>
      </div>
      <div style="padding:0.75rem 1rem;border-top:1px solid var(--border);
                  background:var(--surface2)">
        <div style="font-size:0.75rem;font-weight:600;color:var(--text);
                    margin-bottom:0.6rem">Add Custom Seed</div>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:flex-end">
          <div>
            <div style="font-size:0.65rem;color:var(--muted);
                        font-family:'Space Mono',monospace;margin-bottom:0.25rem">
              IP Address
            </div>
            <input class="settings-input" id="new-seed-ip"
                   placeholder="1.2.3.4" style="width:130px">
          </div>
          <div>
            <div style="font-size:0.65rem;color:var(--muted);
                        font-family:'Space Mono',monospace;margin-bottom:0.25rem">
              Port
            </div>
            <input class="settings-input" id="new-seed-port"
                   value="44806" style="width:80px" type="number">
          </div>
          <div style="flex:1;min-width:140px">
            <div style="font-size:0.65rem;color:var(--muted);
                        font-family:'Space Mono',monospace;margin-bottom:0.25rem">
              Brontide Key (base32)
            </div>
            <input class="settings-input wide" id="new-seed-key"
                   placeholder="a..." style="width:100%">
          </div>
          <div>
            <div style="font-size:0.65rem;color:var(--muted);
                        font-family:'Space Mono',monospace;margin-bottom:0.25rem">
              Label (optional)
            </div>
            <input class="settings-input" id="new-seed-label"
                   placeholder="My node" style="width:120px">
          </div>
          <button class="btn-save" style="padding:0.4rem 0.8rem;font-size:0.78rem"
                  onclick="addSeed()">Add</button>
          <span id="seed-add-status" class="save-status"></span>
        </div>
      </div>
    </div>`;
}

async function loadSeeds() {
  try {
    const res   = await fetch('/api/seeds');
    const seeds = await res.json();
    renderSeedsList(seeds);
  } catch (err) {
    const el = document.getElementById('seeds-list');
    if (el) el.innerHTML = '<div class="peers-empty">Failed to load seeds.</div>';
  }
}

function renderSeedsList(seeds) {
  const el = document.getElementById('seeds-list');
  if (!el) return;
  if (!seeds || seeds.length === 0) {
    el.innerHTML = '<div class="peers-empty">No seeds configured.</div>';
    return;
  }

  el.innerHTML = seeds.map(s => {
    const score = window._peerScores ? window._peerScores[s.ip] : null;
    const dotCls = !s.enabled ? 'backoff'
        : score == null ? 'degraded'
            : score >= 40   ? 'healthy'
                : score >= 20   ? 'degraded' : 'backoff';
    const actions = s.source === 'BUILTIN'
        ? `<button class="btn-secondary"
                   style="font-size:0.65rem;padding:0.2rem 0.5rem"
                   onclick="toggleSeed('${s.ip}', ${!s.enabled})">
             ${s.enabled ? 'Disable' : 'Enable'}
           </button>`
        : `<button class="btn-secondary"
                   style="font-size:0.65rem;padding:0.2rem 0.5rem"
                   onclick="toggleSeed('${s.ip}', ${!s.enabled})">
             ${s.enabled ? 'Disable' : 'Enable'}
           </button>
           <button class="btn-secondary"
                   style="font-size:0.65rem;padding:0.2rem 0.5rem;
                          color:var(--danger);border-color:var(--danger)"
                   onclick="removeSeed('${s.ip}')">
             Remove
           </button>`;
    return `<div class="settings-row" style="gap:0.6rem">
      <span class="peer-dot ${dotCls}"></span>
      <span style="font-family:'Space Mono',monospace;font-size:0.72rem;
                   color:${s.enabled ? 'var(--text)' : 'var(--muted)'};
                   min-width:120px">${esc(s.ip)}:${s.port}</span>
      <span style="font-size:0.65rem;color:var(--muted);flex:1;
                   overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
        ${esc(s.label || s.source)}
      </span>
      <div style="display:flex;gap:0.4rem">${actions}</div>
    </div>`;
  }).join('');
}

async function toggleSeed(ip, enable) {
  const action = enable ? 'enable' : 'disable';
  await fetch(`/api/seeds?ip=${encodeURIComponent(ip)}&action=${action}`,
      { method: 'DELETE' });
  loadSeeds();
}

async function removeSeed(ip) {
  if (!confirm(`Remove seed ${ip}?`)) return;
  await fetch(`/api/seeds?ip=${encodeURIComponent(ip)}&action=remove`,
      { method: 'DELETE' });
  loadSeeds();
}

async function addSeed() {
  const ip    = document.getElementById('new-seed-ip').value.trim();
  const port  = document.getElementById('new-seed-port').value.trim();
  const key   = document.getElementById('new-seed-key').value.trim();
  const label = document.getElementById('new-seed-label').value.trim();
  const status = document.getElementById('seed-add-status');

  if (!ip || !key) {
    status.className = 'save-status err';
    status.textContent = '✗ IP and key required';
    return;
  }

  try {
    const res = await fetch('/api/seeds', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ key, ip, port: parseInt(port) || 44806, label }),
    });
    const data = await res.json();
    if (data.ok) {
      status.className = 'save-status ok';
      status.textContent = '✓ Added';
      document.getElementById('new-seed-ip').value    = '';
      document.getElementById('new-seed-key').value   = '';
      document.getElementById('new-seed-label').value = '';
      loadSeeds();
    } else {
      status.className = 'save-status err';
      status.textContent = '✗ ' + (data.error || 'Failed');
    }
  } catch (err) {
    status.className = 'save-status err';
    status.textContent = '✗ ' + err.message;
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function esc(str) {
  return String(str)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
}

// ── Init ──────────────────────────────────────────────────────────────────────

loadConfig();