'use strict';

// ── State ─────────────────────────────────────────────────────────────────────

let originalConfig = {};
let pendingChanges = {};

// Keys that require a node restart to take effect
const RESTART_REQUIRED = new Set([
  'http.port', 'http.bind', 'p2p.port',
  'dns.auth.port', 'dns.recursive.port',
  'deployment.type',
  'module.full_node', 'module.dns',
  'module.wallet', 'module.miner',
]);

// ── Load config ───────────────────────────────────────────────────────────────

async function loadConfig() {
  try {
    const res  = await fetch('/api/config');
    const data = await res.json();
    originalConfig = data.settings || {};
    renderSettings(data);
  } catch (err) {
    document.getElementById('settings-grid').innerHTML =
      `<div style="color:var(--danger);padding:1rem">
         Failed to load settings: ${err.message}
       </div>`;
  }
}

// ── Render ────────────────────────────────────────────────────────────────────

function renderSettings(data) {
  const s = data.settings || {};
  const modules = data.modules || [];
  const grid = document.getElementById('settings-grid');

  grid.innerHTML = `
    ${renderDeploymentSection(s)}
    ${renderModulesSection(modules)}
    ${renderNetworkSection(s)}
    ${renderDnsSection(s)}
    ${renderActionsSection()}
  `;

  attachHandlers();
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
          <span class="restart-badge">restart</span>
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
          <span class="restart-badge">restart</span>
        </div>
      </div>
    </div>`;
}

function renderModulesSection(modules) {
  const rows = modules.map(m => {
    const planned = m.id === 'WALLET' || m.id === 'MINER';
    return `
      <div class="settings-row">
        <div class="settings-label">
          <div class="settings-label-text">${m.icon} ${m.name}</div>
          <div class="settings-label-desc">${m.desc}</div>
        </div>
        <div class="settings-control">
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
        ${planned ? '' : '<span class="restart-badge">restart</span>'}
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
        ${portRow('DNS authoritative port', 'dns.auth.port',
            s['dns.auth.port'] || '5349',
            'Handshake root zone authoritative nameserver')}
        ${portRow('DNS recursive port', 'dns.recursive.port',
            s['dns.recursive.port'] || '5350',
            'HNS-first recursive resolver for all DNS queries')}
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
      <span class="restart-badge">restart</span>
    </div>`;
}

function renderDnsSection(s) {
  const upstream = s['dns.upstream'] || '';
  return `
    <div class="settings-section">
      <div class="settings-section-title">DNS</div>
      <div class="settings-rows">
        <div class="settings-row">
          <div class="settings-label">
            <div class="settings-label-text">Upstream DNS override</div>
            <div class="settings-label-desc">
              Fallback DNS for ICANN queries. Leave blank to auto-detect
              from system. Set to your router IP if outbound UDP port 53
              is blocked (e.g. when using a VPN).
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

function renderActionsSection() {
  return `
    <div class="settings-actions">
      <button class="btn-save" id="btn-save" onclick="saveChanges()"
              disabled>Save Changes</button>
      <button class="btn-secondary" onclick="resetForm()">Reset</button>
      <span class="save-status" id="save-status"></span>
    </div>`;
}

// ── Interaction ───────────────────────────────────────────────────────────────

function attachHandlers() {
  // Watch all inputs for changes
  document.querySelectorAll('.settings-input, .toggle input').forEach(el => {
    el.addEventListener('input', () => updateSaveButton());
  });
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
  pendingChanges[key] = value;
  updateSaveButton();
}

function updateSaveButton() {
  const btn = document.getElementById('btn-save');
  if (!btn) return;
  const hasChanges = Object.keys(pendingChanges).length > 0;
  btn.disabled = !hasChanges;
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
    const needsRestart = Object.keys(pendingChanges)
        .some(k => RESTART_REQUIRED.has(k));
    pendingChanges = {};
    status.className   = 'save-status ok';
    status.textContent = needsRestart
        ? '✓ Saved — restart node to apply changes'
        : '✓ Saved';
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
