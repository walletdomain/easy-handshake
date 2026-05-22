'use strict';

// ── State ─────────────────────────────────────────────────────────────────────

let activeWalletId = null;
let wallets        = [];
let tipHeight      = 0;

// ── Init ──────────────────────────────────────────────────────────────────────

async function loadWallets() {
  try {
    const res = await fetch('/api/wallet');

    if (!res.ok) {
      if (res.status === 503) {
        // Wallet module not enabled — enable it silently then reload
        await fetch('/api/config', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ key: 'module.wallet', value: 'true' }),
        });
        // Reload to pick up the now-enabled module
        await loadWallets();
        return;
      }
      throw new Error('HTTP ' + res.status);
    }

    const data = await res.json();
    wallets = data.wallets || data;
    tipHeight = data.tipHeight || 0;
    renderSidebar();
    renderScanStatus(data.scan);
    if (data.scan && data.scan.scanning) pollScanStatus();

    if (wallets.length === 0) {
      // No wallets yet — show create/restore immediately
      showWelcomeState();
    } else {
      selectWallet(wallets[0].id);
    }
  } catch (err) {
    document.getElementById('wallet-main').innerHTML =
        `<div class="empty-state"><div class="empty-state-msg">
         Error loading wallets: ${esc(err.message)}
       </div></div>`;
  }
}

function showWelcomeState() {
  document.getElementById('wallet-main').innerHTML = `
    <div class="empty-state">
      <div class="empty-state-icon">💰</div>
      <div class="empty-state-msg">
        You don't have a wallet yet.<br>
        Create a new one or restore an existing wallet from a seed phrase.
      </div>
      <div style="display:flex;gap:0.75rem;justify-content:center;flex-wrap:wrap">
        <button class="btn-primary" style="max-width:200px"
                onclick="showCreateModal()">
          + Create New Wallet
        </button>
        <button class="btn-cancel" style="max-width:200px"
                onclick="showRestoreModal()">
          ↩ Recover Wallet
        </button>
      </div>
    </div>`;
}

// ── Scan status ───────────────────────────────────────────────────────────────

let scanPolling = false;

function renderScanStatus(scan) {
  const existing = document.getElementById('scan-progress-bar');
  if (existing) existing.remove();
  if (!scan || !scan.scanning) return;

  const bar = document.createElement('div');
  bar.id = 'scan-progress-bar';
  bar.style.cssText = `
    background:rgba(88,166,255,0.1);
    border:1px solid var(--accent);
    border-radius:8px;
    padding:0.75rem 1rem;
    margin-bottom:1rem;
    font-family:'Space Mono',monospace;
    font-size:0.75rem;
  `;
  const etaStr = scan.eta > 0 ? ' · ETA ' + formatUptime(scan.eta) : '';
  bar.innerHTML = `
    <div style="display:flex;justify-content:space-between;margin-bottom:0.4rem">
      <span style="color:var(--accent)">🔍 Scanning blockchain for transaction history</span>
      <span style="color:var(--accent)">${scan.pct}%${etaStr}</span>
    </div>
    <div style="height:4px;background:var(--border);border-radius:2px;overflow:hidden">
      <div style="height:100%;width:${scan.pct}%;background:var(--accent);
                  border-radius:2px;transition:width 0.5s"></div>
    </div>
    <div style="color:var(--muted);font-size:0.65rem;margin-top:0.3rem">
      Block ${scan.progress.toLocaleString()} of ${scan.total.toLocaleString()}
    </div>`;

  const layout = document.querySelector('.wallet-layout');
  if (layout) layout.parentNode.insertBefore(bar, layout);
}

async function pollScanStatus() {
  if (scanPolling) return;
  scanPolling = true;
  while (true) {
    await new Promise(r => setTimeout(r, 3000));
    try {
      const res  = await fetch('/api/wallet');
      const data = await res.json();
      if (data.tipHeight) tipHeight = data.tipHeight;
      renderScanStatus(data.scan);
      // If scan finished, refresh wallet balance and stop polling
      if (!data.scan || !data.scan.scanning) {
        scanPolling = false;
        if (activeWalletId) selectWallet(activeWalletId);
        break;
      }
    } catch (e) {
      scanPolling = false;
      break;
    }
  }
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return h + 'h ' + m + 'm';
  if (m > 0) return m + 'm ' + s + 's';
  return s + 's';
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

function renderSidebar() {
  const el = document.getElementById('wallet-list');
  if (wallets.length === 0) {
    el.innerHTML = ''; // welcome state shown in main panel
    return;
  }
  el.innerHTML = wallets.map(w => `
    <div class="wallet-card ${w.id === activeWalletId ? 'active' : ''}"
         onclick="selectWallet('${w.id}')">
      <div class="wallet-card-name">${esc(w.name)}</div>
      <div class="wallet-card-status ${w.unlocked ? 'unlocked' : 'locked'}">
        ${w.unlocked ? '🔓 Unlocked' : '🔒 Locked'}
      </div>
    </div>`).join('');
}

// ── Main panel ────────────────────────────────────────────────────────────────

async function selectWallet(id) {
  activeWalletId = id;
  renderSidebar();

  try {
    const res  = await fetch('/api/wallet/' + id);
    const data = await res.json();
    renderWalletMain(data);
  } catch (err) {
    document.getElementById('wallet-main').innerHTML =
        `<div class="empty-state"><div class="empty-state-msg">
         Error: ${esc(err.message)}
       </div></div>`;
  }
}

function renderWalletMain(data) {
  const w        = data.wallet;
  const unlocked = data.unlocked;
  const balance  = data.balance || 0;
  const main     = document.getElementById('wallet-main');

  main.innerHTML = `
    <!-- Lock bar -->
    <div class="lock-bar">
      <span class="lock-icon">${unlocked ? '🔓' : '🔒'}</span>
      <span class="lock-msg">
        ${unlocked
      ? `<strong>${esc(w.name)}</strong> is unlocked`
      : `<strong>${esc(w.name)}</strong> is locked — unlock to view addresses`}
      </span>
      ${unlocked
      ? `<button class="btn-copy" onclick="lockWallet('${w.id}')">Lock</button>`
      : `<button class="btn-copy" style="border-color:var(--accent);color:var(--accent)"
                   onclick="showUnlockModal('${w.id}','${esc(w.name)}')">Unlock</button>`}
    </div>

    ${unlocked ? `
    <!-- Balance + action buttons -->
    <div class="wallet-panel">
      <div class="balance-display">
        <div class="balance-hns">${formatHns(balance)}</div>
        <div class="balance-label">HNS</div>
      </div>
      <div style="display:flex;gap:0.75rem;justify-content:center;
                  padding:0.75rem 0 0.25rem">
        <button class="btn-primary" style="max-width:140px;opacity:0.45;
                cursor:not-allowed" title="Coming soon">
          ↑ Send
        </button>
        <button class="btn-primary" style="max-width:140px"
                onclick="showReceivePanel('${w.id}')">
          ↓ Receive
        </button>
      </div>
    </div>

    <!-- Receive panel (shown on demand) -->
    <div id="receive-panel" style="display:none" class="wallet-panel">
      <div class="wallet-panel-title">Receive HNS</div>
      <div style="font-size:0.75rem;color:var(--muted);margin-bottom:0.75rem">
        Share this address with the sender. Each address can be reused,
        but a fresh address is generated for each receive for better privacy.
      </div>
      <div class="receive-addr" id="receive-addr-row">
        <span id="next-addr" style="word-break:break-all;flex:1">
          Generating address...
        </span>
        <button class="btn-copy" id="copy-addr-btn" onclick="copyReceiveAddr()">
          📋
        </button>
      </div>
    </div>

    <!-- Names -->
    <div class="wallet-panel" id="names-panel">
      <div class="wallet-panel-title">Owned Names</div>
      <div style="color:var(--muted);font-size:0.78rem">Loading names...</div>
    </div>
    ` : `
    <div class="wallet-panel">
      <div style="color:var(--muted);font-size:0.85rem;text-align:center;
                  padding:2rem">
        Unlock the wallet to view addresses and balance.
      </div>
    </div>
    `}
  `;

  if (unlocked) loadNames(w.id);
}

// ── IDN / Punycode decoding ───────────────────────────────────────────────────

function decodePunycode(input) {
  // RFC 3492 Punycode decoder
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const initialBias = 72, initialN = 128, delimiter = '-';
  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  }
  function decodeDigit(cp) {
    return cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : base;
  }
  const src = input.toLowerCase().startsWith('xn--') ? input.slice(4) : input;
  const output = [];
  const basic = src.lastIndexOf(delimiter);
  if (basic > 0) for (let j = 0; j < basic; j++) output.push(src.charCodeAt(j));
  let i = 0, n = initialN, bias = initialBias, idx = basic > 0 ? basic + 1 : 0;
  while (idx < src.length) {
    const oldi = i; let w = 1;
    for (let k = base; ; k += base) {
      const digit = decodeDigit(src.charCodeAt(idx++));
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

function decodeIdn(name) {
  if (!name.toLowerCase().includes('xn--')) return null;
  try {
    const decoded = decodePunycode(name);
    return decoded !== name ? decoded : null;
  } catch (e) { return null; }
}

function nameDisplay(name) {
  const decoded = decodeIdn(name);
  if (!decoded) return '<span class="name-tag">.' + esc(name) + '</span>';
  return '<span class="name-tag">.' + esc(name) + '</span>'
      + ' <span style="color:var(--muted);font-size:0.75rem">(' + esc(decoded) + ')</span>';
}

// ── Names table ──────────────────────────────────────────────────────────────

let namesSortCol = 'name';
let namesSortDir = 1; // 1 = asc, -1 = desc
let namesCache   = [];

async function loadNames(walletId) {
  try {
    const res = await fetch('/api/wallet/' + walletId + '/names');
    namesCache = await res.json();
    renderNamesTable();
  } catch (err) { /* ignore */ }
}

function renderNamesTable() {
  const el = document.getElementById('names-panel');
  if (!el) return;

  if (namesCache.length === 0) {
    el.innerHTML = `<div class="wallet-panel-title">Owned Names</div>
      <div style="color:var(--muted);font-size:0.78rem;padding:1rem 0">
        No names found in this wallet yet.<br>
        Names will appear here after the UTXO scanner runs.
      </div>`;
    return;
  }

  const sorted = [...namesCache].sort((a, b) => {
    let va, vb;
    if (namesSortCol === 'name')    { va = a.name;         vb = b.name; }
    if (namesSortCol === 'expires') { va = a.expireHeight; vb = b.expireHeight; }
    if (namesSortCol === 'status')  { va = a.state;        vb = b.state; }
    if (va < vb) return -namesSortDir;
    if (va > vb) return  namesSortDir;
    return 0;
  });

  const arrow  = col => namesSortCol === col ? (namesSortDir === 1 ? ' ↑' : ' ↓') : '';
  const thBase = `cursor:pointer;user-select:none;font-size:0.65rem;letter-spacing:0.08em;
    color:var(--muted);padding:0.5rem 0.75rem;text-align:left;
    border-bottom:1px solid var(--border);font-family:'Space Mono',monospace;white-space:nowrap`;
  const thNoSort = `font-size:0.65rem;letter-spacing:0.08em;color:var(--muted);
    padding:0.5rem 0.75rem;text-align:left;border-bottom:1px solid var(--border);
    font-family:'Space Mono',monospace`;

  el.innerHTML = `
    <div class="wallet-panel-title">Owned Names (${namesCache.length})</div>
    <table style="width:100%;border-collapse:collapse;font-size:0.82rem">
      <thead><tr>
        <th style="${thBase}" onclick="sortNames('name')"
            onmouseover="this.style.color='var(--accent)'"
            onmouseout="this.style.color='var(--muted)'">NAME${arrow('name')}</th>
        <th style="${thBase}" onclick="sortNames('expires')"
            onmouseover="this.style.color='var(--accent)'"
            onmouseout="this.style.color='var(--muted)'">EXPIRES${arrow('expires')}</th>
        <th style="${thBase}" onclick="sortNames('status')"
            onmouseover="this.style.color='var(--accent)'"
            onmouseout="this.style.color='var(--muted)'">STATUS${arrow('status')}</th>
        <th style="${thNoSort}">ACTIONS</th>
      </tr></thead>
      <tbody>
        ${sorted.map(n => `
          <tr style="border-bottom:1px solid var(--border)">
            <td style="padding:0.6rem 0.75rem">
              ${nameDisplay(n.name)}
            </td>
            <td style="padding:0.6rem 0.75rem">
              <span class="name-expiry ${expiryClass(n.expireHeight)}">
                ${expiryText(n.expireHeight)}
              </span>
            </td>
            <td style="padding:0.6rem 0.75rem;font-size:0.65rem;
                       color:var(--muted);font-family:'Space Mono',monospace">
              ${esc(n.state)}
            </td>
            <td style="padding:0.6rem 0.75rem;white-space:nowrap">
              <button class="action-btn" onclick="transferName('${esc(n.name)}')">Transfer</button>
              <button class="action-btn" onclick="manageDns('${esc(n.name)}')">DNS</button>
              <button class="action-btn" onclick="nameHistory('${esc(n.name)}')">History</button>
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
}

function sortNames(col) {
  if (namesSortCol === col) namesSortDir *= -1;
  else { namesSortCol = col; namesSortDir = 1; }
  renderNamesTable();
}

function transferName(name) { alert('Transfer .' + name + ' — coming soon'); }
function manageDns(name)    { alert('DNS for .'  + name + ' — coming soon'); }
function nameHistory(name)  { alert('History for .' + name + ' — coming soon'); }

function expiryText(expireHeight) {
  const remaining = expireHeight - tipHeight;
  if (remaining <= 0) return 'expired';
  // ~144 blocks per day (10 min per block)
  const days   = Math.floor(remaining / 144);
  const years  = Math.floor(days / 365);
  const months = Math.floor((days % 365) / 30);
  const parts  = [];
  if (years  > 0) parts.push(years  + (years  === 1 ? ' year'  : ' years'));
  if (months > 0) parts.push(months + (months === 1 ? ' month' : ' months'));
  if (parts.length === 0) {
    const weeks = Math.floor(days / 7);
    if (weeks > 0) return `expires in ${weeks} ${weeks === 1 ? 'week' : 'weeks'}`;
    return `expires in ${days} ${days === 1 ? 'day' : 'days'}`;
  }
  return `expires in ${parts.join(' ')}`;
}

function expiryClass(expireHeight) {
  const remaining = expireHeight - tipHeight;
  if (remaining < 1008)  return 'danger';  // < 1 week
  if (remaining < 4320)  return 'warn';    // < 1 month
  return '';
}

// ── Receive panel ─────────────────────────────────────────────────────────────

async function showReceivePanel(walletId) {
  const panel = document.getElementById('receive-panel');
  const addrEl = document.getElementById('next-addr');
  if (!panel) return;

  panel.style.display = 'block';
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const res  = await fetch('/api/wallet/' + walletId + '/address');
    const data = await res.json();
    if (addrEl) addrEl.textContent = data.address || 'Error generating address';
  } catch (err) {
    if (addrEl) addrEl.textContent = 'Error: ' + err.message;
  }
}

function copyReceiveAddr() {
  const addr = document.getElementById('next-addr')?.textContent?.trim();
  if (!addr || addr.startsWith('Error') || addr === 'Generating address...') return;
  navigator.clipboard.writeText(addr).then(() => {
    const btn = document.getElementById('copy-addr-btn');
    if (btn) {
      btn.textContent = '✓';
      btn.style.color = 'var(--accent2)';
      setTimeout(() => {
        btn.textContent = '📋';
        btn.style.color = '';
      }, 2500);
    }
  });
}

// ── Lock / Unlock ─────────────────────────────────────────────────────────────

async function lockWallet(id) {
  await fetch('/api/wallet/' + id + '/lock', { method: 'POST' });
  await loadWallets();
  if (activeWalletId === id) selectWallet(id);
}

function showUnlockModal(id, name) {
  document.getElementById('unlock-msg').textContent =
      'Enter your password to unlock "' + name + '"';
  document.getElementById('unlock-password').value = '';
  document.getElementById('unlock-error').classList.add('hidden');
  document.getElementById('unlock-error').textContent = '';
  document.getElementById('unlock-modal').dataset.walletId = id;
  document.getElementById('unlock-modal').classList.remove('hidden');
  setTimeout(() => document.getElementById('unlock-password').focus(), 100);
}

async function unlockWallet() {
  const id       = document.getElementById('unlock-modal').dataset.walletId;
  const password = document.getElementById('unlock-password').value;
  const errEl    = document.getElementById('unlock-error');

  try {
    const res  = await fetch('/api/wallet/' + id + '/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();
    if (data.ok) {
      hideModals();
      await loadWallets();
      selectWallet(id);
      // Start polling for scan progress
      pollScanStatus();
    } else {
      errEl.textContent = data.error || 'Incorrect password';
      errEl.classList.remove('hidden');
    }
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.remove('hidden');
  }
}

// ── Create wallet ─────────────────────────────────────────────────────────────

function showCreateModal() {
  document.getElementById('create-name').value = '';
  document.getElementById('create-password').value = '';
  document.getElementById('create-password2').value = '';
  document.getElementById('create-error').classList.add('hidden');
  updateStrengthBar('');
  document.getElementById('create-modal').classList.remove('hidden');
  setTimeout(() => document.getElementById('create-name').focus(), 100);
}

function updateStrengthBar(password, fillId, labelId) {
  fillId  = fillId  || 'strength-fill';
  labelId = labelId || 'strength-label';
  const bar   = document.getElementById(fillId);
  const label = document.getElementById(labelId);
  if (!bar) return;

  let score = 0;
  if (password.length >= 8)            score++;
  if (password.length >= 12)           score++;
  if (/[A-Z]/.test(password))          score++;
  if (/[0-9]/.test(password))          score++;
  if (/[^A-Za-z0-9]/.test(password))  score++;

  const levels = [
    { pct: 0,   color: 'transparent', text: '' },
    { pct: 20,  color: '#f85149',     text: 'Very weak' },
    { pct: 40,  color: '#e36209',     text: 'Weak' },
    { pct: 60,  color: '#d29922',     text: 'Fair' },
    { pct: 80,  color: '#3fb950',     text: 'Strong' },
    { pct: 100, color: '#2ea043',     text: 'Very strong' },
  ];
  const level = levels[score];
  bar.style.width      = level.pct + '%';
  bar.style.background = level.color;
  if (label) { label.textContent = level.text; label.style.color = level.color; }
}

async function createWallet() {
  const name   = document.getElementById('create-name').value.trim();
  const pass1  = document.getElementById('create-password').value;
  const pass2  = document.getElementById('create-password2').value;
  const errEl  = document.getElementById('create-error');

  if (!name)         { showErr(errEl, 'Please enter a wallet name'); return; }
  if (!pass1)        { showErr(errEl, 'Please enter a password'); return; }
  if (pass1 !== pass2) { showErr(errEl, 'Passwords do not match'); return; }

  try {
    const res  = await fetch('/api/wallet/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, password: pass1, words: '24' }),
    });
    const data = await res.json();
    if (data.ok) {
      hideModals();
      showMnemonicModal(data.mnemonic);
      await loadWallets();
      if (activeWalletId !== data.walletId)
        selectWallet(data.walletId);
    } else {
      showErr(errEl, data.error || 'Failed to create wallet');
    }
  } catch (err) {
    showErr(errEl, err.message);
  }
}

function showMnemonicModal(mnemonic) {
  const words = mnemonic.split(' ');
  const grid  = document.getElementById('mnemonic-grid');
  grid.innerHTML = words.map((w, i) => `
    <div class="mnemonic-word">
      <span class="mnemonic-num">${i + 1}.</span>
      <span>${esc(w)}</span>
    </div>`).join('');

  // Store mnemonic for copy button
  document.getElementById('mnemonic-modal').dataset.mnemonic = mnemonic;
  document.getElementById('mnemonic-modal').classList.remove('hidden');
}

function copyMnemonic() {
  const mnemonic = document.getElementById('mnemonic-modal').dataset.mnemonic;
  if (!mnemonic) return;
  navigator.clipboard.writeText(mnemonic).then(() => {
    const btn = document.getElementById('copy-mnemonic-btn');
    if (btn) {
      btn.textContent = '✓ Copied!';
      btn.style.color = 'var(--accent2)';
      setTimeout(() => {
        btn.textContent = '📋 Copy seed phrase';
        btn.style.color = '';
      }, 2500);
    }
  });
}

// ── Restore wallet ────────────────────────────────────────────────────────────

function showRestoreModal() {
  document.getElementById('restore-name').value = '';
  document.getElementById('restore-mnemonic').value = '';
  document.getElementById('restore-password').value = '';
  document.getElementById('restore-password2').value = '';
  document.getElementById('restore-error').classList.add('hidden');
  updateStrengthBar('', 'restore-strength-fill', 'restore-strength-label');
  document.getElementById('restore-modal').classList.remove('hidden');
  setTimeout(() => document.getElementById('restore-name').focus(), 100);
}

async function restoreWallet() {
  const name     = document.getElementById('restore-name').value.trim();
  const password = document.getElementById('restore-password').value;
  const password2= document.getElementById('restore-password2').value;
  const errEl    = document.getElementById('restore-error');

  // Clean the mnemonic — normalize whitespace, remove punctuation,
  // handle newlines and extra spaces from copy/paste
  const rawMnemonic = document.getElementById('restore-mnemonic').value;
  const mnemonic    = rawMnemonic
      .toLowerCase()
      .replace(/[^a-z\s]/g, '')   // remove any non-letter chars (punctuation, numbers)
      .replace(/\s+/g, ' ')       // collapse all whitespace to single spaces
      .trim();

  const wordCount = mnemonic ? mnemonic.split(' ').length : 0;

  if (!name)           { showErr(errEl, 'Please enter a wallet name'); return; }
  if (!mnemonic)       { showErr(errEl, 'Please enter your seed phrase'); return; }
  if (wordCount !== 24) { showErr(errEl, `Seed phrase must be 24 words (you entered ${wordCount})`); return; }
  if (!password)       { showErr(errEl, 'Please enter a password'); return; }
  if (password !== password2) { showErr(errEl, 'Passwords do not match'); return; }

  try {
    const res  = await fetch('/api/wallet/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, mnemonic, passphrase: '', password }),
    });
    const data = await res.json();
    if (data.ok) {
      hideModals();
      const res2     = await fetch('/api/wallet');
      const data2    = await res2.json();
      wallets        = data2.wallets || data2;
      activeWalletId = data.walletId;
      renderSidebar();
      selectWallet(data.walletId);
      // Trigger scan for newly restored wallet
      fetch('/api/wallet/scan', { method: 'POST' }).catch(() => {});
      pollScanStatus();
    } else {
      showErr(errEl, data.error || 'Failed to recover wallet');
    }
  } catch (err) {
    showErr(errEl, err.message);
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function hideModals() {
  document.querySelectorAll('.modal-overlay').forEach(m =>
      m.classList.add('hidden'));
}

function showErr(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

function copyAddr() {
  const addr = document.getElementById('next-addr')?.textContent;
  if (!addr) return;
  navigator.clipboard.writeText(addr).then(() => {
    const btn = document.querySelector('.btn-copy');
    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy', 2000); }
  });
}

function formatHns(satoshis) {
  return (satoshis / 1_000_000).toLocaleString(undefined,
      { minimumFractionDigits: 2, maximumFractionDigits: 6 });
}

function esc(str) {
  return String(str)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Close modal on overlay click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', e => {
    if (e.target === overlay) hideModals();
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
loadWallets();