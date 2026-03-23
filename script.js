'use strict';

// Configuration
const SUBSTR_LENGTHS = [6, 7, 8];   // window sizes to check
const TOP_N          = 10_000;      // lines used for substring Set

// State
let commonPasswords = null;   // full Set  — exact match
let substrDB        = null;   // small Set — substring match
let dbState = 'loading';      // 'loading' | 'ready' | 'error'
let dbCount = 0;

// References
const input         = document.getElementById('password-input');
const wrapper       = document.getElementById('input-wrapper');
const feedbackEl    = document.getElementById('feedback-content');
const strengthFill  = document.getElementById('strength-fill');
const strengthLabel = document.getElementById('strength-label');
const toggleBtn     = document.getElementById('toggle-btn');
const eyeIcon       = document.getElementById('eye-icon');
const eyeOffIcon    = document.getElementById('eye-off-icon');
const dbBanner      = document.getElementById('db-banner');
const dbStatus      = document.getElementById('db-status');
const filePicker    = document.getElementById('file-picker');
const dlBtn         = document.getElementById('dl-btn');

const reqItems = {
  upper:   document.getElementById('req-upper'),
  lower:   document.getElementById('req-lower'),
  digit:   document.getElementById('req-digit'),
  special: document.getElementById('req-special'),
  common:  document.getElementById('req-common'),
  substr:  document.getElementById('req-substr'),
  length:  document.getElementById('req-length'),
};

function buildSets(text) {
  const lines = text.split('\n')
                    .map(l => l.trim().toLowerCase())
                    .filter(l => l.length > 0);

  const full   = new Set(lines);
  const topSet = new Set(lines.slice(0, TOP_N));

  return { full, topSet };
}

function findSubstrMatch(lowerPassword) {
  for (const len of SUBSTR_LENGTHS) {
    const limit = lowerPassword.length - len;
    for (let i = 0; i <= limit; i++) {
      const slice = lowerPassword.slice(i, i + len);
      if (substrDB.has(slice)) return slice;  
    }
  }
  return null;
}

function onDbReady(full, topSet) {
  commonPasswords = full;
  substrDB        = topSet;
  dbCount         = full.size;
  dbState         = 'ready';
  dbBanner.className        = 'db-banner db-ok';
  dbStatus.textContent      =
    `✓ DB loaded — ${dbCount.toLocaleString()} entries` +
    ` (substring: top ${TOP_N.toLocaleString()})`;
  filePicker.style.display  = 'none';
  dlBtn.style.display       = 'none';
  if (input.value.length > 0) validate(input.value);
}

function onDbError(reason) {
  dbState               = 'error';
  dbBanner.className    = 'db-banner db-err';
  dbStatus.innerHTML    =
    `⚠ DB load failed (${reason}). ` +
    `<label class="pick-label" for="file-picker">Select file manually ▶</label>`;
  filePicker.style.display = 'inline';
  dlBtn.style.display      = 'flex';
  if (input.value.length > 0) validate(input.value);
}

(async function tryFetch() {
  if (location.protocol === 'file:') {
    onDbError('file:// protocol — use a local server or load manually');
    return;
  }
  try {
    const res = await fetch('common-passwords.txt');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const { full, topSet } = buildSets(text);
    if (full.size === 0) throw new Error('file appears empty');
    onDbReady(full, topSet);
  } catch (err) {
    console.error('[DB] fetch failed:', err);
    onDbError(err.message);
  }
})();

filePicker.addEventListener('change', () => {
  const file = filePicker.files[0];
  if (!file) return;
  dbState               = 'loading';
  dbBanner.className    = 'db-banner db-loading';
  dbStatus.textContent  = `⟳ Reading ${file.name}…`;
  const reader          = new FileReader();
  reader.onload = e => {
    const { full, topSet } = buildSets(e.target.result);
    if (full.size === 0) { onDbError('file appears empty'); return; }
    onDbReady(full, topSet);
  };
  reader.onerror = () => onDbError('FileReader error');
  reader.readAsText(file);
});

// Rules for password requirements
const RULES = {
  upper:   { re: /[A-Z]/,        label: 'uppercase letter' },
  lower:   { re: /[a-z]/,        label: 'lowercase letter' },
  digit:   { re: /[0-9]/,        label: 'digit' },
  special: { re: /[^A-Za-z0-9]/, label: 'special character' },
  length:  { fn: v => v.length >= 8, label: 'minimum length (8)' },
};

// Validation
function validate(password) {
  if (dbState === 'loading') {
    setFeedback('loading', 'Loading password database…');
    setStrength(0, 'LOADING');
    resetReqs();
    setWrapper('');
    return;
  }

  if (dbState === 'error') {
    setFeedback('dberr', 'DB unavailable — load the file manually above');
    setStrength(0, 'DB ERROR');
    resetReqs();
    setWrapper('');
    return;
  }

  if (password.length === 0) {
    setFeedback('idle');
    setStrength(0, 'AWAITING INPUT');
    resetReqs();
    setWrapper('');
    return;
  }

  const lower       = password.toLowerCase();
  const isExact     = commonPasswords.has(lower);
  const substrMatch = isExact ? null : findSubstrMatch(lower);

  const results = {
    upper:   RULES.upper.re.test(password),
    lower:   RULES.lower.re.test(password),
    digit:   RULES.digit.re.test(password),
    special: RULES.special.re.test(password),
    length:  RULES.length.fn(password),
    common:  !isExact,
    substr:  !substrMatch,
  };

  // Update requirements
  for (const [key, el] of Object.entries(reqItems)) {
    el.classList.toggle('pass', results[key]);
    el.classList.toggle('fail', !results[key]);
  }

  const missingKeys = ['upper', 'lower', 'digit', 'special', 'length']
    .filter(k => !results[k]);
  const score = Object.values(results).filter(Boolean).length;

  if (isExact) {
    setFeedback('rejected', 'Rejected: Common password',
      `Exact match in DB (${dbCount.toLocaleString()} entries checked).`);
    setStrength(score / 7, 'COMPROMISED');
    setWrapper('invalid');
  } else if (substrMatch) {
    setFeedback('rejected', 'Rejected: Contains common substring',
      `Password contains "${substrMatch}" (top ${TOP_N.toLocaleString()} list).`);
    setStrength(score / 7, 'COMPROMISED');
    setWrapper('invalid');
  } else if (missingKeys.length > 0) {
    const missing = missingKeys.map(k => RULES[k]?.label || k).join(', ');
    setFeedback('rejected', 'Rejected: Missing required complexity',
      `Missing: ${missing}`);
    setStrength(score / 7, strengthWord(score));
    setWrapper('invalid');
  } else {
    setFeedback('accepted', 'Accepted',
      'Passphrase meets all security requirements.');
    setStrength(1, 'STRONG');
    setWrapper('valid');
  }
}

function setFeedback(type, headline, detail) {
  feedbackEl.innerHTML = '';
  if (type === 'idle') {
    feedbackEl.innerHTML = `<span class="idle-msg">System ready. Enter a passphrase to begin analysis…</span>`;
    return;
  }
  if (type === 'loading') {
    feedbackEl.innerHTML = `<span class="msg-loading">⟳ ${headline}</span>`;
    return;
  }
  if (type === 'dberr') {
    feedbackEl.innerHTML = `<span class="msg-loading">⚠ ${headline}</span>`;
    return;
  }
  const cls    = type === 'accepted' ? 'msg-accepted' : 'msg-rejected';
  const prefix = type === 'accepted' ? '✓' : '✗';
  let html = `<span class="${cls}">${prefix} ${headline}</span>`;
  if (detail) html += `<span class="msg-detail">${detail}</span>`;
  feedbackEl.innerHTML = html;
}

function setStrength(ratio, label) {
  strengthFill.style.width = `${Math.round(ratio * 100)}%`;
  const color =
    ratio === 0   ? 'var(--text-dim)' :
    ratio <= 0.33 ? 'var(--red)'      :
    ratio <= 0.66 ? 'var(--yellow)'   :
    ratio < 1     ? 'var(--accent)'   : 'var(--green)';
  strengthFill.style.background = color;
  strengthLabel.textContent     = label;
  strengthLabel.style.color     = ratio === 0 ? 'var(--text-dim)' : color;
}

function strengthWord(score) {
  const words = ['', 'VERY WEAK', 'WEAK', 'FAIR', 'MODERATE', 'GOOD', 'STRONG'];
  return words[Math.min(score, words.length - 1)] || 'WEAK';
}

function setWrapper(state) {
  wrapper.classList.remove('state-valid', 'state-invalid');
  if (state === 'valid')   wrapper.classList.add('state-valid');
  if (state === 'invalid') wrapper.classList.add('state-invalid');
}

function resetReqs() {
  for (const el of Object.values(reqItems)) {
    el.classList.remove('pass', 'fail');
  }
}

// Events
input.addEventListener('input', () => validate(input.value));

toggleBtn.addEventListener('click', () => {
  const isHidden        = input.type === 'password';
  input.type            = isHidden ? 'text'  : 'password';
  eyeIcon.style.display    = isHidden ? 'none' : '';
  eyeOffIcon.style.display = isHidden ? ''     : 'none';
  input.focus();
});
