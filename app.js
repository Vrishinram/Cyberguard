/* ============================================================
   CyGuard — Password Strength Analyzer  |  Core Logic
   ============================================================
   Features:
   1. Real-time strength analysis (length, complexity, entropy)
   2. Criteria checklist with animated state
   3. Crack-time estimation
   4. Breach exposure check via Have I Been Pwned (k-anonymity)
   5. Suggested strong passwords
   6. Password history via localStorage (reuse prevention)
   7. Educational "Learn" section
   ============================================================ */

// ─── Common Passwords Database (top 200) ──────────────────────
const COMMON_PASSWORDS = new Set([
  'password','123456','123456789','12345678','12345','1234567','1234567890',
  'qwerty','abc123','111111','password1','iloveyou','1q2w3e4r','000000',
  'qwerty123','zaq12wsx','dragon','sunshine','princess','letmein','654321',
  'monkey','27653','1qaz2wsx','123321','qwertyuiop','superman','asdfghjkl',
  'trustno1','welcome','master','hello','charlie','donald','football',
  'shadow','michael','login','baseball','starwars','passw0rd','jordan',
  'access','ranger','thomas','buster','hunter','soccer','harley','batman',
  'andrew','tigger','2000','robert','andrea','ashley','pepper','killer',
  'admin','admin123','root','toor','pass','test','guest','changeme',
  'default','password123','letmein123','welcome1','p@ssw0rd','p@ssword',
  'qwerty1','123qwe','1q2w3e','q1w2e3r4','zaq1xsw2','1234','12345678910',
  'abcdef','abcdefg','abcdefgh','aaaaaa','abc','password1234','iloveu',
  'trustno1','monkey123','dragon1','whatever','freedom','master1',
  'fuckyou','bailey','shadow1','passpass','jessica','jennifer','jordan23',
  'chelsea','diamond','michelle','liverpool','matrix','cheese','computer',
  'corvette','mercedes','midnight','samantha','falcon','dolphin','chester',
  'jackson','forever','friend','mother','father','summer','winter',
  'tennis','hockey','george','internet','coffee','guitar','chicken',
  'pepper1','ginger','sparky','maggie','global','hammer','silver',
  'cookie','peanut','orange','yankees','thunder','joshua','digital',
  'ginger1','flower','secret','lovely','purple','angel1','angel',
  'junior','family','member','matrix1','heaven','jasper','nicole',
  'rocket','nothing','dallas','brandy','racing','butter','genius',
  '11111111','00000000','99999999','88888888','77777777','55555555',
  'asdf','zxcv','qazwsx','1234qwer','qwer1234','!@#$%^&*','password!',
  'pa55w0rd','pa$$word','p@55w0rd','passw0rd!','admin1','admin1234',
  'administrator','user','user123','test123','demo','demo123',
]);

// ─── Keyboard Sequences / Patterns ────────────────────────────
const KEYBOARD_SEQUENCES = [
  'qwertyuiop','asdfghjkl','zxcvbnm','qwerty','asdfgh','zxcvbn',
  '1234567890','qazwsx','wsxedc','rfvtgb','tgbyhn','yhnujm',
  '!@#$%^&*()', 'qweasdzxc','poiuytrewq','lkjhgfdsa','mnbvcxz',
];

// ─── DOM References ───────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const passwordInput   = $('#passwordInput');
const toggleBtn       = $('#toggleVisibility');
const eyeShow         = $('#eyeIconShow');
const eyeHide         = $('#eyeIconHide');
const strengthBar     = $('#strengthBar');
const strengthLabel   = $('#strengthLabel');
const strengthScore   = $('#strengthScore');
const statLenVal      = $('#statLengthValue');
const statEntVal      = $('#statEntropyValue');
const statCharVal     = $('#statCharsetValue');
const statCrackVal    = $('#statCrackValue');
const criteriaChecks  = {
  length:   { el: $('#criteriaLengthCheck'),   item: $('#criteriaLength') },
  upper:    { el: $('#criteriaUpperCheck'),     item: $('#criteriaUpper') },
  lower:    { el: $('#criteriaLowerCheck'),     item: $('#criteriaLower') },
  digit:    { el: $('#criteriaDigitCheck'),     item: $('#criteriaDigit') },
  special:  { el: $('#criteriaSpecialCheck'),   item: $('#criteriaSpecial') },
  noRepeat: { el: $('#criteriaNoRepeatCheck'),  item: $('#criteriaNoRepeat') },
  noCommon: { el: $('#criteriaNoCommonCheck'),  item: $('#criteriaNoCommon') },
};
const suggestionsList    = $('#suggestionsList');
const generatedList      = $('#generatedPasswordsList');
const refreshBtn         = $('#refreshPasswords');
const breachBtn          = $('#breachCheckBtn');
const breachResult       = $('#breachResult');
const navLinks           = document.querySelectorAll('.header__link');
const sections           = { analyzer: $('#analyzer'), history: $('#history'), learn: $('#learn') };
const heroSection        = $('#heroSection');
const historyList        = $('#historyList');
const historyEmpty       = $('#historyEmpty');
const clearHistoryBtn    = $('#clearHistory');

// ─── State ────────────────────────────────────────────────────
let passwordHistory = JSON.parse(localStorage.getItem('cyguard_history') || '[]');
let currentSection = 'analyzer';
let isPasswordVisible = false;

// ─── Navigation ───────────────────────────────────────────────
navLinks.forEach(link => {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const target = link.getAttribute('href').replace('#', '');
    switchSection(target);
  });
});

function switchSection(name) {
  currentSection = name;
  // Toggle sections
  Object.entries(sections).forEach(([key, el]) => {
    el.style.display = key === name ? '' : 'none';
  });
  heroSection.style.display = name === 'analyzer' ? '' : 'none';
  // Update nav
  navLinks.forEach(l => {
    l.classList.toggle('header__link--active', l.getAttribute('href') === '#' + name);
  });
  // Load history when switching to it
  if (name === 'history') renderHistory();
}

// ─── Toggle Visibility ───────────────────────────────────────
toggleBtn.addEventListener('click', () => {
  isPasswordVisible = !isPasswordVisible;
  passwordInput.type = isPasswordVisible ? 'text' : 'password';
  eyeShow.style.display = isPasswordVisible ? 'none' : '';
  eyeHide.style.display = isPasswordVisible ? '' : 'none';
});

// ─── Password Analysis Engine ─────────────────────────────────

/**
 * Calculates charset size based on characters used.
 */
function getCharsetSize(pw) {
  let size = 0;
  if (/[a-z]/.test(pw)) size += 26;
  if (/[A-Z]/.test(pw)) size += 26;
  if (/[0-9]/.test(pw)) size += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) size += 33; // common specials
  return size;
}

/**
 * Calculates Shannon entropy in bits.
 */
function calcEntropy(pw) {
  const charset = getCharsetSize(pw);
  if (charset === 0 || pw.length === 0) return 0;
  return pw.length * Math.log2(charset);
}

/**
 * Checks for repeated character sequences (e.g., aaa, 111, abcabc).
 */
function hasRepeatedSequences(pw) {
  // 3+ same character in a row
  if (/(.)\1{2,}/.test(pw)) return true;
  // Sequential digits (ascending or descending, 3+)
  for (let i = 0; i < pw.length - 2; i++) {
    const a = pw.charCodeAt(i), b = pw.charCodeAt(i+1), c = pw.charCodeAt(i+2);
    if (b - a === 1 && c - b === 1) return true;
    if (a - b === 1 && b - c === 1) return true;
  }
  // Keyboard sequences
  const lower = pw.toLowerCase();
  for (const seq of KEYBOARD_SEQUENCES) {
    if (lower.includes(seq) || lower.includes(seq.split('').reverse().join(''))) return true;
  }
  return false;
}

/**
 * Checks if the password is in the common passwords list (case-insensitive).
 */
function isCommonPassword(pw) {
  return COMMON_PASSWORDS.has(pw.toLowerCase());
}

/**
 * Checks if the password was used before (in local history).
 */
function isReusedPassword(pw) {
  return passwordHistory.some(h => h.masked === maskPassword(pw));
}

/**
 * Estimates time to crack via brute-force at 10 billion guesses/second.
 */
function estimateCrackTime(pw) {
  const charset = getCharsetSize(pw);
  if (charset === 0 || pw.length === 0) return '—';
  const combinations = Math.pow(charset, pw.length);
  const guessesPerSecond = 1e10; // 10B/s (modern GPU)
  let seconds = combinations / guessesPerSecond / 2; // average case

  if (seconds < 0.001) return 'Instant';
  if (seconds < 1) return '< 1 second';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 86400 * 365) return `${Math.round(seconds / 86400)} days`;
  if (seconds < 86400 * 365 * 1000) return `${Math.round(seconds / (86400 * 365))} years`;
  if (seconds < 86400 * 365 * 1e6) return `${(seconds / (86400 * 365 * 1000)).toFixed(0)}K years`;
  if (seconds < 86400 * 365 * 1e9) return `${(seconds / (86400 * 365 * 1e6)).toFixed(0)}M years`;
  if (seconds < 86400 * 365 * 1e12) return `${(seconds / (86400 * 365 * 1e9)).toFixed(0)}B years`;
  return '∞ (heat death)';
}

/**
 * Computes overall strength score (0-100).
 */
function computeStrengthScore(pw) {
  if (pw.length === 0) return 0;

  let score = 0;

  // Length contribution (up to 30 points)
  score += Math.min(pw.length * 2.5, 30);

  // Character diversity (up to 25 points)
  const types = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];
  const typeCount = types.filter(r => r.test(pw)).length;
  score += typeCount * 6.25;

  // Entropy contribution (up to 25 points)
  const entropy = calcEntropy(pw);
  score += Math.min(entropy / 4, 25);

  // Penalties
  if (isCommonPassword(pw)) score -= 40;
  if (hasRepeatedSequences(pw)) score -= 15;
  if (pw.length < 6) score -= 15;

  // Bonus for length > 16
  if (pw.length > 16) score += 5;
  if (pw.length > 20) score += 5;

  return Math.max(0, Math.min(100, Math.round(score)));
}

/**
 * Gets strength label and class from score.
 */
function getStrengthInfo(score) {
  if (score <= 20) return { label: 'Very Weak', cls: 'weak', gradient: 'var(--gradient-strength-weak)' };
  if (score <= 40) return { label: 'Weak', cls: 'weak', gradient: 'var(--gradient-strength-weak)' };
  if (score <= 55) return { label: 'Fair', cls: 'fair', gradient: 'var(--gradient-strength-fair)' };
  if (score <= 75) return { label: 'Good', cls: 'good', gradient: 'var(--gradient-strength-good)' };
  if (score <= 90) return { label: 'Strong', cls: 'strong', gradient: 'var(--gradient-strength-strong)' };
  return { label: 'Excellent', cls: 'excellent', gradient: 'var(--gradient-strength-excellent)' };
}

/**
 * Generates improvement suggestions.
 */
function getSuggestions(pw) {
  const tips = [];
  if (pw.length === 0) return tips;
  if (pw.length < 8) tips.push('Add more characters — aim for at least 12 for strong security.');
  else if (pw.length < 12) tips.push('Consider extending to 12+ characters for better protection.');
  if (!/[A-Z]/.test(pw)) tips.push('Include uppercase letters to expand the character space.');
  if (!/[a-z]/.test(pw)) tips.push('Include lowercase letters for added complexity.');
  if (!/[0-9]/.test(pw)) tips.push('Add digits to increase randomness.');
  if (!/[^a-zA-Z0-9]/.test(pw)) tips.push('Use special characters like !@#$%^&* to greatly increase entropy.');
  if (hasRepeatedSequences(pw)) tips.push('Avoid repeated characters and keyboard sequences (e.g., "aaa", "qwerty", "123").');
  if (isCommonPassword(pw)) tips.push('This is a very common password — attackers try these first! Choose something unique.');
  if (pw.length >= 12 && tips.length === 0) tips.push('Great password! Consider using a passphrase for even better memorability.');
  return tips;
}

// ─── UI Update ────────────────────────────────────────────────

function updateUI(pw) {
  const score = computeStrengthScore(pw);
  const info = getStrengthInfo(score);
  const entropy = calcEntropy(pw);
  const charset = getCharsetSize(pw);
  const crackTime = estimateCrackTime(pw);

  // Strength bar
  strengthBar.style.width = `${score}%`;
  strengthBar.style.background = info.gradient;

  // Labels
  if (pw.length === 0) {
    strengthLabel.textContent = 'Enter a password';
    strengthLabel.className = 'strength-meter__label';
    strengthScore.textContent = '';
  } else {
    strengthLabel.textContent = info.label;
    strengthLabel.className = `strength-meter__label strength--${info.cls}`;
    strengthScore.textContent = `${score}/100`;
    strengthScore.className = `strength-meter__score strength--${info.cls}`;
  }

  // Stats
  statLenVal.textContent = pw.length;
  statEntVal.textContent = entropy.toFixed(1);
  statCharVal.textContent = charset;
  statCrackVal.textContent = crackTime;

  // Criteria
  updateCriteria('length',   pw.length >= 8);
  updateCriteria('upper',    /[A-Z]/.test(pw));
  updateCriteria('lower',    /[a-z]/.test(pw));
  updateCriteria('digit',    /[0-9]/.test(pw));
  updateCriteria('special',  /[^a-zA-Z0-9]/.test(pw));
  updateCriteria('noRepeat', pw.length === 0 ? false : !hasRepeatedSequences(pw));
  updateCriteria('noCommon', pw.length === 0 ? false : !isCommonPassword(pw));

  // Suggestions
  const tips = getSuggestions(pw);
  if (tips.length === 0 && pw.length === 0) {
    suggestionsList.innerHTML = '<p class="suggestions-panel__empty">Enter a password to get personalized tips.</p>';
  } else if (tips.length === 0) {
    suggestionsList.innerHTML = '<p class="suggestions-panel__empty" style="color:var(--accent-green);">✓ No issues detected — well done!</p>';
  } else {
    suggestionsList.innerHTML = tips.map(t =>
      `<div class="suggestion-item"><span class="suggestion-item__icon">⚠</span><span>${t}</span></div>`
    ).join('');
  }

  // Reset breach
  breachResult.style.display = 'none';
}

function updateCriteria(key, pass) {
  const c = criteriaChecks[key];
  c.el.textContent = pass ? '✓' : '✗';
  c.el.className = `criteria__check ${pass ? 'criteria__check--pass' : ''}`;
  c.item.className = `criteria__item ${pass ? 'criteria__item--pass' : ''}`;
}

// ─── Input Handler ────────────────────────────────────────────
let debounceTimer;
passwordInput.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    updateUI(passwordInput.value);
  }, 50);
});

// ─── Generate Strong Passwords ────────────────────────────────
const CHARSET_ALL = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_+-=~';

function generatePassword(length = 18) {
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let pw = '';
  for (let i = 0; i < length; i++) {
    pw += CHARSET_ALL[arr[i] % CHARSET_ALL.length];
  }
  // Ensure at least one of each type
  const ensure = [
    { regex: /[a-z]/, pool: 'abcdefghijklmnopqrstuvwxyz' },
    { regex: /[A-Z]/, pool: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' },
    { regex: /[0-9]/, pool: '0123456789' },
    { regex: /[^a-zA-Z0-9]/, pool: '!@#$%^&*_+-=~' },
  ];
  for (const e of ensure) {
    if (!e.regex.test(pw)) {
      const pos = crypto.getRandomValues(new Uint32Array(1))[0] % pw.length;
      const ch = e.pool[crypto.getRandomValues(new Uint32Array(1))[0] % e.pool.length];
      pw = pw.slice(0, pos) + ch + pw.slice(pos + 1);
    }
  }
  return pw;
}

function renderGeneratedPasswords() {
  generatedList.innerHTML = '';
  for (let i = 0; i < 3; i++) {
    const pw = generatePassword(20);
    const div = document.createElement('div');
    div.className = 'gen-pw';
    div.innerHTML = `
      <span class="gen-pw__text">${escapeHtml(pw)}</span>
      <button class="gen-pw__copy" data-pw="${escapeHtml(pw)}">COPY</button>
    `;
    generatedList.appendChild(div);
  }
  // Attach copy handlers
  generatedList.querySelectorAll('.gen-pw__copy').forEach(btn => {
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.pw);
        btn.textContent = 'COPIED!';
        btn.classList.add('gen-pw__copy--copied');
        setTimeout(() => {
          btn.textContent = 'COPY';
          btn.classList.remove('gen-pw__copy--copied');
        }, 1500);
      } catch {
        btn.textContent = 'FAILED';
      }
    });
  });
}

refreshBtn.addEventListener('click', renderGeneratedPasswords);
renderGeneratedPasswords(); // initial

// ─── Have I Been Pwned (k-Anonymity) ─────────────────────────
breachBtn.addEventListener('click', async () => {
  const pw = passwordInput.value;
  if (!pw) {
    passwordInput.focus();
    passwordInput.parentElement.classList.add('shake');
    setTimeout(() => passwordInput.parentElement.classList.remove('shake'), 400);
    return;
  }

  breachBtn.disabled = true;
  breachBtn.innerHTML = '<span class="spinner"></span> Checking...';
  breachResult.style.display = 'none';

  try {
    // SHA-1 hash the password
    const encoder = new TextEncoder();
    const data = encoder.encode(pw);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }
    });

    if (!response.ok) throw new Error(`API returned ${response.status}`);

    const text = await response.text();
    const lines = text.split('\n');
    let count = 0;
    for (const line of lines) {
      const [hashSuffix, cnt] = line.trim().split(':');
      if (hashSuffix === suffix) {
        count = parseInt(cnt, 10);
        break;
      }
    }

    breachResult.style.display = 'block';
    if (count > 0) {
      breachResult.className = 'breach-section__result breach-section__result--breached';
      breachResult.innerHTML = `⚠️ <strong>Breached!</strong> This password has appeared in <strong>${count.toLocaleString()}</strong> known data breaches. Do NOT use it.`;
    } else {
      breachResult.className = 'breach-section__result breach-section__result--safe';
      breachResult.innerHTML = `✅ <strong>No breaches found.</strong> This password hasn't appeared in known data breaches. Stay vigilant!`;
    }

    // Save to history
    saveToHistory(pw, computeStrengthScore(pw));

  } catch (err) {
    breachResult.style.display = 'block';
    breachResult.className = 'breach-section__result breach-section__result--error';
    breachResult.innerHTML = `⚠️ Could not check breach database: ${escapeHtml(err.message)}. Your password was NOT sent — only a partial hash prefix was transmitted.`;
  } finally {
    breachBtn.disabled = false;
    breachBtn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      Check Breach Exposure (via Have I Been Pwned)
    `;
  }
});

// ─── Password History (Local Storage) ─────────────────────────
function maskPassword(pw) {
  if (pw.length <= 3) return '***';
  return pw.slice(0, 2) + '*'.repeat(pw.length - 3) + pw.slice(-1);
}

function saveToHistory(pw, score) {
  const entry = {
    masked: maskPassword(pw),
    score,
    strength: getStrengthInfo(score).label,
    cls: getStrengthInfo(score).cls,
    date: new Date().toISOString(),
  };
  // Prevent duplicate consecutive
  if (passwordHistory.length > 0 && passwordHistory[0].masked === entry.masked) return;
  passwordHistory.unshift(entry);
  if (passwordHistory.length > 50) passwordHistory.pop();
  localStorage.setItem('cyguard_history', JSON.stringify(passwordHistory));
}

function renderHistory() {
  if (passwordHistory.length === 0) {
    historyList.innerHTML = '<p class="history-section__empty">No passwords analyzed yet.</p>';
    return;
  }
  historyList.innerHTML = passwordHistory.map((h, i) => `
    <div class="history-item">
      <span class="history-item__strength history-item__strength--${h.cls}"></span>
      <span class="history-item__pw">${escapeHtml(h.masked)}</span>
      <div class="history-item__meta">
        <span class="history-item__label strength--${h.cls}">${h.strength} (${h.score})</span>
        <span class="history-item__date">${new Date(h.date).toLocaleString()}</span>
      </div>
      <button class="history-item__delete" data-idx="${i}" title="Remove">✕</button>
    </div>
  `).join('');

  historyList.querySelectorAll('.history-item__delete').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx);
      passwordHistory.splice(idx, 1);
      localStorage.setItem('cyguard_history', JSON.stringify(passwordHistory));
      renderHistory();
    });
  });
}

clearHistoryBtn.addEventListener('click', () => {
  passwordHistory = [];
  localStorage.removeItem('cyguard_history');
  renderHistory();
});

// Also save to history on significant analysis (when user pauses typing)
let historyDebounce;
passwordInput.addEventListener('input', () => {
  clearTimeout(historyDebounce);
  historyDebounce = setTimeout(() => {
    const pw = passwordInput.value;
    if (pw.length >= 4) {
      saveToHistory(pw, computeStrengthScore(pw));
    }
  }, 2000);
});

// ─── Utilities ────────────────────────────────────────────────
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ─── Initialize ───────────────────────────────────────────────
updateUI('');
