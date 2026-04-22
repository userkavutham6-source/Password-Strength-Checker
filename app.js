/* ═══════════════════════════════════════════
   PassGuard — Password Strength Checker
   Pure-frontend application logic
   ═══════════════════════════════════════════ */

(() => {
  'use strict';

  // ── Common / Weak Passwords List ──
  const COMMON_PASSWORDS = new Set([
    'password','123456','12345678','qwerty','abc123','monkey','1234567',
    'letmein','trustno1','dragon','baseball','iloveyou','master','sunshine',
    'ashley','bailey','passw0rd','shadow','123123','654321','superman',
    'qazwsx','michael','football','password1','password123','welcome',
    'jesus','ninja','mustang','password2','123456789','12345','1234567890',
    '0987654321','admin','login','princess','starwars','solo','qwerty123',
    '1q2w3e4r','1qaz2wsx','zaq1xsw2','!qaz2wsx','passwd','pass123',
    'admin123','root','toor','changeme','test','guest','info','default',
    'hello','charlie','donald','access','freedom','whatever','qwerty1',
    '1234','123','111111','000000','121212','666666','696969','7777777',
    'aa123456','password!','p@ssw0rd','p@$$w0rd','pass@123','test123',
    'abcdef','abcdefg','abc1234','computer','tigger','thomas','george',
    'amanda','jennifer','jessica','pepper','ginger','hunter','buster',
    'joshua','maggie','jessica1','summer','hannah','bandit','samantha',
  ]);

  const KEYBOARD_PATTERNS = [
    'qwerty','qwertz','azerty','asdfgh','zxcvbn','qazwsx','!@#$%^','1qaz2wsx',
    'poiuyt','lkjhgf','mnbvcx','0987654321',
  ];

  const SEQUENTIAL_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789';

  // ── DOM References ──
  const dom = {
    passwordInput:    document.getElementById('password-input'),
    toggleVisibility: document.getElementById('toggle-visibility'),
    iconEye:          document.getElementById('icon-eye'),
    iconEyeOff:       document.getElementById('icon-eye-off'),
    strengthFill:     document.getElementById('strength-fill'),
    strengthLabel:    document.getElementById('strength-label'),
    strengthScore:    document.getElementById('strength-score'),
    crackTimeContainer: document.getElementById('crack-time-container'),
    crackTimeValue:   document.getElementById('crack-time-value'),
    entropyContainer: document.getElementById('entropy-container'),
    entropyValue:     document.getElementById('entropy-value'),
    checklist: {
      length:  document.getElementById('chk-length'),
      upper:   document.getElementById('chk-upper'),
      lower:   document.getElementById('chk-lower'),
      number:  document.getElementById('chk-number'),
      special: document.getElementById('chk-special'),
    },
    commonWarning:    document.getElementById('common-warning'),
    suggestionsContainer: document.getElementById('suggestions-container'),
    suggestionsList:  document.getElementById('suggestions-list'),
    // Generator
    generatedPassword: document.getElementById('generated-password'),
    copyBtn:           document.getElementById('copy-btn'),
    genLength:         document.getElementById('gen-length'),
    genLengthVal:      document.getElementById('gen-length-val'),
    genUpper:          document.getElementById('gen-upper'),
    genLower:          document.getElementById('gen-lower'),
    genNumbers:        document.getElementById('gen-numbers'),
    genSymbols:        document.getElementById('gen-symbols'),
    generateBtn:       document.getElementById('generate-btn'),
    useGeneratedBtn:   document.getElementById('use-generated-btn'),
    // Nav
    mobileMenuBtn:     document.getElementById('mobile-menu-btn'),
  };

  // ═══════════════════════════════════════
  //  Entropy & Strength Calculation
  // ═══════════════════════════════════════

  /**
   * Calculate the character-pool size based on what categories
   * are present in the password.
   */
  function getPoolSize(password) {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 33; // common special chars
    return pool;
  }

  /**
   * Detect patterns that reduce effective entropy.
   * Returns a penalty factor (0–1) to multiply against raw entropy.
   */
  function patternPenalty(password) {
    const lower = password.toLowerCase();
    let penalty = 1;

    // Repeated characters (e.g., "aaa")
    const repeats = (lower.match(/(.)\1{2,}/g) || []).length;
    if (repeats > 0) penalty *= Math.max(0.5, 1 - repeats * 0.12);

    // Sequential characters (e.g., "abc", "123")
    let seqCount = 0;
    for (let i = 0; i < lower.length - 2; i++) {
      const idx = SEQUENTIAL_CHARS.indexOf(lower[i]);
      if (idx !== -1 &&
          lower[i + 1] === SEQUENTIAL_CHARS[idx + 1] &&
          lower[i + 2] === SEQUENTIAL_CHARS[idx + 2]) {
        seqCount++;
      }
    }
    if (seqCount > 0) penalty *= Math.max(0.5, 1 - seqCount * 0.1);

    // Keyboard patterns
    for (const pat of KEYBOARD_PATTERNS) {
      if (lower.includes(pat)) { penalty *= 0.5; break; }
    }

    return penalty;
  }

  /**
   * Calculate entropy in bits, adjusted for patterns.
   */
  function calculateEntropy(password) {
    if (!password) return 0;
    const pool = getPoolSize(password);
    if (pool === 0) return 0;
    const rawEntropy = password.length * Math.log2(pool);
    return rawEntropy * patternPenalty(password);
  }

  /**
   * Map entropy to strength level.
   */
  function getStrengthLevel(entropy, password) {
    if (COMMON_PASSWORDS.has(password.toLowerCase())) return { level: 'weak', label: 'Weak', pct: 8 };
    if (entropy < 28) return { level: 'weak',        label: 'Weak',        pct: Math.max(5, (entropy / 28) * 25) };
    if (entropy < 50) return { level: 'medium',      label: 'Medium',      pct: 25 + ((entropy - 28) / 22) * 25 };
    if (entropy < 70) return { level: 'strong',      label: 'Strong',      pct: 50 + ((entropy - 50) / 20) * 25 };
    return { level: 'very-strong', label: 'Very Strong', pct: 75 + Math.min(25, ((entropy - 70) / 50) * 25) };
  }

  // ═══════════════════════════════════════
  //  Crack-Time Estimation
  // ═══════════════════════════════════════

  /**
   * Estimate brute-force crack time at 10 billion guesses/second.
   */
  function estimateCrackTime(entropy) {
    if (entropy <= 0) return 'Instant';
    const GUESSES_PER_SEC = 1e10;
    const totalGuesses = Math.pow(2, entropy);
    let seconds = totalGuesses / GUESSES_PER_SEC;

    if (seconds < 0.001) return 'Instant';
    if (seconds < 1)     return 'Less than a second';
    if (seconds < 60)    return `${Math.round(seconds)} second${seconds >= 2 ? 's' : ''}`;
    let minutes = seconds / 60;
    if (minutes < 60)    return `${Math.round(minutes)} minute${minutes >= 2 ? 's' : ''}`;
    let hours = minutes / 60;
    if (hours < 24)      return `${Math.round(hours)} hour${hours >= 2 ? 's' : ''}`;
    let days = hours / 24;
    if (days < 365)      return `${Math.round(days)} day${days >= 2 ? 's' : ''}`;
    let years = days / 365.25;
    if (years < 1e3)     return `~${Math.round(years)} year${years >= 2 ? 's' : ''}`;
    if (years < 1e6)     return `~${(years / 1e3).toFixed(1)} thousand years`;
    if (years < 1e9)     return `~${(years / 1e6).toFixed(1)} million years`;
    if (years < 1e12)    return `~${(years / 1e9).toFixed(1)} billion years`;
    if (years < 1e15)    return `~${(years / 1e12).toFixed(1)} trillion years`;
    return 'Centuries+';
  }

  // ═══════════════════════════════════════
  //  Suggestions Engine
  // ═══════════════════════════════════════

  function generateSuggestions(password, checks) {
    const suggestions = [];
    if (!checks.length)  suggestions.push('Make your password at least 8 characters long.');
    if (!checks.upper)   suggestions.push('Add uppercase letters (A–Z) for a larger character pool.');
    if (!checks.lower)   suggestions.push('Include lowercase letters (a–z).');
    if (!checks.number)  suggestions.push('Mix in numbers (0–9) to increase entropy.');
    if (!checks.special) suggestions.push('Use special characters like !@#$%^&* for more complexity.');

    if (password.length >= 8 && password.length < 14) {
      suggestions.push('Consider using 14+ characters — length is the biggest entropy multiplier.');
    }

    const lower = password.toLowerCase();
    if (COMMON_PASSWORDS.has(lower)) {
      suggestions.push('This is a commonly breached password — choose something unique.');
    }
    if (/(.)\1{2,}/.test(lower)) {
      suggestions.push('Avoid repeating the same character multiple times in a row.');
    }
    for (const pat of KEYBOARD_PATTERNS) {
      if (lower.includes(pat)) {
        suggestions.push('Avoid common keyboard patterns like "qwerty" or "asdfgh".');
        break;
      }
    }

    if (password.length >= 14 && suggestions.length === 0) {
      suggestions.push('Great job! Consider using a passphrase for even better memorability.');
    }

    return suggestions;
  }

  // ═══════════════════════════════════════
  //  Real-Time Analysis (main handler)
  // ═══════════════════════════════════════

  function analyzePassword() {
    const pw = dom.passwordInput.value;

    // Reset if empty
    if (!pw) {
      dom.strengthFill.style.width = '0';
      dom.strengthFill.className = 'strength-fill';
      dom.strengthLabel.textContent = 'Enter a password';
      dom.strengthScore.textContent = '';
      dom.crackTimeContainer.classList.remove('visible');
      dom.entropyContainer.classList.remove('visible');
      dom.commonWarning.classList.remove('visible');
      dom.suggestionsContainer.classList.remove('visible');
      Object.values(dom.checklist).forEach(el => el.setAttribute('data-met', 'false'));
      return;
    }

    // Checklist
    const checks = {
      length:  pw.length >= 8,
      upper:   /[A-Z]/.test(pw),
      lower:   /[a-z]/.test(pw),
      number:  /[0-9]/.test(pw),
      special: /[^a-zA-Z0-9]/.test(pw),
    };
    for (const [key, met] of Object.entries(checks)) {
      dom.checklist[key].setAttribute('data-met', String(met));
    }

    // Entropy
    const entropy = calculateEntropy(pw);
    dom.entropyContainer.classList.add('visible');
    dom.entropyValue.textContent = `${entropy.toFixed(1)} bits`;

    // Strength
    const strength = getStrengthLevel(entropy, pw);
    dom.strengthFill.style.width = `${strength.pct}%`;
    dom.strengthFill.className = `strength-fill ${strength.level}`;
    dom.strengthLabel.textContent = strength.label;
    dom.strengthScore.textContent = `${Math.round(strength.pct)}%`;

    // Colour the label
    const colorMap = { weak: 'var(--str-weak)', medium: 'var(--str-medium)', strong: 'var(--str-strong)', 'very-strong': 'var(--str-very-strong)' };
    dom.strengthLabel.style.color = colorMap[strength.level];

    // Crack time
    const isCommon = COMMON_PASSWORDS.has(pw.toLowerCase());
    dom.crackTimeContainer.classList.add('visible');
    dom.crackTimeValue.textContent = isCommon ? 'Instant (common password)' : estimateCrackTime(entropy);

    // Common warning
    if (isCommon) {
      dom.commonWarning.classList.add('visible');
    } else {
      dom.commonWarning.classList.remove('visible');
    }

    // Suggestions
    const suggestions = generateSuggestions(pw, checks);
    if (suggestions.length > 0) {
      dom.suggestionsContainer.classList.add('visible');
      dom.suggestionsList.innerHTML = suggestions.map(s => `<li>${s}</li>`).join('');
    } else {
      dom.suggestionsContainer.classList.remove('visible');
    }
  }

  // ═══════════════════════════════════════
  //  Password Generator
  // ═══════════════════════════════════════

  const CHAR_SETS = {
    upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower:   'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  };

  function generatePassword() {
    const length = parseInt(dom.genLength.value, 10);
    const useUpper   = dom.genUpper.checked;
    const useLower   = dom.genLower.checked;
    const useNumbers = dom.genNumbers.checked;
    const useSymbols = dom.genSymbols.checked;

    let chars = '';
    const guaranteed = [];

    if (useUpper)   { chars += CHAR_SETS.upper;   guaranteed.push(CHAR_SETS.upper); }
    if (useLower)   { chars += CHAR_SETS.lower;   guaranteed.push(CHAR_SETS.lower); }
    if (useNumbers) { chars += CHAR_SETS.numbers;  guaranteed.push(CHAR_SETS.numbers); }
    if (useSymbols) { chars += CHAR_SETS.symbols;  guaranteed.push(CHAR_SETS.symbols); }

    if (!chars) { chars = CHAR_SETS.lower; guaranteed.push(CHAR_SETS.lower); }

    // Use crypto.getRandomValues for true randomness
    const randomArray = new Uint32Array(length);
    crypto.getRandomValues(randomArray);

    let result = [];
    // Guarantee at least one char from each selected set
    for (const set of guaranteed) {
      const rIdx = crypto.getRandomValues(new Uint32Array(1))[0] % set.length;
      result.push(set[rIdx]);
    }
    // Fill remaining
    for (let i = result.length; i < length; i++) {
      result.push(chars[randomArray[i] % chars.length]);
    }

    // Shuffle (Fisher-Yates)
    for (let i = result.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }

    dom.generatedPassword.value = result.join('');
  }

  // ═══════════════════════════════════════
  //  Copy to Clipboard
  // ═══════════════════════════════════════

  async function copyToClipboard() {
    const text = dom.generatedPassword.value;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      showCopyFeedback();
    } catch {
      // Fallback
      dom.generatedPassword.select();
      document.execCommand('copy');
      showCopyFeedback();
    }
  }

  function showCopyFeedback() {
    dom.copyBtn.style.color = 'var(--neon-green)';
    setTimeout(() => { dom.copyBtn.style.color = ''; }, 1200);
  }

  // ═══════════════════════════════════════
  //  Stat Counter Animation
  // ═══════════════════════════════════════

  function animateCounters() {
    document.querySelectorAll('.stat-number').forEach(el => {
      const target = parseInt(el.dataset.target, 10);
      const duration = 1600;
      const start = performance.now();
      function step(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(eased * target);
        if (progress < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    });
  }

  // ═══════════════════════════════════════
  //  Scroll Reveal (Intersection Observer)
  // ═══════════════════════════════════════

  function initScrollReveal() {
    const revealTargets = document.querySelectorAll('.info-card, .stat-card, .tip-card, .timeline-item');
    let countersAnimated = false;

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry, i) => {
        if (entry.isIntersecting) {
          // Stagger the reveal
          setTimeout(() => entry.target.classList.add('revealed'), i * 80);
          observer.unobserve(entry.target);

          // Animate stat counters when first stat card appears
          if (!countersAnimated && entry.target.classList.contains('stat-card')) {
            countersAnimated = true;
            animateCounters();
          }
        }
      });
    }, { threshold: 0.15 });

    revealTargets.forEach(el => observer.observe(el));
  }

  // ═══════════════════════════════════════
  //  Toggle Password Visibility
  // ═══════════════════════════════════════

  function togglePasswordVisibility() {
    const isPassword = dom.passwordInput.type === 'password';
    dom.passwordInput.type = isPassword ? 'text' : 'password';
    dom.iconEye.classList.toggle('hidden', !isPassword);
    dom.iconEyeOff.classList.toggle('hidden', isPassword);
    dom.toggleVisibility.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
  }

  // ═══════════════════════════════════════
  //  Mobile Menu
  // ═══════════════════════════════════════

  function toggleMobileMenu() {
    const navLinks = document.querySelector('.nav-links');
    const isOpen = navLinks.classList.toggle('open');
    dom.mobileMenuBtn.classList.toggle('open', isOpen);
    dom.mobileMenuBtn.setAttribute('aria-expanded', String(isOpen));
  }

  // ═══════════════════════════════════════
  //  Event Bindings
  // ═══════════════════════════════════════

  dom.passwordInput.addEventListener('input', analyzePassword);
  dom.toggleVisibility.addEventListener('click', togglePasswordVisibility);
  dom.mobileMenuBtn.addEventListener('click', toggleMobileMenu);

  // Close mobile menu on link click
  document.querySelectorAll('.nav-links a').forEach(link => {
    link.addEventListener('click', () => {
      document.querySelector('.nav-links').classList.remove('open');
      dom.mobileMenuBtn.classList.remove('open');
      dom.mobileMenuBtn.setAttribute('aria-expanded', 'false');
    });
  });

  // Generator
  dom.genLength.addEventListener('input', () => {
    dom.genLengthVal.textContent = dom.genLength.value;
  });
  dom.generateBtn.addEventListener('click', generatePassword);
  dom.copyBtn.addEventListener('click', copyToClipboard);
  dom.useGeneratedBtn.addEventListener('click', () => {
    if (dom.generatedPassword.value) {
      dom.passwordInput.value = dom.generatedPassword.value;
      dom.passwordInput.type = 'text';
      dom.iconEye.classList.add('hidden');
      dom.iconEyeOff.classList.remove('hidden');
      analyzePassword();
      dom.passwordInput.focus();
      // Scroll to checker
      document.getElementById('checker-card').scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  });

  // ═══════════════════════════════════════
  //  Init
  // ═══════════════════════════════════════

  initScrollReveal();
  generatePassword(); // Pre-generate one password

})();
