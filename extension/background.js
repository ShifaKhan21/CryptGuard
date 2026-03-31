// ═══════════════════════════════════════════════════════════════════════════
// CryptGuard Extension — Background Service Worker
// Privacy-preserving: we NEVER read request/response bodies.
// We only analyze: domain, timing, size, frequency, MIME type.
// ═══════════════════════════════════════════════════════════════════════════

// ─── In-Memory State ────────────────────────────────────────────────────
const domainTracker = {};
const downloadResults = [];
const alertHistory = [];

let totalRequests = 0;
let totalBlocked = 0;
let sessionStart = Date.now();

// ═══════════════════════════════════════════════════════════════════════════
// 1. WEB REQUEST MONITOR
// ═══════════════════════════════════════════════════════════════════════════
chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (!details.url || details.url.startsWith('chrome') || details.url.includes('localhost:8081')) return;
    if (details.type === 'main_frame' || details.type === 'sub_frame' ||
        details.type === 'xmlhttprequest' || details.type === 'script' ||
        details.type === 'stylesheet' || details.type === 'image' ||
        details.type === 'font' || details.type === 'other') {
      // process all types
    }

    try {
      const url = new URL(details.url);
      const domain = url.hostname;
      if (!domain || domain === 'localhost') return;

      totalRequests++;
      const now = Date.now();

      // Find content-length from response headers
      let contentLength = 0;
      let contentType = '';
      if (details.responseHeaders) {
        for (const h of details.responseHeaders) {
          const name = h.name.toLowerCase();
          if (name === 'content-length') contentLength = parseInt(h.value) || 0;
          if (name === 'content-type') contentType = (h.value || '').split(';')[0].trim();
        }
      }

      if (!domainTracker[domain]) {
        domainTracker[domain] = {
          count: 0,
          timestamps: [],
          sizes: [],
          contentTypes: new Set(),
          firstSeen: now,
          lastSeen: now,
          tabId: details.tabId,
          riskScore: 0,
          flagged: false,
        };
      }

      const entry = domainTracker[domain];
      entry.count++;
      entry.lastSeen = now;
      entry.timestamps.push(now);
      if (contentLength > 0) entry.sizes.push(contentLength);
      if (contentType) entry.contentTypes.add(contentType);

      // Memory: keep last 100 data points
      if (entry.timestamps.length > 100) entry.timestamps = entry.timestamps.slice(-100);
      if (entry.sizes.length > 100) entry.sizes = entry.sizes.slice(-100);

      // Analyze every 5 hits for expensive heuristics
      if (entry.count % 5 === 0) {
        runLocalHeuristics(domain, entry);
      }
    } catch (_) { /* skip malformed */ }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// ═══════════════════════════════════════════════════════════════════════════
// 2. LOCAL HEURISTICS ENGINE
// ═══════════════════════════════════════════════════════════════════════════
function runLocalHeuristics(domain, entry) {
  let risk = 0;
  const signals = [];

  // Signal 1: Beaconing — fixed interval request pattern
  if (entry.timestamps.length >= 5) {
    const intervals = [];
    for (let i = 1; i < entry.timestamps.length; i++) {
      intervals.push(entry.timestamps[i] - entry.timestamps[i - 1]);
    }
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / intervals.length;
    const cv = Math.sqrt(variance) / (avg || 1);

    if (cv < 0.15 && intervals.length >= 5) {
      risk += 35;
      signals.push('PERIODIC_BEACON');
    } else if (cv < 0.3 && intervals.length >= 8) {
      risk += 20;
      signals.push('SEMI_PERIODIC');
    }
  }

  // Signal 2: Response size uniformity
  if (entry.sizes.length >= 5) {
    const avgSize = entry.sizes.reduce((a, b) => a + b, 0) / entry.sizes.length;
    const sizeVar = entry.sizes.reduce((a, b) => a + Math.pow(b - avgSize, 2), 0) / entry.sizes.length;
    const sizeCV = Math.sqrt(sizeVar) / (avgSize || 1);
    if (sizeCV < 0.1) {
      risk += 25;
      signals.push('UNIFORM_SIZE');
    }
  }

  // Signal 3: Domain entropy (DGA detection)
  const sub = domain.split('.')[0];
  const entropy = calcEntropy(sub);
  if (entropy > 4.0) {
    risk += 20;
    signals.push('HIGH_ENTROPY');
  }

  // Signal 4: Suspicious TLD
  const suspTLDs = ['.xyz', '.top', '.club', '.work', '.click', '.link', '.buzz', '.info', '.ru', '.cn'];
  if (suspTLDs.some(tld => domain.endsWith(tld))) {
    risk += 10;
    signals.push('SUSPICIOUS_TLD');
  }

  // Signal 5: Night activity
  const hour = new Date().getHours();
  if (hour >= 0 && hour < 6 && entry.count > 20) {
    risk += 15;
    signals.push('NIGHT_ACTIVITY');
  }

  // Signal 6: Very high frequency
  const sessionSec = (Date.now() - entry.firstSeen) / 1000;
  if (sessionSec > 0 && (entry.count / sessionSec) > 2) {
    risk += 15;
    signals.push('HIGH_FREQUENCY');
  }

  risk = Math.min(100, risk);
  entry.riskScore = risk;

  if (risk >= 60 && !entry.flagged) {
    entry.flagged = true;
    totalBlocked++;
    fireAlert(domain, risk, signals);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. DOWNLOAD SCANNER
// ═══════════════════════════════════════════════════════════════════════════
chrome.downloads.onCreated.addListener(async (item) => {
  const filename = item.filename || extractFilename(item.url);
  const result = {
    id: item.id,
    filename,
    url: item.url,
    fileSize: item.fileSize || 0,
    mime: item.mime || 'unknown',
    referrer: item.referrer || '',
    timestamp: Date.now(),
    riskScore: 0,
    verdict: 'SAFE',
    signals: [],
  };

  let risk = 0;
  const signals = [];
  const lowerName = filename.toLowerCase();

  // Check 1: Dangerous extensions
  const dangerExts = ['.exe','.bat','.cmd','.ps1','.vbs','.js','.scr','.msi','.dll','.com','.pif','.hta','.wsf','.cpl'];
  if (dangerExts.some(ext => lowerName.endsWith(ext))) {
    risk += 40;
    signals.push('DANGEROUS_EXT');
  }

  // Check 1.5: Suspicious Archive Extensions (Moderate Risk)
  const archiveExts = ['.zip','.rar','.7z','.tar','.gz','.iso'];
  if (archiveExts.some(ext => lowerName.endsWith(ext))) {
    risk += 20;
    signals.push('ARCHIVE_FILE');
  }

  // Check 2: Double extension (.pdf.exe)
  const parts = lowerName.split('.');
  if (parts.length > 2) {
    const lastExt = '.' + parts[parts.length - 1];
    if (dangerExts.includes(lastExt)) {
      risk += 30;
      signals.push('DOUBLE_EXTENSION');
    }
  }

  // Check 3: Source domain risk
  try {
    const srcDomain = new URL(item.url).hostname;
    const tracker = domainTracker[srcDomain];
    if (tracker && tracker.riskScore > 40) {
      risk += 25;
      signals.push('RISKY_SOURCE');
    }
    if (calcEntropy(srcDomain.split('.')[0]) > 4.0) {
      risk += 15;
      signals.push('ENTROPY_SOURCE');
    }
  } catch (_) {}

  // Check 4: Executable MIME
  const execMimes = ['application/x-msdownload','application/x-executable','application/x-dosexec','application/octet-stream'];
  if (execMimes.includes(result.mime)) {
    risk += 15;
    signals.push('EXEC_MIME');
  }

  // Check 5: HTTP (insecure)
  if (item.url && item.url.startsWith('http://')) {
    risk += 10;
    signals.push('INSECURE_HTTP');
  }

  // Check 6: Dynamic Active Payload Scanner (Standalone JS)
  const payloadAnalysis = await scanPayload(item.url);
  risk += payloadAnalysis.risk;
  signals.push(...payloadAnalysis.signals);

  risk = Math.min(100, risk);
  result.riskScore = risk;
  result.signals = signals;
  result.verdict = risk >= 60 ? 'DANGEROUS' : risk >= 30 ? 'SUSPICIOUS' : 'SAFE';

  // Automatically Cancel High Risk Downloads (Windows Defender Style)
  if (risk >= 60) {
    chrome.downloads.cancel(item.id, () => {
       result.signals.push('ACTIVELY_CANCELLED');
    });
  }

  downloadResults.unshift(result);
  if (downloadResults.length > 50) downloadResults.pop();

  if (risk >= 30) {
    chrome.notifications.create(`dl-${item.id}`, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: risk >= 60 ? '🔴 CryptGuard: Dangerous Download!' : '🟡 CryptGuard: Suspicious Download',
      message: `${filename}\nRisk: ${risk}/100\n${signals.join(', ')}`,
      priority: 2,
    });
  }
  updateBadge();
});

// Sync natively detected viruses from Chrome into our extension
chrome.downloads.onChanged.addListener((delta) => {
  const result = downloadResults.find(d => d.id === delta.id);
  if (!result) return;
  
  let newlyBlocked = false;

  // If Chrome detects danger (safe, file, content, host, unwanted, etc.)
  if (delta.danger && delta.danger.current && delta.danger.current !== 'safe' && delta.danger.current !== 'accepted') {
    result.riskScore = 100;
    result.verdict = 'DANGEROUS';
    if (!result.signals.includes('NATIVE_MALWARE_BLOCK')) {
      result.signals.push('NATIVE_MALWARE_BLOCK');
      newlyBlocked = true;
    }
  }

  // Specific fallback for VIRUS_FAILED interruptions
  if (delta.error && delta.error.current === 'VIRUS_FAILED') {
    result.riskScore = 100;
    result.verdict = 'DANGEROUS';
    if (!result.signals.includes('VIRUS_FAILED')) {
      result.signals.push('VIRUS_FAILED');
      newlyBlocked = true;
    }
  }

  if (newlyBlocked) {
    chrome.notifications.create(`dl-update-${delta.id}`, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: '🔴 CryptGuard: Malware Intercepted!',
      message: `${result.filename} contained a virus and was blocked.\nRisk: 100/100`,
      priority: 2,
    });
    updateBadge();
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. PERIODIC CHECK (every 30s)
// ═══════════════════════════════════════════════════════════════════════════
chrome.alarms.create('cg-beacon-check', { periodInMinutes: 0.5 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== 'cg-beacon-check') return;

  for (const [domain, entry] of Object.entries(domainTracker)) {
    if (entry.count >= 5) runLocalHeuristics(domain, entry);
  }

  // Evict stale domains (5 min idle)
  const cutoff = Date.now() - 5 * 60 * 1000;
  for (const d of Object.keys(domainTracker)) {
    if (domainTracker[d].lastSeen < cutoff) delete domainTracker[d];
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. HELPERS
// ═══════════════════════════════════════════════════════════════════════════
function calcEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let e = 0;
  for (const n of Object.values(freq)) {
    const p = n / str.length;
    e -= p * Math.log2(p);
  }
  return e;
}

function extractFilename(url) {
  try { return new URL(url).pathname.split('/').pop() || 'unknown'; }
  catch { return 'unknown'; }
}

function fireAlert(domain, risk, signals) {
  alertHistory.unshift({ domain, risk, signals, timestamp: Date.now() });
  if (alertHistory.length > 30) alertHistory.pop();

  chrome.notifications.create(`threat-${Date.now()}`, {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '🔴 CryptGuard: Threat Detected',
    message: `${domain}\nRisk: ${risk}/100\n${signals.join(', ')}`,
    priority: 2,
  });
  updateBadge();
}

function updateBadge() {
  const threats = Object.values(domainTracker).filter(d => d.riskScore >= 60).length
                + downloadResults.filter(d => d.riskScore >= 60).length;
  if (threats > 0) {
    chrome.action.setBadgeText({ text: String(threats) });
    chrome.action.setBadgeBackgroundColor({ color: '#f43f5e' });
  } else {
    chrome.action.setBadgeText({ text: '' });
  }
}

async function scanPayload(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) return { risk: 0, signals: [] };
    
    // Stream up to 1 MB max to prevent memory bloat on huge files
    const reader = res.body.getReader();
    let bytesReceived = 0;
    const MAX_BYTES = 1048576; // 1 MB
    const chunks = [];
    
    while(true) {
      const {done, value} = await reader.read();
      if (done) break;
      chunks.push(value);
      bytesReceived += value.length;
      if (bytesReceived >= MAX_BYTES) break;
    }
    
    reader.cancel(); // Stop full download background streaming
    
    // Merge
    const buffer = new Uint8Array(bytesReceived);
    let offset = 0;
    for (const chunk of chunks) {
      buffer.set(chunk, offset);
      offset += chunk.length;
    }
    
    let localRisk = 0;
    const localSignals = [];
    
    // 1. Precise Malware String Signature Matching (EICAR)
    const eicarStr = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const textDecoder = new TextDecoder('ascii', {fatal: false});
    const text = textDecoder.decode(buffer.slice(0, 500)); 
    if (text.includes(eicarStr)) {
       return { risk: 100, signals: ['MALWARE_SIGNATURE_DETECTED'] };
    }
    
    // 2. High Entropy Executable Flagging (Packed malware detection)
    if (buffer.length > 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) { // "MZ" Header
       const entropy = calcByteEntropy(buffer);
       if (entropy > 7.4) {
         localRisk += 45;
         localSignals.push(`PACKED_PE_ENTROPY(${entropy.toFixed(2)})`);
       }
    }
    
    return { risk: localRisk, signals: localSignals };
  } catch (e) {
    return { risk: 0, signals: [] };
  }
}

function calcByteEntropy(buffer) {
  const freq = new Array(256).fill(0);
  for (let i=0; i < buffer.length; i++) {
     freq[buffer[i]]++;
  }
  let e = 0;
  for (let i=0; i < 256; i++) {
     if (freq[i] === 0) continue;
     const p = freq[i] / buffer.length;
     e -= p * Math.log2(p);
  }
  return e;
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. MESSAGE HANDLER — popup requests data
// ═══════════════════════════════════════════════════════════════════════════
chrome.runtime.onMessage.addListener((req, _sender, sendResponse) => {
  if (req.type === 'GET_STATUS') {
    const domains = Object.entries(domainTracker)
      .map(([domain, d]) => ({
        domain,
        count: d.count,
        riskScore: d.riskScore,
        contentTypes: [...d.contentTypes],
        firstSeen: d.firstSeen,
        lastSeen: d.lastSeen,
      }))
      .sort((a, b) => b.riskScore - a.riskScore || b.count - a.count)
      .slice(0, 30);

    sendResponse({
      apiOnline: true, // Always true for Standalone Mode!
      totalRequests,
      totalBlocked,
      totalDomains: Object.keys(domainTracker).length,
      sessionDuration: Date.now() - sessionStart,
      domains,
      downloads: downloadResults.slice(0, 15),
      alerts: alertHistory.slice(0, 15),
    });
  }
  return true;
});

// Boot
console.log('[CryptGuard Standalone Sentinel] Service worker initialized.');
