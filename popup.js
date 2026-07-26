// Global State
let currentTabInfo = {
  id: null,
  url: '',
  domain: '',
  ip: 'Fetching...',
  serverHeader: 'N/A',
  headers: [],
  pvi: [], // Passive Vulnerability Indicators
  ports: []
};

let extractedData = {
  emails: [],
  phones: [],
  internalLinks: [],
  externalLinks: [],
  technologies: []
};

// API Keys State
let apiKeys = {
  hunter: '',
  shodan: '',
  intelx: ''
};

// Feature toggles storage
let featureToggles = {
  enableSubdomains: false,
  enableSSL: false,
  enableTech: false,
  enableOSINT: false
};

// Tool Configuration
const OSINT_TOOLS = {
  dns: [
    { name: 'Whois (DomainTools)', getUrl: (d) => `https://whois.domaintools.com/${d}` },
    { name: 'DNS Dumpster', getUrl: (d) => `https://dnsdumpster.com/` },
    { name: 'BGPView (IP Data)', getUrl: (d, ip) => `https://bgpview.io/ip/${ip || d}` },
    { name: 'VirusTotal (Domain)', getUrl: (d) => `https://www.virustotal.com/gui/domain/${d}/detection` },
    { name: 'NSLookup.io', getUrl: (d) => `https://www.nslookup.io/domains/${d}/dns-records` },
    { name: 'DNSlytics', getUrl: (d) => `https://dnslytics.com/domain/${d}` },
    { name: 'Shodan (Domain)', getUrl: (d) => `https://www.shodan.io/domain/${d}` },
    { name: 'Shodan (IP)', getUrl: (d, ip) => `https://www.shodan.io/host/${ip || d}` },
    { name: 'Censys (IPv4)', getUrl: (d, ip) => `https://search.censys.io/hosts/${ip || d}` }
  ],
  subs: [
    { name: 'Subdomains (crt.sh)', getUrl: (d) => `https://crt.sh/?q=%25.${d}` },
    { name: 'Tech Stack (Wappalyzer)', getUrl: (d) => `https://www.wappalyzer.com/lookup/${d}/` },
    { name: 'History (Wayback)', getUrl: (d) => `https://web.archive.org/web/*/${d}` },
    { name: 'SecurityTrails', getUrl: (d) => `https://securitytrails.com/domain/${d}/dns` }
  ],
  social: [
    { name: 'Emails (Hunter.io)', getUrl: (d) => `https://hunter.io/search/${d}` },
    { name: 'Social Searcher', getUrl: (d) => `https://www.social-searcher.com/search/?q5=${d}` },
    // Spokeo blocks direct extension referrals. We open via a Google search to bypass 403.
    { name: 'Spokeo (People Search)', getUrl: (d) => `https://www.spokeo.com/search?q=${d}&t=16` },
    { name: 'Spokeo via Google', getUrl: (d) => `https://www.google.com/search?q=site:spokeo.com+%22${d}%22` },
    { name: 'RocketReach', getUrl: (d) => `https://rocketreach.co/search?query=${d}` },
    { name: 'Phonebook.cz', getUrl: (d) => `https://phonebook.cz/?s=${d}` }
  ],
  advanced: [
    { name: 'Pulsedive (IOC)', getUrl: (d) => `https://pulsedive.com/indicator/?iid=${d}` },
    { name: 'ThreatMiner (Pivot)', getUrl: (d) => `https://www.threatminer.org/domain.php?q=${d}` },
    { name: 'ThreatCrowd (Graph)', getUrl: (d) => `http://ci-www.threatcrowd.org/domain.php?domain=${d}` },
    { name: 'AlienVault OTX', getUrl: (d) => `https://otx.alienvault.com/indicator/domain/${d}` },
    { name: 'IntelX', getUrl: (d) => `https://intelx.io/?s=${d}` }
  ]
};

document.addEventListener('DOMContentLoaded', async () => {
  // Load API keys first
  loadApiKeys();
  // Load feature toggles
  chrome.storage.sync.get(['enableSubdomains','enableSSL','enableTech','enableOSINT'], (result) => {
    featureToggles = result;
  });
  initTabs();
  initExportListeners();
  loadApiKeys();

  document.getElementById('btn-save-keys').addEventListener('click', saveApiKeys);

  // Manual refresh button — triggers autoCapture
  document.getElementById('btn-refresh-headers').addEventListener('click', () => {
    if (!currentTabInfo.id) return;
    startAutoCapture(currentTabInfo.id);
  });

  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs || tabs.length === 0) return;

    const tab = tabs[0];
    currentTabInfo.id = tab.id;
    currentTabInfo.url = tab.url;

    try {
      const urlObj = new URL(tab.url);
      currentTabInfo.domain = urlObj.hostname;
    } catch (e) {
      currentTabInfo.domain = 'Invalid URL';
    }

    document.getElementById('current-url').textContent =
      currentTabInfo.url.substring(0, 50) + (currentTabInfo.url.length > 50 ? '...' : '');
    document.getElementById('info-domain').textContent = currentTabInfo.domain;
    document.getElementById('info-title').textContent = tab.title || 'N/A';

    if (currentTabInfo.domain !== 'Invalid URL') {
      // Always fetch DNS intelligence and subdomains
      fetchAdvancedRecon(currentTabInfo.domain);
      fetchDnsIntelligence(currentTabInfo.domain);
    }

    populateOSINTLinks();
    document.getElementById('btn-detach').addEventListener('click', detachWindow);

    // ── STEP 1: Try to get already-cached headers from background ──
    chrome.runtime.sendMessage({ action: "getTabData", tabId: tab.id }, async (cachedData) => {
      if (chrome.runtime.lastError) {
        console.warn('getTabData error:', chrome.runtime.lastError.message);
      }

      if (cachedData && cachedData.headers && cachedData.headers.length > 0) {
        // ✅ Headers already cached — display immediately
        processTabData(cachedData, tab);
      } else {
        // ❌ Not cached — auto-capture: reload tab in bg and wait for headers
        if (currentTabInfo.url.startsWith('http')) {
          startAutoCapture(tab.id, tab);
        } else {
          // Non-HTTP page (chrome://, etc.)
          document.getElementById('header-list').innerHTML =
            '<li class="status-warn">Security headers N/A for this page type.</li>';
          document.getElementById('tech-list').innerHTML =
            '<li class="status-warn">Cannot scan non-HTTP pages</li>';
          document.getElementById('pvi-list').innerHTML =
            '<li class="status-warn">N/A</li>';
          document.getElementById('info-ip').textContent = 'N/A';
        }
      }
    });

    // Always try Google DNS for IP (runs in parallel)
    if (currentTabInfo.domain && currentTabInfo.domain !== 'Invalid URL') {
      try {
        const dnsRes = await fetch(`https://dns.google/resolve?name=${currentTabInfo.domain}&type=A`);
        const dnsData = await dnsRes.json();
        if (dnsData && dnsData.Answer && dnsData.Answer.length > 0) {
          // Only update if IP is still unknown
          if (currentTabInfo.ip === 'Fetching...' || currentTabInfo.ip === 'N/A') {
            currentTabInfo.ip = dnsData.Answer[0].data;
            document.getElementById('info-ip').textContent = currentTabInfo.ip + ' (DNS)';
            populateOSINTLinks();
            fetchDirectApiData();
          }
        }
      } catch (e) {
        if (currentTabInfo.ip === 'Fetching...') {
          document.getElementById('info-ip').textContent = 'Unknown';
        }
      }
    }
  });

  document.getElementById('btn-copy-links').addEventListener('click', () => {
    if (extractedData.externalLinks.length > 0) {
      navigator.clipboard.writeText(extractedData.externalLinks.join('\n'))
        .then(() => alert('Copied ' + extractedData.externalLinks.length + ' external links to clipboard!'));
    }
  });
});

// ──────────────────────────────────────────────────────────────
// AUTO-CAPTURE FLOW
// Automatically reloads the tab, intercepts headers via webRequest,
// then re-runs all extraction. Fully hands-free after popup opens.
// ──────────────────────────────────────────────────────────────
function startAutoCapture(tabId, tab) {
  const list = document.getElementById('header-list');

  // Show animated status
  list.innerHTML = '<li class="loading">Auto-capturing headers — reloading page...</li>';

  let countdown = 8;
  const timer = setInterval(() => {
    countdown--;
    const li = list.querySelector('li');
    if (li) li.textContent = `Auto-capturing headers — please wait (${countdown}s)...`;
  }, 1000);

  chrome.runtime.sendMessage({ action: "autoCapture", tabId: tabId }, (result) => {
    clearInterval(timer);

    if (chrome.runtime.lastError) {
      console.warn('autoCapture error:', chrome.runtime.lastError.message);
      list.innerHTML = '<li class="status-warn">Auto-capture failed. Try the ⟳ Refresh button.</li>';
      return;
    }

    if (result && result.headers && result.headers.length > 0) {
      // ✅ Got headers automatically — process everything (includes content extraction now)
      processTabData(result, tab || { id: tabId });
    } else {
      list.innerHTML =
        '<li class="status-warn">Could not capture headers automatically. ' +
        'Click ⟳ Refresh to try again.</li>';
    }
  });
}

// ──────────────────────────────────────────────────────────────
// PROCESS TAB DATA (headers + IP)
// Called once we have valid data, either from cache or auto-capture
// ──────────────────────────────────────────────────────────────
function processTabData(data, tab) {
  // IP
  if (data.ip) {
    currentTabInfo.ip = data.ip;
    document.getElementById('info-ip').textContent = data.ip;
    populateOSINTLinks();
    fetchDirectApiData();
  }

  // Security Headers
  if (data.headers && data.headers.length > 0) {
    currentTabInfo.headers = data.headers;
    currentTabInfo.pvi = []; // Reset PVI before re-render
    renderSecurityHeaders(data.headers);
    // Run PVI engine immediately after headers are processed
    runPassiveVulnerabilityEngine();
  } else {
    document.getElementById('header-list').innerHTML =
      '<li class="status-warn">No headers received from server.</li>';
  }

  // Also run content extraction so technologies are detected
  if (tab && tab.id && currentTabInfo.url.startsWith('http')) {
    runContentExtraction(tab.id);
  }
}

// ──────────────────────────────────────────────────────────────
// CONTENT EXTRACTION
// Injects content.js and extracts emails, links, tech stack
// ──────────────────────────────────────────────────────────────
function runContentExtraction(tabId, retries = 5) {
  if (!currentTabInfo.url.startsWith('http')) return;

  const techList = document.getElementById('tech-list');

  // Only reset state on the first attempt
  if (retries === 5) {
    extractedData.emails = [];
    extractedData.technologies = [];
    techList.innerHTML = '<li class="loading">Scanning technologies (waiting for page)...</li>';
  }

  chrome.scripting.executeScript({
    target: { tabId: tabId },
    files: ['content.js']
  }).then(() => {
    // Small delay to ensure content.js listener is registered before we message it
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, { action: "extractData" }, (res) => {
        if (chrome.runtime.lastError) {
          console.warn('Content extraction message failed:', chrome.runtime.lastError.message);
          if (retries > 0) {
            setTimeout(() => runContentExtraction(tabId, retries - 1), 1500);
          } else {
            techList.innerHTML = '<li class="status-warn">Could not scan page content.</li>';
            runPassiveVulnerabilityEngine();
          }
          return;
        }
        if (res) {
          handleExtractedData(res);
          // Re-run PVI engine — merges header PVIs + DOM PVIs
          runPassiveVulnerabilityEngine();
        } else {
          techList.innerHTML = '<li class="status-warn">No response from page scanner.</li>';
          runPassiveVulnerabilityEngine();
        }
      });
    }, 350); // Allow content.js listener to register
  }).catch(err => {
    console.warn('Script execution failed:', err);
    if (err.message && err.message.includes('Cannot access')) {
      techList.innerHTML = '<li class="status-warn">Restricted page (cannot scan).</li>';
      runPassiveVulnerabilityEngine();
      return;
    }

    if (retries > 0) {
      setTimeout(() => runContentExtraction(tabId, retries - 1), 1500);
    } else {
      techList.innerHTML = '<li class="status-warn">Cannot scan this page type.</li>';
      runPassiveVulnerabilityEngine();
    }
  });
}


function detachWindow() {
  const width = 420;
  const height = 650;
  chrome.windows.create({
    url: chrome.runtime.getURL("popup.html"),
    type: "popup",
    width: width,
    height: height
  });
  window.close(); // Close the current popup
}

// Free fallback: ipwho.is gives ISP, Org, Location info without any key and supports HTTPS
async function fetchIpApiData(ip) {
  const ispSpan = document.getElementById('info-isp');
  const orgSpan = document.getElementById('info-org');
  const osSpan = document.getElementById('info-os');
  const locSpan = document.getElementById('info-location');

  try {
    const res = await fetch(`https://ipwho.is/${ip}`);
    if (!res.ok) return;
    const data = await res.json();
    if (!data.success) return;

    ispSpan.textContent = data.connection?.isp || 'N/A';
    orgSpan.textContent = data.connection?.org || 'N/A';
    // ipwho.is does not return OS — mark as not available
    if (osSpan.textContent === 'N/A' || osSpan.textContent === '') {
      osSpan.textContent = 'Not Available';
    }
    locSpan.textContent = (data.city && data.country) ? `${data.city}, ${data.country}` : (data.country || 'N/A');
  } catch (e) {
    console.warn('ipwho.is fetch failed:', e);
  }
}

async function fetchAdvancedRecon(domain) {
  const txtSpan = document.getElementById('info-dns-txt');
  const subCountSpan = document.getElementById('info-sub-count');
  const subDiv = document.getElementById('info-subdomains');

  // Extract base domain for better results on HackerTarget
  const parts = domain.split('.');
  let baseDomain = domain;
  if (parts.length > 2) {
    const secondLevel = parts[parts.length - 2];
    if (secondLevel.length <= 3 && parts.length >= 3) {
      baseDomain = parts.slice(-3).join('.');
    } else {
      baseDomain = parts.slice(-2).join('.');
    }
  }

  // 1. Fetch DNS TXT Records
  try {
    const dnsRes = await fetch(`https://dns.google/resolve?name=${baseDomain}&type=TXT`);
    if (dnsRes.ok) {
      const dnsData = await dnsRes.json();
      if (dnsData.Answer && dnsData.Answer.length > 0) {
        const txts = dnsData.Answer.map(a => a.data).join(', ');
        txtSpan.textContent = txts;
        currentTabInfo.dnsTxt = txts;
      } else {
        txtSpan.textContent = 'None Found';
        currentTabInfo.dnsTxt = 'None Found';
      }
    }
  } catch (e) {
    txtSpan.textContent = 'Failed to fetch';
    currentTabInfo.dnsTxt = 'Failed to fetch';
  }

  // Always fetch subdomains via HackerTarget (free, no key needed)
  try {
    subDiv.innerHTML = '<li style="color:#aaa;">Fetching subdomains...</li>';
    const htRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${baseDomain}`);
    if (htRes.ok) {
      const text = await htRes.text();
      if (text.includes('API count exceeded') || text.trim().startsWith('error')) {
        subDiv.textContent = 'HackerTarget API limit reached. Try again later.';
        subCountSpan.textContent = '0';
        currentTabInfo.subdomains = [];
      } else {
        const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
        currentTabInfo.subdomains = lines;
        subCountSpan.textContent = lines.length;
        if (lines.length > 0) {
          const formattedLines = lines.map(l => {
            const parts = l.split(',');
            if (parts.length === 2) {
              return `<li style="margin-bottom: 3px;"><strong>${parts[0]}</strong> <span style="color:#aaa;">(${parts[1]})</span></li>`;
            }
            return `<li>${l}</li>`;
          });
          subDiv.innerHTML = '<ul style="margin:0; padding-left:15px; list-style-type: square;">' + formattedLines.join('') + '</ul>';
        } else {
          subDiv.textContent = 'No subdomains found for this domain.';
        }
      }
    } else {
      subDiv.textContent = 'Failed to reach HackerTarget API.';
      currentTabInfo.subdomains = [];
    }
  } catch (e) {
    subDiv.textContent = 'Subdomain fetch failed.';
    currentTabInfo.subdomains = [];
  }
}

// ──────────────────────────────────────────────────────────────
// DNS INTELLIGENCE
// Fetches MX, NS, CNAME, AAAA records via Google DNS
// ──────────────────────────────────────────────────────────────
async function fetchDnsIntelligence(domain) {
  const mxEl = document.getElementById('dns-mx');
  const nsEl = document.getElementById('dns-ns');
  const cnameEl = document.getElementById('dns-cname');
  const aaaaEl = document.getElementById('dns-aaaa');
  const hintsEl = document.getElementById('dns-intel-hints');

  // Extract base domain for MX and NS records
  const parts = domain.split('.');
  let baseDomain = domain;
  if (parts.length > 2) {
    const secondLevel = parts[parts.length - 2];
    if (secondLevel.length <= 3 && parts.length >= 3) {
      baseDomain = parts.slice(-3).join('.');
    } else {
      baseDomain = parts.slice(-2).join('.');
    }
  }

  const queryDns = async (queryDomain, type) => {
    try {
      const res = await fetch(`https://dns.google/resolve?name=${queryDomain}&type=${type}`);
      if (!res.ok) return [];
      const data = await res.json();
      return (data.Answer || []).map(r => r.data);
    } catch (e) {
      return [];
    }
  };

  // MX Records (Apex Domain)
  const mx = await queryDns(baseDomain, 'MX');
  mxEl.textContent = mx.length > 0 ? mx.join(', ') : 'None found';

  // NS Records (Apex Domain)
  const ns = await queryDns(baseDomain, 'NS');
  nsEl.textContent = ns.length > 0 ? ns.join(', ') : 'None found';

  // CNAME Records (Exact Domain)
  const cname = await queryDns(domain, 'CNAME');
  cnameEl.textContent = cname.length > 0 ? cname.join(', ') : 'None';

  // AAAA (IPv6) Records
  const aaaa = await queryDns(domain, 'AAAA');
  aaaaEl.textContent = aaaa.length > 0 ? aaaa.join(', ') : 'None';

  // Expert hints
  const hints = [];
  if (mx.length > 0) {
    const mxStr = mx.join(' ').toLowerCase();
    if (mxStr.includes('google')) hints.push('✉️ Google Workspace mail detected.');
    else if (mxStr.includes('outlook') || mxStr.includes('microsoft')) hints.push('✉️ Microsoft 365 mail detected.');
    else if (mxStr.includes('proofpoint')) hints.push('🛡️ Proofpoint email filtering detected.');
    else if (mxStr.includes('mimecast')) hints.push('🛡️ Mimecast email filtering detected.');
  }
  if (cname.length > 0) {
    const cnameStr = cname.join(' ').toLowerCase();
    if (cnameStr.includes('cloudflare')) hints.push('☁️ Cloudflare CDN detected via CNAME.');
    if (cnameStr.includes('akamai')) hints.push('☁️ Akamai CDN detected via CNAME.');
    if (cnameStr.includes('github')) hints.push('🐙 GitHub Pages hosting detected.');
  }
  if (hints.length > 0) {
    hintsEl.style.display = 'block';
    hintsEl.innerHTML = hints.join('<br>');
  }
}

async function fetchShodanData(ip) {
  const portSpan = document.getElementById('info-ports');
  const ispSpan = document.getElementById('info-isp');
  const orgSpan = document.getElementById('info-org');
  const osSpan = document.getElementById('info-os');
  const locSpan = document.getElementById('info-location');

  if (!ip || ip === 'Fetching...' || ip === 'Unknown') {
    portSpan.textContent = 'IP unknown';
    return;
  }

  if (!apiKeys.shodan) {
    portSpan.textContent = 'Shodan Key required for ports';
    portSpan.className = 'status-warn';
    // Use free fallback for ISP/Org/Location
    fetchIpApiData(ip);
    return;
  }

  try {
    const res = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKeys.shodan}`);
    if (res.ok) {
      const data = await res.json();

      // Update ISP, Org, OS, Location from Shodan (most detailed)
      ispSpan.textContent = data.isp || 'N/A';
      orgSpan.textContent = data.org || 'N/A';
      osSpan.textContent = data.os || 'Not Detected';
      locSpan.textContent = (data.city && data.country_name) ? `${data.city}, ${data.country_name}` : (data.country_name || 'N/A');

      if (data && data.ports && data.ports.length > 0) {
        portSpan.innerHTML = '';
        data.ports.forEach(port => {
          const badge = document.createElement('span');
          badge.className = 'badge';
          badge.style.marginLeft = '4px';
          badge.style.display = 'inline-block';
          badge.textContent = port;
          portSpan.appendChild(badge);
        });
        currentTabInfo.ports = data.ports;
      } else {
        portSpan.textContent = 'No open ports found';
      }
    } else {
      if (res.status === 404) {
        portSpan.textContent = 'Host not found in Shodan';
        // Still try free fallback for basic ISP/Location info
        fetchIpApiData(ip);
      } else {
        portSpan.textContent = 'API Error (' + res.status + ')';
        portSpan.className = 'status-bad';
        // Fallback for any other error
        fetchIpApiData(ip);
      }
    }
  } catch (e) {
    portSpan.textContent = 'Fetch failed';
    portSpan.className = 'status-bad';
    console.error('Shodan fetch error:', e);
    // Try free fallback on error
    fetchIpApiData(ip);
  }
}

function switchTab(targetId) {
  const btns = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.tab-content');

  btns.forEach(b => b.classList.remove('active'));
  contents.forEach(c => c.classList.remove('active'));

  const activeBtn = Array.from(btns).find(b => b.getAttribute('data-target') === targetId);
  if (activeBtn) activeBtn.classList.add('active');

  const activeContent = document.getElementById(targetId);
  if (activeContent) activeContent.classList.add('active');

  // Render chart if report tab is opened and not rendered yet
  if (targetId === 'tab-report') {
    if (!window.chartRendered) {
      renderChart();
      window.chartRendered = true;
    }
    renderFullReportSummary();
  }
}

function initTabs() {
  const btns = document.querySelectorAll('.tab-btn');
  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.getAttribute('data-target'));
    });
  });

  // Global delegation for navigation shortcuts
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('jump-link')) {
      const target = e.target.getAttribute('data-jump');
      if (target) switchTab(target);
    }
  });
}

function populateOSINTLinks() {
  const d = currentTabInfo.domain;
  const ip = currentTabInfo.ip === 'Fetching...' ? '' : currentTabInfo.ip;

  if (!d || d === 'Invalid URL') return;

  const renderLinks = (containerId, toolArray) => {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';
    toolArray.forEach(tool => {
      if (!tool.name) return;
      const a = document.createElement('a');
      a.className = 'osint-link';
      a.href = tool.getUrl(d, ip);
      a.target = '_blank';
      a.rel = 'noopener';
      a.textContent = tool.name;
      container.appendChild(a);
    });
  };

  renderLinks('links-dns', OSINT_TOOLS.dns);
  renderLinks('links-subs', OSINT_TOOLS.subs);
  renderLinks('links-social', OSINT_TOOLS.social);
  renderLinks('links-advanced', OSINT_TOOLS.advanced);
}


// Stats for Chart

let headerStats = { present: 0, missing: 0 };

function renderSecurityHeaders(headers) {
  const secHeaders = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'x-xss-protection',
    'referrer-policy'
  ];

  const list = document.getElementById('header-list');
  list.innerHTML = '';

  const headerMap = {};
  headers.forEach(h => {
    headerMap[h.name.toLowerCase()] = h.value;
  });

  if (headerMap['server']) {
    currentTabInfo.serverHeader = headerMap['server'];
    document.getElementById('info-server-header').textContent = headerMap['server'];
    const helpSrv = document.getElementById('help-server');
    if (helpSrv) helpSrv.style.display = 'none';
  } else {
    currentTabInfo.serverHeader = 'N/A';
    document.getElementById('info-server-header').textContent = 'N/A';
    const helpSrv = document.getElementById('help-server');
    if (helpSrv) helpSrv.style.display = 'inline';
  }

  // Attempt to guess OS from Server header
  const osSpan = document.getElementById('info-os');
  const srvLower = currentTabInfo.serverHeader.toLowerCase();
  
  if (osSpan.textContent === 'N/A' || osSpan.textContent === 'Not Available' || osSpan.textContent.includes('Try Shodan')) {
    if (srvLower.includes('ubuntu')) osSpan.textContent = 'Ubuntu (Guessed)';
    else if (srvLower.includes('debian')) osSpan.textContent = 'Debian (Guessed)';
    else if (srvLower.includes('centos')) osSpan.textContent = 'CentOS (Guessed)';
    else if (srvLower.includes('red hat') || srvLower.includes('rhel')) osSpan.textContent = 'Red Hat (Guessed)';
    else if (srvLower.includes('windows') || srvLower.includes('iis')) osSpan.textContent = 'Windows (Guessed)';
    else if (srvLower.includes('freebsd')) osSpan.textContent = 'FreeBSD (Guessed)';
    else {
      osSpan.textContent = 'Not Available';
      const helpOs = document.getElementById('help-os');
      if (helpOs) helpOs.style.display = 'inline';
    }
  }

  headerStats = { present: 0, missing: 0 };

  secHeaders.forEach(sh => {
    const li = document.createElement('li');
    const nameSpan = document.createElement('span');
    nameSpan.textContent = sh;

    const valSpan = document.createElement('span');

    if (headerMap[sh]) {
      valSpan.textContent = 'PRESENT';
      valSpan.className = 'status-good';
      headerStats.present++;
    } else {
      valSpan.textContent = 'MISSING';
      valSpan.className = 'status-bad';
      headerStats.missing++;

      // Add missing security headers as Low/Medium PVI
      let severity = 'Low';
      let mitigation = 'Implement this header to improve security.';
      if (sh === 'strict-transport-security') {
        severity = 'Medium';
        mitigation = 'Enforce HTTPS by adding Strict-Transport-Security: max-age=31536000; includeSubDomains';
      }
      if (sh === 'content-security-policy') {
        severity = 'Medium';
        mitigation = 'Mitigate XSS attacks by implementing a strong Content-Security-Policy.';
      }
      if (sh === 'x-frame-options') {
        mitigation = 'Prevent clickjacking by adding X-Frame-Options: DENY or SAMEORIGIN.';
      }
      if (sh === 'x-content-type-options') {
        mitigation = 'Prevent MIME-sniffing by adding X-Content-Type-Options: nosniff.';
      }
      if (sh === 'referrer-policy') {
        mitigation = 'Protect user privacy with Referrer-Policy: strict-origin-when-cross-origin.';
      }
      currentTabInfo.pvi.push({ name: `Missing Header: ${sh}`, severity: severity, type: 'header', mitigation: mitigation });
    }

    li.appendChild(nameSpan);
    li.appendChild(valSpan);
    list.appendChild(li);
  });
}

// Returns a simple emoji/symbol icon for tech categories
function getTechIcon(techName) {
  const name = techName.toLowerCase();
  if (name.includes('wordpress') || name.includes('drupal') || name.includes('joomla') || name.includes('squarespace') || name.includes('wix') || name.includes('ghost') || name.includes('webflow')) return '🗂️';
  if (name.includes('shopify') || name.includes('magento') || name.includes('woocommerce') || name.includes('bigcommerce') || name.includes('prestashop')) return '🛒';
  if (name.includes('react') || name.includes('vue') || name.includes('angular') || name.includes('svelte') || name.includes('ember') || name.includes('backbone') || name.includes('alpine') || name.includes('htmx')) return '⚛️';
  if (name.includes('next') || name.includes('nuxt') || name.includes('gatsby') || name.includes('astro') || name.includes('remix') || name.includes('sveltekit')) return '🚀';
  if (name.includes('bootstrap') || name.includes('tailwind') || name.includes('bulma') || name.includes('foundation') || name.includes('materialize') || name.includes('semantic') || name.includes('mui') || name.includes('chakra')) return '🎨';
  if (name.includes('jquery') || name.includes('lodash') || name.includes('moment') || name.includes('axios') || name.includes('gsap') || name.includes('three') || name.includes('d3') || name.includes('chart') || name.includes('socket')) return '📦';
  if (name.includes('analytics') || name.includes('google tag') || name.includes('pixel') || name.includes('hotjar') || name.includes('intercom') || name.includes('segment') || name.includes('mixpanel') || name.includes('hubspot') || name.includes('heap')) return '📊';
  if (name.includes('cloudflare') || name.includes('fastly') || name.includes('akamai') || name.includes('cdn') || name.includes('jsdelivr') || name.includes('unpkg')) return '☁️';
  if (name.includes('stripe') || name.includes('paypal') || name.includes('braintree')) return '💳';
  if (name.includes('web3') || name.includes('crypto') || name.includes('ethereum') || name.includes('metamask')) return '🔗';
  if (name.includes('php') || name.includes('laravel') || name.includes('django') || name.includes('rails') || name.includes('asp.net') || name.includes('node') || name.includes('express')) return '⚙️';
  if (name.includes('generator:')) return '🏷️';
  return '🔧';
}

function handleExtractedData(data) {
  extractedData = data;
  if (!extractedData.phones) extractedData.phones = [];

  document.getElementById('email-count').textContent = data.emails.length;
  document.getElementById('extracted-emails').value = data.emails.length > 0 ? data.emails.join('\n') : '';

  // Render Phone Numbers
  const phoneList = document.getElementById('phone-list');
  const phoneCount = document.getElementById('phone-count');
  const phoneHints = document.getElementById('phone-osint-hints');
  phoneCount.textContent = extractedData.phones.length;
  phoneList.innerHTML = '';
  if (extractedData.phones.length > 0) {
    extractedData.phones.forEach(ph => {
      const li = document.createElement('li');
      li.style.display = 'flex';
      li.style.justifyContent = 'space-between';
      li.style.alignItems = 'center';
      li.style.gap = '5px';
      li.innerHTML = `<span style="color:#00ff41; font-family:monospace;">${ph}</span>
        <a href="https://www.truecaller.com/search/pk/${ph.replace(/[^0-9+]/g,'')}" target="_blank"
          style="font-size:9px;background:#1a1a1a;padding:2px 5px;border:1px solid #444;border-radius:3px;color:#ffcc00;text-decoration:none;">
          🔍 Lookup
        </a>`;
      phoneList.appendChild(li);
    });
    // Show OSINT hints for phones
    phoneHints.style.display = 'block';
    phoneHints.innerHTML = `<strong style="color:#00ffff;">💡 Expert Next Steps for Phone Numbers:</strong><br>
      • <a href="https://www.truecaller.com" target="_blank" style="color:#00ff41;">Truecaller</a> — Reverse lookup name & carrier<br>
      • <a href="https://www.numverify.com" target="_blank" style="color:#00ff41;">Numverify</a> — Validate line type (mobile/landline)<br>
      • Use phone to pivot on <a href="https://www.spokeo.com" target="_blank" style="color:#00ff41;">Spokeo</a> or <a href="https://www.whitepages.com" target="_blank" style="color:#00ff41;">Whitepages</a><br>
      • Search phone in breach databases — leaked credentials may be tied to it`;
  } else {
    phoneList.innerHTML = '<li class="status-muted">No phone numbers found on this page.</li>';
    phoneHints.style.display = 'none';
  }

  document.getElementById('internal-link-count').textContent = data.internalLinks.length;
  document.getElementById('external-link-count').textContent = data.externalLinks.length;

  const techList = document.getElementById('tech-list');
  techList.innerHTML = '';
  if (data.technologies && data.technologies.length > 0) {
    // Sort: generator entries last, others first
    const sorted = [...data.technologies].sort((a, b) => {
      const aGen = a.startsWith('Generator:');
      const bGen = b.startsWith('Generator:');
      if (aGen && !bGen) return 1;
      if (!aGen && bGen) return -1;
      return a.localeCompare(b);
    });
    sorted.forEach(tech => {
      const li = document.createElement('li');
      // Add a tech icon category indicator
      const icon = getTechIcon(tech);
      li.innerHTML = `<span class="tech-icon">${icon}</span><span>${tech}</span>`;
      li.className = 'status-good';
      li.style.display = 'flex';
      li.style.gap = '6px';
      li.style.alignItems = 'center';
      techList.appendChild(li);
    });
  } else {
    techList.innerHTML = '<li class="status-warn">No distinct technologies identified from page DOM.</li>';
  }
}

// PASSIVE VULNERABILITY ENGINE
function runPassiveVulnerabilityEngine() {
  const pviList = document.getElementById('pvi-list');
  pviList.innerHTML = '';

  // 1. Analyze Server Header
  const srv = currentTabInfo.serverHeader.toLowerCase();
  if (srv !== 'n/a') {
    if (srv.includes('apache/2.4.49') || srv.includes('apache/2.4.50')) {
      currentTabInfo.pvi.push({ name: 'Apache Path Traversal (CVE-2021-41773/42013) possible', severity: 'Critical', type: 'server', mitigation: 'Update Apache immediately to version 2.4.51 or later.' });
    }
    // Flag exposed exact versions as info/low leakage
    if (srv.match(/[0-9]+\.[0-9]+/)) {
      currentTabInfo.pvi.push({ name: 'Server Version Exposed', severity: 'Low', type: 'info_leak', mitigation: 'Configure the server to hide its version number to prevent targeted attacks.' });
    }
  }

  // 2. Analyze X-Powered-By
  const xpb = currentTabInfo.headers.find(h => h.name.toLowerCase() === 'x-powered-by');
  if (xpb) {
    currentTabInfo.pvi.push({ name: `Exposed Framework: ${xpb.value}`, severity: 'Low', type: 'info_leak', mitigation: 'Remove the X-Powered-By header to obscure the backend technology.' });
    if (xpb.value.toLowerCase().includes('php/5') || xpb.value.toLowerCase().includes('php/7.0') || xpb.value.toLowerCase().includes('php/7.1') || xpb.value.toLowerCase().includes('php/7.2') || xpb.value.toLowerCase().includes('php/7.3') || xpb.value.toLowerCase().includes('php/7.4')) {
      currentTabInfo.pvi.push({ name: `Outdated PHP Detected (${xpb.value})`, severity: 'High', type: 'outdated', mitigation: 'Upgrade to a supported version of PHP (8.1+) immediately.' });
    }
  }

  // 3. Extracted Data PVIs (from content.js - .env backups etc)
  if (extractedData.pvi && extractedData.pvi.length > 0) {
    currentTabInfo.pvi = currentTabInfo.pvi.concat(extractedData.pvi);
  }

  // Render PVI
  if (currentTabInfo.pvi.length === 0) {
    pviList.innerHTML = '<li class="status-good">No passive vulnerabilities detected.</li>';
  } else {
    // Sort critical first
    const severityOrder = { "Critical": 4, "High": 3, "Medium": 2, "Low": 1 };
    currentTabInfo.pvi.sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]);

    currentTabInfo.pvi.forEach(vuln => {
      const li = document.createElement('li');

      const titleSpan = document.createElement('span');
      titleSpan.textContent = vuln.name;

      const sevSpan = document.createElement('span');
      sevSpan.textContent = vuln.severity;

      if (vuln.severity === 'Critical') sevSpan.className = 'status-critical';
      else if (vuln.severity === 'High') sevSpan.className = 'status-bad';
      else if (vuln.severity === 'Medium') sevSpan.className = 'status-warn';
      else sevSpan.className = 'status-muted'; // Low

      li.appendChild(titleSpan);
      li.appendChild(sevSpan);
      pviList.appendChild(li);
    });
  }
}

function renderChart() {
  const chartCanvas = document.getElementById('headerChart');
  if (!chartCanvas) return;
  const ctx = chartCanvas.getContext('2d');

  if (window.myChart) {
    window.myChart.destroy();
  }

  window.myChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Present', 'Missing'],
      datasets: [{
        data: [headerStats.present, headerStats.missing],
        backgroundColor: ['#00ff41', '#ff003c'],
        borderWidth: 1,
        borderColor: '#1a1a1a'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#00ff41', font: { family: 'Courier New' } }
        }
      }
    }
  });
}

// EXPORT LOGIC
function initExportListeners() {
  document.getElementById('btn-export-json').addEventListener('click', exportJSON);
  document.getElementById('btn-export-csv').addEventListener('click', exportCSV);
  document.getElementById('btn-export-pdf').addEventListener('click', exportPDF);
}

function gatherReportData() {
  const isp = document.getElementById('info-isp').textContent;
  const org = document.getElementById('info-org').textContent;
  const os = document.getElementById('info-os').textContent;
  const loc = document.getElementById('info-location').textContent;

  return {
    domain: currentTabInfo.domain,
    url: currentTabInfo.url,
    ip: currentTabInfo.ip,
    server: currentTabInfo.serverHeader,
    isp: isp,
    org: org,
    os: os,
    location: loc,
    dnsTxt: currentTabInfo.dnsTxt || 'N/A',
    subdomains: currentTabInfo.subdomains || [],
    timestamp: new Date().toISOString(),
    pvi: currentTabInfo.pvi,
    ports: currentTabInfo.ports || [],
    technologies: extractedData.technologies,
    emails: extractedData.emails,
    phones: extractedData.phones || [],
    externalLinks: extractedData.externalLinks.length
  };
}

function renderFullReportSummary() {
  const container = document.getElementById('report-summary-content');
  if (!container) return;
  const data = gatherReportData();
  
  let html = `<p style="margin:0 0 5px 0"><strong>Target:</strong> <span style="color:#00ff41">${data.domain}</span> (${data.ip})</p>`;
  html += `<p style="margin:0 0 5px 0"><strong>Location:</strong> ${data.location} | <strong>ISP:</strong> ${data.isp}</p>`;
  html += `<p style="margin:0 0 10px 0"><strong>OS:</strong> ${data.os}</p>`;

  // PVIs
  html += `<h4 style="margin: 10px 0 5px 0; color: #ff003c; border-bottom: 1px solid #333; padding-bottom: 3px;">Vulnerabilities Found (${data.pvi.length})</h4>`;
  if (data.pvi.length > 0) {
    html += `<ul style="padding-left: 15px; margin: 0;">`;
    data.pvi.forEach(p => {
      let color = '#ccc';
      if (p.severity === 'Critical') color = '#ff003c';
      if (p.severity === 'High') color = '#ff8800';
      if (p.severity === 'Medium') color = '#ffcc00';
      html += `<li style="margin-bottom: 8px;"><strong style="color: ${color};">[${p.severity}]</strong> ${p.name}`;
      if (p.mitigation) {
        html += `<br><span style="color: #00ff41; font-size: 10px;">➔ Fix: ${p.mitigation}</span>`;
      }
      html += `</li>`;
    });
    html += `</ul>`;
  } else {
    html += `<p style="color: #00ff41; margin: 0;">No passive vulnerabilities detected.</p>`;
  }

  // Tech & OSINT
  html += `<h4 style="margin: 15px 0 5px 0; color: #00ff41; border-bottom: 1px solid #333; padding-bottom: 3px;">Data Gathered</h4>`;
  html += `<p style="margin:0 0 2px 0;"><strong>Technologies:</strong> ${data.technologies.length} detected</p>`;
  html += `<p style="margin:0 0 2px 0;"><strong>Emails:</strong> ${data.emails.length} found</p>`;
  html += `<p style="margin:0 0 2px 0;"><strong>Phone Numbers:</strong> ${data.phones.length} found</p>`;
  html += `<p style="margin:0 0 2px 0;"><strong>Subdomains:</strong> ${data.subdomains.length} discovered</p>`;
  html += `<p style="margin:0 0 10px 0;"><strong>External Links:</strong> ${data.externalLinks}</p>`;

  if (data.emails.length > 0) {
    html += `<h4 style="margin:10px 0 3px 0;color:#ffcc00;font-size:11px;">Extracted Emails</h4>`;
    html += `<p style="margin:0 0 5px 0;font-family:monospace;font-size:10px;color:#ccc;">${data.emails.join(', ')}</p>`;
  }
  if (data.phones.length > 0) {
    html += `<h4 style="margin:10px 0 3px 0;color:#ffcc00;font-size:11px;">Extracted Phone Numbers</h4>`;
    html += `<p style="margin:0 0 5px 0;font-family:monospace;font-size:10px;color:#00ff41;">${data.phones.join(' | ')}</p>`;
  }
  
  html += `<h4 style="margin: 10px 0 5px 0; color: #00ff41; border-bottom: 1px solid #333; padding-bottom: 3px;">DNS TXT Records</h4>`;
  html += `<p style="margin:0 0 10px 0; font-family: monospace; color: #ccc; word-wrap: break-word;">${data.dnsTxt}</p>`;

  // Next Steps (OSINT Hints)
  html += `<h4 style="margin: 10px 0 5px 0; color: #00ffff; border-bottom: 1px solid #333; padding-bottom: 3px;">Expert Next Steps</h4>`;
  html += `<ul style="padding-left: 15px; margin: 0; color: #ccc;">`;
  if (data.pvi.length > 0) html += `<li>Review and remediate the highlighted vulnerabilities above.</li>`;
  if (data.technologies.length > 0) html += `<li>Check <a href="https://www.exploit-db.com" target="_blank" style="color:#00ff41;">exploit-db.com</a> for CVEs related to detected technologies.</li>`;
  if (data.emails.length > 0) html += `<li>Search extracted emails on <a href="https://haveibeenpwned.com" target="_blank" style="color:#00ff41;">HaveIBeenPwned</a> & <a href="https://hunter.io" target="_blank" style="color:#00ff41;">Hunter.io</a> for OSINT pivoting.</li>`;
  if (data.phones.length > 0) html += `<li>Reverse-lookup phone numbers on <a href="https://www.truecaller.com" target="_blank" style="color:#00ff41;">Truecaller</a> & pivot on <a href="https://www.spokeo.com" target="_blank" style="color:#00ff41;">Spokeo</a> to find owner identity.</li>`;
  if (!apiKeys.shodan) html += `<li>Add a Shodan API key in Settings to scan open ports and identify running services automatically.</li>`;
  html += `<li>Use the OSINT Tools tab to enumerate subdomains and review historical snapshots via Wayback Machine.</li>`;
  html += `<li>Cross-check discovered subdomains against the IP list to find old/forgotten assets.</li>`;
  html += `</ul>`;

  container.innerHTML = html;
}

function triggerDownload(content, filename, type) {
  const blob = new Blob([content], { type: type });
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({
    url: url,
    filename: filename,
    saveAs: true
  });
}

function exportJSON() {
  const data = gatherReportData();
  triggerDownload(JSON.stringify(data, null, 2), `recon_${data.domain}.json`, 'application/json');
}

function exportCSV() {
  const data = gatherReportData();
  let csv = 'Category,Item,Detail\n';
  csv += `Target,Domain,"${data.domain}"\n`;
  csv += `Target,URL,"${data.url}"\n`;
  csv += `Target,IP,"${data.ip}"\n`;
  csv += `Target,Server,"${data.server}"\n`;
  csv += `Target,Location,"${data.location}"\n`;
  csv += `Target,ISP,"${data.isp}"\n`;
  csv += `Target,OS,"${data.os}"\n`;
  csv += `Recon,DNS TXT,"${data.dnsTxt}"\n`;

  data.pvi.forEach(p => {
    let detail = p.name;
    if (p.mitigation) detail += ` (Fix: ${p.mitigation})`;
    csv += `Vulnerability,${p.severity},"${detail}"\n`;
  });

  data.technologies.forEach(t => {
    csv += `Technology,Detected,"${t}"\n`;
  });

  data.emails.forEach(e => {
    csv += `Email,Found,${e}\n`;
  });

  data.phones.forEach(p => {
    csv += `Phone,Found,${p}\n`;
  });

  data.subdomains.forEach(s => {
    csv += `Subdomain,Discovered,"${s}"\n`;
  });

  csv += `Expert Hint,Next Step,"Review and remediate vulnerabilities."\n`;
  if (data.technologies.length > 0) csv += `Expert Hint,Next Step,"Check exploit-db.com for known CVEs related to technologies."\n`;
  if (data.emails.length > 0) csv += `Expert Hint,Next Step,"Search emails in breach databases (e.g., HaveIBeenPwned)."\n`;
  csv += `Expert Hint,Next Step,"Use OSINT Tools tab to discover subdomains and historical snapshots."\n`;

  triggerDownload(csv, `recon_${data.domain}.csv`, 'text/csv');
}

function exportPDF() {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const data = gatherReportData();

  // Header
  doc.setFont("courier", "bold");
  doc.setFontSize(20);
  doc.setTextColor(0, 255, 65); // Hacker green
  doc.text("Passive Recon .2 Report", 14, 20);

  doc.setFontSize(10);
  doc.setTextColor(100, 100, 100);
  doc.text(`Generated: ${data.timestamp}`, 14, 28);

  doc.autoTable({
    startY: 35,
    body: [
      ['Target Domain', data.domain, 'URL', data.url],
      ['IP Address', data.ip, 'Location', data.location],
      ['Server Header', data.server, 'OS (Guessed)', data.os],
      ['ISP', data.isp, 'DNS TXT', data.dnsTxt || 'N/A']
    ],
    theme: 'plain'
  });

  let currentY = doc.lastAutoTable.finalY + 10;

  // PVI Table
  if (data.pvi.length > 0) {
    doc.autoTable({
      startY: currentY,
      head: [['Severity', 'Vulnerability indicator', 'Mitigation']],
      body: data.pvi.map(p => [p.severity, p.name, p.mitigation || 'N/A']),
      theme: 'grid',
      headStyles: { fillColor: [13, 13, 13], textColor: [0, 255, 65] },
      didParseCell: function (data) {
        if (data.section === 'body' && data.column.index === 0) {
          if (data.cell.raw === 'Critical') data.cell.styles.textColor = [139, 0, 0];
          if (data.cell.raw === 'High') data.cell.styles.textColor = [255, 0, 60];
          if (data.cell.raw === 'Medium') data.cell.styles.textColor = [255, 184, 0];
        }
      }
    });
    currentY = doc.lastAutoTable.finalY + 10;
  }

  // Tech Map
  if (data.technologies.length > 0) {
    doc.autoTable({
      startY: currentY,
      head: [['Detected Technologies']],
      body: data.technologies.map(t => [t]),
      theme: 'plain'
    });
    currentY = doc.lastAutoTable.finalY + 10;
  }

  // Emails
  if (data.emails.length > 0) {
    doc.autoTable({
      startY: currentY,
      head: [['Extracted Emails']],
      body: data.emails.map(e => [e]),
      theme: 'plain'
    });
    currentY = doc.lastAutoTable.finalY + 10;
  }

  // Phone Numbers
  if (data.phones.length > 0) {
    doc.autoTable({
      startY: currentY,
      head: [['Extracted Phone Numbers']],
      body: data.phones.map(p => [p]),
      theme: 'plain',
      headStyles: { textColor: [0, 255, 65] }
    });
    currentY = doc.lastAutoTable.finalY + 10;
  }
  
  // Subdomains
  if (data.subdomains.length > 0) {
    doc.autoTable({
      startY: currentY,
      head: [['Discovered Subdomains (HackerTarget)']],
      body: data.subdomains.map(s => [s]),
      theme: 'plain'
    });
    currentY = doc.lastAutoTable.finalY + 10;
  }

  // Expert Hints
  const hints = [
    ["Review and remediate vulnerabilities."],
    ["Use OSINT Tools tab to discover subdomains and historical snapshots."]
  ];
  if (data.technologies.length > 0) hints.push(["Check exploit-db.com for known CVEs related to technologies."]);
  if (data.emails.length > 0) hints.push(["Search emails in breach databases (e.g., HaveIBeenPwned)."]);
  
  doc.autoTable({
    startY: currentY,
    head: [['Expert Next Steps (OSINT Hints)']],
    body: hints,
    theme: 'plain',
    headStyles: { textColor: [0, 255, 255] }
  });

  // Save via Extension Downloads logic using blob to avoid strict CSP blocks in MV3
  const blob = doc.output('blob');
  const url = URL.createObjectURL(blob);
  chrome.downloads.download({
    url: url,
    filename: `recon_${data.domain}.pdf`,
    saveAs: true
  });
}

// === SETTINGS & DIRECT FETCH API LOGIC ===
function loadApiKeys() {
  chrome.storage.sync.get(['hunter', 'shodan', 'intelx'], (result) => {
    if (result.hunter) {
      apiKeys.hunter = result.hunter;
      document.getElementById('key-hunter').value = apiKeys.hunter;
    }
    if (result.shodan) {
      apiKeys.shodan = result.shodan;
      document.getElementById('key-shodan').value = apiKeys.shodan;
    }
    if (result.intelx) {
      apiKeys.intelx = result.intelx;
      document.getElementById('key-intelx').value = apiKeys.intelx;
    }
  });
}

function saveApiKeys() {
  const hunter = document.getElementById('key-hunter').value.trim();
  const shodan = document.getElementById('key-shodan').value.trim();
  const intelx = document.getElementById('key-intelx').value.trim();

  chrome.storage.sync.set({
    hunter: hunter,
    shodan: shodan,
    intelx: intelx
  }, () => {
    apiKeys.hunter = hunter;
    apiKeys.shodan = shodan;
    apiKeys.intelx = intelx;
    const status = document.getElementById('save-status');
    status.textContent = 'Keys saved successfully!';
    setTimeout(() => { status.textContent = ''; }, 3000);
    // Re-trigger fetch if we just added keys
    fetchDirectApiData();
  });
}

async function fetchDirectApiData() {
  const ip = currentTabInfo.ip.split(' ')[0]; // Handle '(DNS Fallback)' suffix
  if (!ip || ip === 'Fetching...' || ip === 'Unknown') return;

  const hunterStatus = document.getElementById('api-status-hunter');

  // Hunter.io Fetch (Emails from Domain)
  if (apiKeys.hunter && currentTabInfo.domain !== 'Invalid URL') {
    hunterStatus.textContent = '(Fetching Hunter.io...)';
    try {
      const hunterRes = await fetch(`https://api.hunter.io/v2/domain-search?domain=${currentTabInfo.domain}&api_key=${apiKeys.hunter}`);
      if (hunterRes.ok) {
        const hunterData = await hunterRes.json();
        if (hunterData.data && hunterData.data.emails) {
          hunterData.data.emails.forEach(emailObj => {
            const val = emailObj.value.toLowerCase();
            if (!extractedData.emails.includes(val)) {
              extractedData.emails.push(val);
            }
          });
          document.getElementById('email-count').textContent = extractedData.emails.length;
          document.getElementById('extracted-emails').value = [...new Set(extractedData.emails)].join('\n');
          hunterStatus.textContent = '(Hunter.io Success)';
          hunterStatus.className = 'status-good';
        }
      } else {
        hunterStatus.textContent = `(Hunter.io Error: ${hunterRes.status})`;
        hunterStatus.className = 'status-bad';
      }
    } catch (e) {
      console.warn('Hunter.io fetch failed, skipping gracefully.', e);
      hunterStatus.textContent = '(Hunter.io Failed)';
      hunterStatus.className = 'status-bad';
    }
  } else {
    hunterStatus.textContent = '(Hunter.io Key Required)';
  }

  // IntelX Fetch (Leaked Data/Emails)
  if (apiKeys.intelx && currentTabInfo.domain !== 'Invalid URL') {
    fetchIntelXData();
  }

  // Shodan Data Fetch (Ports, ISP, Org, etc.)
  if (ip && ip !== 'Fetching...') {
    fetchShodanData(ip);
  }
}

async function fetchIntelXData() {
  // Simple search for domain in IntelX
  try {
    const res = await fetch(`https://2.intelx.io/phonebook/search?k=${apiKeys.intelx}`, {
      method: 'POST',
      body: JSON.stringify({
        term: currentTabInfo.domain,
        maxresults: 100,
        media: 0,
        target: 1 // Emails
      })
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.id) {
        // IntelX uses a task ID, we'd need to poll, 
        // but for now we'll just log that we started the search
        console.log('IntelX Search Started:', data.id);
      }
    }
  } catch (e) {
    console.warn('IntelX fetch failed', e);
  }
}
