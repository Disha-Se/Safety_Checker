// Blacklist example expanded
const blacklist = [
  "badsite.com", "malware.ru", "phishing.tk", "scam.xyz", "dangerous.top", "fakegift.ml"
];

// Popular domains for typo check
const popularDomains = [
  "google.com", "facebook.com", "youtube.com", "amazon.com", "twitter.com",
  "wikipedia.org", "instagram.com", "linkedin.com", "netflix.com", "paypal.com"
];

// Known URL shorteners (expanded)
const urlShorteners = [
  "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "is.gd"
];

// Free hosting providers (common)
const freeHosts = [
  "000webhostapp.com", "github.io", "herokuapp.com", "netlify.app", "vercel.app"
];

// TLD country codes map (partial)
const tldCountries = {
  ".ru": "🇷🇺 Russia",
  ".cn": "🇨🇳 China",
  ".tk": "🇹🇰 Tokelau",
  ".ml": "🇲🇱 Mali",
  ".top": "Top Level Domain (generic)",
  ".xyz": "Generic",
  ".org": "Organization",
  ".com": "Commercial",
  ".net": "Network"
};

// HSTS preload list (small sample)
const hstsPreloadDomains = [
  "google.com", "facebook.com", "github.com", "paypal.com", "twitter.com"
];

// === Utility Functions ===
function isIPv4(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}
function isIPv6(hostname) {
  // IPv6 format: [xxxx:xxxx:...]
  return /^\[[0-9a-fA-F:]+\]$/.test(hostname);
}
function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}
function base64UrlEncode(str) {
  return btoa(str).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function levenshtein(a, b) {
  // Simple Levenshtein Distance function
  const matrix = Array.from({length: b.length + 1}, (_, i) => [i]);
  for(let j=0; j <= a.length; j++) matrix[0][j] = j;
  for(let i=1; i <= b.length; i++) {
    for(let j=1; j <= a.length; j++) {
      if(b[i-1] === a[j-1]) matrix[i][j] = matrix[i-1][j-1];
      else matrix[i][j] = Math.min(
        matrix[i-1][j-1] + 1,
        matrix[i][j-1] + 1,
        matrix[i-1][j] + 1
      );
    }
  }
  return matrix[b.length][a.length];
}
function findClosestDomain(domain) {
  let minDist = Infinity;
  let closest = null;
  for (const popDomain of popularDomains) {
    const dist = levenshtein(domain, popDomain);
    if(dist < minDist) {
      minDist = dist;
      closest = popDomain;
    }
  }
  if (minDist > 0 && minDist <= 2) return closest;
  return null;
}

// Calculate entropy of a string
function entropy(str) {
  const len = str.length;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  let ent = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    ent -= p * Math.log2(p);
  }
  return ent.toFixed(2);
}

// Check for emoji/unicode characters in URL
function containsEmojisOrUnicode(str) {
  // Regex to detect emojis and non-ASCII chars
  return /[\u{1F300}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{FE00}-\u{FE0F}\u{1F900}-\u{1F9FF}\u{200D}]/u.test(str) ||
         /[^\x00-\x7F]/.test(str);
}

// === Feature Functions ===
function checkSuspiciousKeywords(url) {
  const keywords = ["bit.ly", "tinyurl", "free", "gift", "win", "login", "verify"];
  const found = keywords.filter(k => url.toLowerCase().includes(k));
  if(found.length) return `🚩 Suspicious keywords found: ${found.join(", ")}\n`;
  return "";
}
function checkShadyExtensions(url) {
  const shadyExt = [".tk", ".xyz", ".ru", ".top", ".ml"];
  const found = shadyExt.filter(ext => url.toLowerCase().includes(ext));
  if(found.length) return `🚨 Shady domain extension(s): ${found.join(", ")}\n`;
  return "";
}
function checkBlacklist(url) {
  const found = blacklist.filter(d => url.toLowerCase().includes(d));
  if(found.length) return `🚫 Blacklisted domain(s): ${found.join(", ")}\n`;
  return "";
}
function checkSubdomains(url) {
  try {
    const hostname = new URL(url).hostname;
    const parts = hostname.split(".");
    if(parts.length > 3) return `⚠️ URL has multiple subdomains (${parts.length - 2}) — suspicious.\n`;
    return "";
  } catch { return ""; }
}
function checkPathComplexity(url) {
  try {
    const u = new URL(url);
    if(u.pathname.length > 40) return `⚠️ URL path is very long (${u.pathname.length} chars).\n`;
    if(u.search.length > 50) return `⚠️ URL query string is very long (${u.search.length} chars).\n`;
    return "";
  } catch { return ""; }
}
function checkIPv4(url) {
  try {
    const hostname = new URL(url).hostname;
    if(isIPv4(hostname)) return "⚠️ URL uses IPv4 address instead of domain name.\n";
    return "";
  } catch { return ""; }
}
function checkIPv6(url) {
  try {
    const hostname = new URL(url).hostname;
    if(isIPv6(hostname)) return "⚠️ URL uses IPv6 address instead of domain name.\n";
    return "";
  } catch { return ""; }
}
function checkURLShortener(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if(urlShorteners.includes(hostname)) return `⚠️ URL uses URL shortener (${hostname}).\n`;
    return "";
  } catch { return ""; }
}
function checkFreeHosting(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if(freeHosts.some(host => hostname.endsWith(host))) return `⚠️ URL hosted on free hosting provider (${hostname}).\n`;
    return "";
  } catch { return ""; }
}
function checkHSTS(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    if(hstsPreloadDomains.includes(hostname)) return `🔒 Domain is HSTS-preloaded (${hostname}) — more secure.\n`;
    return "⚠️ Domain not HSTS-preloaded - connection might be insecure.\n";
  } catch { return ""; }
}
function checkDomainTypo(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    const closest = findClosestDomain(hostname);
    if(closest && closest !== hostname) return `⚠️ Domain similar to popular site "${closest}"- possible typo-squatting.\n`;
    return "";
  } catch { return ""; }
}
function checkDomainLength(url) {
  try {
    const hostname = new URL(url).hostname;
    if(hostname.length > 30) return `⚠️ Domain length is long (${hostname.length} chars).\n`;
    return "";
  } catch { return ""; }
}
function checkDomainAge(url) {
  // Without API, just a placeholder:
  return "";
}
function checkProtocol(url) {
  try {
    const u = new URL(url);
    if(u.protocol !== "https:") return "⚠️ URL does not use HTTPS - not secure.\n";
    return "🔐 URL uses HTTPS.\n";
  } catch { return ""; }
}
function checkEntropy(url) {
  const ent = entropy(url);
  if(ent > 4.5) return `⚠️ URL entropy is high (${ent}) - possibly random or obfuscated.\n`;
  return "";
}
function checkEmoji(url) {
  if(containsEmojisOrUnicode(url)) return "⚠️ URL contains emojis or unusual unicode characters.\n";
  return "";
}

// === Main check function ===
function analyzeUrl(url) {
  if (!url) return "❗ Please enter a URL.\n";

  let result = "";

  try {
    const u = new URL(url);
    // Basic checks
    result += checkProtocol(url);
    result += checkBlacklist(url);
    result += checkSuspiciousKeywords(url);
    result += checkShadyExtensions(url);
    result += checkURLShortener(url);
    result += checkFreeHosting(url);
    result += checkSubdomains(url);
    result += checkPathComplexity(url);
    result += checkIPv4(url);
    result += checkIPv6(url);
    result += checkHSTS(url);
    result += checkDomainTypo(url);
    result += checkDomainLength(url);
    result += checkEntropy(url);
    result += checkEmoji(url);
  } catch {
    return "❌ Invalid URL format.\n";
  }

  if(!result) result = "✅ Link is safe!";
  return result;
}

// === UI & Event Listeners ===
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("linkInput");
  const resultDiv = document.getElementById("result");
  const checkBtn = document.getElementById("checkBtn");
  const copyBtn = document.getElementById("copyBtn");
  const resetBtn = document.getElementById("resetBtn");
  const historyDiv = document.getElementById("history");
  const darkModeBtn = document.getElementById("darkModeBtn");

  function addToHistory(url) {
    if(!url) return;
    let history = JSON.parse(localStorage.getItem("history") || "[]");
    // Avoid duplicates
    if(!history.includes(url)) {
      history.unshift(url);
      if(history.length > 20) history.pop();
      localStorage.setItem("history", JSON.stringify(history));
      renderHistory();
    }
  }
  function renderHistory() {
    let history = JSON.parse(localStorage.getItem("history") || "[]");
    historyDiv.innerHTML = "";
    history.forEach(url => {
      const div = document.createElement("div");
      div.textContent = url;
      div.className = "history-item";
      div.title = "Click to load this URL";
      div.addEventListener("click", () => {
        input.value = url;
        resultDiv.textContent = analyzeUrl(url);
      });
      historyDiv.appendChild(div);
    });
  }

  checkBtn.addEventListener("click", () => {
    const url = input.value.trim();
    const analysis = analyzeUrl(url);
    resultDiv.textContent = analysis;
    addToHistory(url);
  });

  copyBtn.addEventListener("click", () => {
    const url = input.value.trim();
    if(!url) return alert("Nothing to copy.");
    navigator.clipboard.writeText(url)
      .then(() => alert("Link copied to clipboard!"))
      .catch(() => alert("Failed to copy link."));
  });

  resetBtn.addEventListener("click", () => {
    input.value = "";
    resultDiv.textContent = "";
  });

  darkModeBtn.addEventListener("click", () => {
    document.body.classList.toggle("dark");
  });

  // Load history on page load
  renderHistory();
});
