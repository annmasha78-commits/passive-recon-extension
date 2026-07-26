// ============================================================
// Passive Recon .2 - Background Service Worker
// ============================================================
// Strategy: Use webRequest.onHeadersReceived to intercept real
// server headers before any CORS filtering occurs.
// This is the ONLY reliable way to get security headers like
// Content-Security-Policy, Strict-Transport-Security, etc.
// ============================================================

// In-memory cache: tabId -> { ip, headers, url }
const tabHeaderCache = {};

// Pending resolvers for auto-capture: tabId -> resolve function
const pendingCaptures = {};

// -- CORE INTERCEPTOR --
// This fires for every HTTP response, including background fetches (tabId = -1)
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        const headers = details.responseHeaders || [];
        const ip = details.ip || null;

        if (details.type === 'main_frame' && details.tabId > 0) {
            // Real tab navigation - store by tabId
            tabHeaderCache[details.tabId] = {
                ip: ip,
                headers: headers,
                url: details.url
            };

            // If popup is waiting for this tab's headers, resolve immediately
            if (pendingCaptures[details.tabId]) {
                pendingCaptures[details.tabId]({ ip, headers });
                delete pendingCaptures[details.tabId];
            }

            // Also persist to session storage as backup
            const data = {};
            data[details.tabId.toString()] = { ip, headers };
            chrome.storage.session.set(data).catch(() => { });
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
);

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabHeaderCache[tabId];
    delete pendingCaptures[tabId];
    chrome.storage.session.remove(tabId.toString()).catch(() => { });
});

// ============================================================
// Message Handler
// ============================================================
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    // -- GET CACHED HEADERS --
    // Popup asks: "do you already have headers for this tab?"
    if (request.action === "getTabData") {
        const tabId = request.tabId;

        // Check in-memory cache first (fastest)
        if (tabHeaderCache[tabId] && tabHeaderCache[tabId].headers.length > 0) {
            sendResponse(tabHeaderCache[tabId]);
            return false;
        }

        // Fall back to session storage (survives service worker restart)
        chrome.storage.session.get([tabId.toString()]).then((result) => {
            const stored = result[tabId.toString()];
            if (stored && stored.headers && stored.headers.length > 0) {
                // Restore to in-memory cache too
                tabHeaderCache[tabId] = stored;
                sendResponse(stored);
            } else {
                sendResponse(null);
            }
        }).catch(() => sendResponse(null));

        return true; // async
    }

    // -- AUTO CAPTURE HEADERS --
    // Popup asks: "reload the tab and give me the headers when they arrive"
    // This is the fully automatic flow - no user action needed.
    if (request.action === "autoCapture") {
        const tabId = request.tabId;
        const timeoutMs = 8000; // 8 second timeout

        // Set up a resolver that onHeadersReceived will call when headers arrive
        const capturePromise = new Promise((resolve) => {
            pendingCaptures[tabId] = resolve;

            // Auto-timeout fallback
            setTimeout(() => {
                if (pendingCaptures[tabId]) {
                    delete pendingCaptures[tabId];
                    resolve(null); // timed out
                }
            }, timeoutMs);
        });

        // Reload the tab to trigger onHeadersReceived
        chrome.tabs.reload(tabId, { bypassCache: true }, () => {
            if (chrome.runtime.lastError) {
                delete pendingCaptures[tabId];
                sendResponse(null);
                return;
            }
            // Wait for headers to be intercepted
            capturePromise.then((result) => {
                sendResponse(result);
            });
        });

        return true; // async
    }

    // -- MANUAL REFRESH (legacy, kept for the ⟳ button) --
    if (request.action === "refreshHeaders") {
        chrome.tabs.reload(request.tabId, { bypassCache: true }, () => {
            sendResponse({ ok: true });
        });
        return true;
    }
});
