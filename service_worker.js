if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
        if (chrome.contextMenus && chrome.contextMenus.create) {
            chrome.contextMenus.create({
                id: "scan-link",
                title: "Scan Link with VirusTotal",
                contexts: ["link"],
            });
        }
        console.log("Context menu item 'Scan Link with VirusTotal' created.");
    });
} 

if (typeof chrome !== "undefined" && chrome.contextMenus && chrome.contextMenus.onClicked) {
    chrome.contextMenus.onClicked.addListener((info) => {
        if (info.menuItemId !== "scan-link") return;

        const rawUrl = info.linkUrl;
        const result = scanLinkFailFast(rawUrl);

        if (chrome.storage && chrome.storage.session && chrome.storage.session.set) {
            chrome.storage.session.set({ lastScanResult: result });
        }
    });
} 

function scanLinkFailFast(rawUrl) {
    let url;
    try {
        url = new URL(rawUrl);
    } catch {
        return gray("INVALID_URL");
    }

    const protocol = url.protocol.toLowerCase();

    if (protocol !== "http:" && protocol !== "https:") {
        return gray("UNSUPPORTED_SCHEME");
    }

    return {
        status: "green",
        scanned_url: url.href,
    };
    function gray(reason) {
        return {
            status: "gray",
            scanned_url: null,
            reason_code: reason,
        };
    }
}

const TRACKING_PARAMS = new Set([
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
]);

function sanitizeUrl(url) {
    const clean = new URL(url.href);
    [...clean.searchParams.keys()].forEach((key) => {
        if (TRACKING_PARAMS.has(key.toLowerCase())) {
            clean.searchParams.delete(key);
        }
    });
    return clean;
}

function containsPotentialSecret(url) {
    for (const [key, value] of url.searchParams.entries()) {
        if (value.length > 32) return true;
        if (/token|code|key|auth|reset/i.test(key)) return true;
    }
    return false;
}

async function scanWithVirusTotal(url, apiKey) {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 5000);

    const res = await fetch(`https://www.virustotal.com/api/v3/urls`, {
        method: "POST",
        headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
        signal: controller.signal,
    });
    if (res.status === 429) return gray("RATE_LIMITED");
    if (!res.ok) return gray("VT_API_ERROR");

    return { status: "green", scanned_url: url };
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        sanitizeUrl,
        containsPotentialSecret,
    };
}


