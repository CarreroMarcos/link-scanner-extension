chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "scan-link",
        title: "Scan Link with VirusTotal",
        contexts: ["link"],
    });
    console.log("Context menu item 'Scan Link with VirusTotal' created.");
});

chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId !== "scan-link") return;

    const rawUrl = info.linkUrl;
    const result = scanLinkFailFast(rawUrl);

    chrome.storage.session.set({ lastScanResult: result });
});

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


