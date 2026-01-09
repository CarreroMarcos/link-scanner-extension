chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "scan-link",
        title: "Scan Link with VirusTotal",
        contexts: ["link"]
    });
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
        scanned_url: url.href
    };
    function gray(reason) {
        return {
            status: "gray",
            scanned_url: null,
            reason_code: reason
        };
    }
}