const DEBUG = true;
const log = (msg, ...args) => { if (DEBUG) console.log(msg, ...args); };
const GRAY_MESSAGES = {
    INVALID_URL: "This link can't be scanned",
    UNSUPPORTED_SCHEME: "Only web links can be scanned",
    RATE_LIMITED: "Try again later",
    VT_API_ERROR: "An error occurred while scanning the link",
    API_KEY_MISSING: "Please set your VirusTotal API key in the extension",
};

function gray(reason) {
    return {
        status: "GRAY",
        scanned_url: null,
        reason_code: reason,
        message: GRAY_MESSAGES[reason] || "An unknown error occurred",
    };
}

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
    chrome.contextMenus.onClicked.addListener(async (info) => {
        if (info.menuItemId !== "scan-link") return;

        const rawUrl = info.linkUrl;
        
        let url;
        try {
            url = new URL(rawUrl);
        } catch {
            const errorResult = gray("INVALID_URL");
            chrome.storage.session.set({ lastScanResult: errorResult }, () => {
                chrome.action.openPopup();
            });
            return;
        }

        const protocol = url.protocol.toLowerCase();
        if (protocol !== "http:" && protocol !== "https:") {
            const errorResult = gray("UNSUPPORTED_SCHEME");
            chrome.storage.session.set({ lastScanResult: errorResult }, () => {
                chrome.action.openPopup();
            });
            return;
        }

        const initialResult = {
            status: "SCANNING",
            scanned_url: rawUrl,
            cleaned_url: sanitizeUrl(url).href,
            message: "Checking link safety with VirusTotal..."
        };
        
        chrome.storage.session.set({ lastScanResult: initialResult }, () => {
            if (chrome.runtime.lastError) {
                console.error("Error saving initial scan result:", chrome.runtime.lastError);
                return;
            }
            chrome.action.openPopup();
            
            scanLink(rawUrl).then(result => {
                log("Scan completed:", result);
                chrome.storage.session.set({ lastScanResult: result });
            }).catch(error => {
                log("Scan failed:", error);
                chrome.storage.session.set({ 
                    lastScanResult: gray("VT_API_ERROR")
                });
            });
        });
    });
} 

async function scanLink(rawUrl) {
    log("Starting scan for URL:", rawUrl);
    
    let url;
    try {
        url = new URL(rawUrl);
    } catch {
        log("Invalid URL format");
        return gray("INVALID_URL");
    }

    const protocol = url.protocol.toLowerCase();

    if (protocol !== "http:" && protocol !== "https:") {
        log("Unsupported protocol:", protocol);
        return gray("UNSUPPORTED_SCHEME");
    }

    const message = containsPotentialSecret(url) ? "This link may contain sensitive information. Proceed with caution." : null;
    log("Potential secret check:", !!message);

    const items = await new Promise(resolve => chrome.storage.local.get(['vtApiKey'], resolve));
    const vtApiKey = items.vtApiKey;
    if (!vtApiKey) {
        log("No API key found");
        return gray("API_KEY_MISSING");
    }
    
    log("API key found, calling VirusTotal...");
    const scanResult = await scanWithVirusTotal(url, vtApiKey).catch((error) => {
        log("VirusTotal API error:", error);
        return gray("VT_API_ERROR");
    });

    let cleanedUrl = url.href;
    try {
        cleanedUrl = sanitizeUrl(scanResult.scanned_url ? new URL(scanResult.scanned_url) : url).href;
    } catch (e) {
        log("Error generating cleaned URL, using original", e);
    }
    
    const finalResult = {
        status: scanResult.status,
        scanned_url: scanResult.scanned_url,
        cleaned_url: cleanedUrl,
        stats: scanResult.stats || null,
        engine_count: typeof scanResult.engine_count === 'number' ? scanResult.engine_count : null,
        analysis_time: scanResult.analysis_time || null,
        vt_report_url: scanResult.vt_report_url || null,
        message: message || scanResult.message,
    };
    
    log("Final result:", finalResult);
    return finalResult;
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

function isValidScanResponse(obj) {
    return obj && typeof obj.status === "string";
}

async function scanWithVirusTotal(url, apiKey) {
    log("Submitting URL to VirusTotal:", url.href);
    
    const submitController = new AbortController();
    setTimeout(() => submitController.abort(), 5000);

    const submitRes = await fetch(`https://www.virustotal.com/api/v3/urls`, {
        method: "POST",
        headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url.href)}`,
        signal: submitController.signal,
    });
    
    log("Submit response status:", submitRes.status);
    
    if (submitRes.status === 429) {
        log("Rate limited");
        return gray("RATE_LIMITED");
    }
    if (!submitRes.ok) {
        log("Submit failed:", submitRes.status, submitRes.statusText);
        return gray("VT_API_ERROR");
    }

    const submitData = await submitRes.json();
    log("Submit response received, analysis queued");
    
    const analysisId = submitData.data?.id;
    if (!analysisId) {
        log("No analysis ID in response");
        return gray("VT_API_ERROR");
    }

    log("Analysis ID:", analysisId);

    log("Waiting 2 seconds for analysis...");
    await new Promise(resolve => setTimeout(resolve, 2000));

    async function fetchAnalysis() {
        const resultController = new AbortController();
        setTimeout(() => resultController.abort(), 5000);

        log("Fetching analysis results...");
        const resultRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { "x-apikey": apiKey },
            signal: resultController.signal,
        });

        log("Results response status:", resultRes.status);
        
        if (!resultRes.ok) {
            log("Results fetch failed:", resultRes.status, resultRes.statusText);
            return null;
        }

        const resultData = await resultRes.json();
        log("Analysis results received");
        return resultData;
    }

    let resultData = await fetchAnalysis();

    const extractStats = rd => rd?.data?.attributes?.stats || null;
    let stats = extractStats(resultData);
    let engineCount = stats ? Object.values(stats).reduce((a,b)=>a+(b||0),0) : 0;

    if (engineCount < 5) {
        log("Low engine count (", engineCount, "), waiting 3s and rechecking once...");
        await new Promise(resolve => setTimeout(resolve, 3000));
        const retryData = await fetchAnalysis();
        const retryStats = extractStats(retryData);
        const retryEngineCount = retryStats ? Object.values(retryStats).reduce((a,b)=>a+(b||0),0) : 0;
        if (retryEngineCount > engineCount) {
            log("Retry returned higher engine count: ", retryEngineCount);
            resultData = retryData;
            stats = retryStats;
            engineCount = retryEngineCount;
        }
    }

    if (!stats) {
        log("No stats in results");
        return gray("VT_API_ERROR");
    }

    log("Detection stats:", stats);

    const positive = (stats.malicious || 0) + (stats.suspicious || 0);
    const isMalicious = positive > 0;

    const analysisAttrs = resultData.data?.attributes || {};
    const analysisTimeEpoch = analysisAttrs.last_analysis_date || analysisAttrs.date || Math.floor(Date.now()/1000);
    const analysisTime = new Date(analysisTimeEpoch * 1000).toISOString();

    const apiSelfLink = submitData?.data?.links?.self;
    let vtReportUrl = null;
    if (apiSelfLink && apiSelfLink.startsWith('https://www.virustotal.com/gui/')) {
        vtReportUrl = apiSelfLink;
    } else {
        vtReportUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(url.href)}`;
    }

    const result = {
        status: isMalicious ? "MALICIOUS" : "SAFE",
        scanned_url: url.href,
        stats: stats,
        engine_count: engineCount,
        analysis_time: analysisTime,
        vt_report_url: vtReportUrl,
        message: isMalicious ?
            `Detected as malicious by ${stats.malicious || 0} security vendors.` :
            `No detections by ${engineCount} engines.`
    };
    
    log("Final scan result:", result);
    return result;
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        sanitizeUrl,
        containsPotentialSecret,
    };
}