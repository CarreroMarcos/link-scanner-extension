chrome.storage.local.get(["vtApiKey"], (data) => {
    if (data.vtApiKey) {
        document.getElementById("apiKeySection").style.display = "none";
    }
});

function isValidVirusTotalApiKey(key) {
    return /^[a-f0-9]{64}$/i.test(key);
}

document.getElementById("saveKey").addEventListener("click", () => {
    const key = document.getElementById("apiKey").value;
    
    if (!key) {
        alert("Please enter an API Key.");
        return;
    }

    if (!isValidVirusTotalApiKey(key)) {
        alert("Invalid API Key format. Please enter a valid 64-character VirusTotal API key.");
        return;
    }

    chrome.storage.local.set({ vtApiKey: key }, () => {
        if (chrome.runtime.lastError) {
            alert("Error saving API Key: " + chrome.runtime.lastError.message);
        } else {
            alert("API Key saved successfully!");
            document.getElementById("apiKeySection").style.display = "none";
        }
    });

});

document.addEventListener("DOMContentLoaded", () => {
    const statusElement = document.getElementById("status");
    const messageElement = document.getElementById("message");
    const refreshBtn = document.getElementById("refreshBtn");
    const statusCircle = document.getElementById("statusCircle");
    const scannedUrlElement = document.getElementById("scannedUrl");
    const cleanedUrlElement = document.getElementById("cleanedUrl");

    if (!statusElement || !messageElement || !refreshBtn || !statusCircle || !scannedUrlElement || !cleanedUrlElement) {
        console.error("Required elements not found in the DOM.");
        return;
    }

    function loadScanResult() {
        chrome.storage.session.get("lastScanResult", (data) => {
            if (chrome.runtime.lastError) {
                console.error("Error retrieving scan result:", chrome.runtime.lastError);
                if (statusElement) statusElement.textContent = "Error";
                if (messageElement) messageElement.textContent = "Failed to load scan result.";
                return;
            }

            const result = data.lastScanResult;
            if (result) {
                let displayStatus = result.status.toUpperCase();
                if (displayStatus === "GRAY") displayStatus = "UNVERIFIABLE";
                if (displayStatus === "SCANNING") displayStatus = "SCANNING...";
                if (statusElement) statusElement.textContent = displayStatus;
                
                const scanned = result.scanned_url || "";
                const cleaned = result.cleaned_url || "";

                if (cleaned && scanned && cleaned === scanned) {
                    if (scannedUrlElement) scannedUrlElement.textContent = "";
                    if (cleanedUrlElement) {
                        cleanedUrlElement.href = cleaned;
                        cleanedUrlElement.textContent = cleaned;
                        cleanedUrlElement.title = cleaned;
                    }
                } else {
                    if (scannedUrlElement) scannedUrlElement.textContent = scanned ? `Original: ${scanned}` : "";
                    if (cleanedUrlElement) {
                        cleanedUrlElement.href = cleaned || "";
                        cleanedUrlElement.textContent = cleaned ? cleaned : "";
                        cleanedUrlElement.title = cleaned || "";
                    }
                }

                const detectionEl = document.getElementById('detectionSummary');
                const timeEl = document.getElementById('analysisTime');
                const vtLinkEl = document.getElementById('vtLink');
                const cautionEl = document.getElementById('caution');

                const engineCount = result.engine_count || (result.stats ? Object.values(result.stats).reduce((a,b)=>a+(b||0),0) : 0);
                const stats = result.stats || {};
                const positive = (stats.malicious || 0) + (stats.suspicious || 0);

                if (result.status && result.status.toUpperCase() === 'SCANNING') {
                    if (detectionEl) detectionEl.textContent = 'Scanning — results will appear shortly';
                    if (timeEl) timeEl.textContent = '';
                    if (vtLinkEl) { vtLinkEl.href = ''; vtLinkEl.textContent = ''; }
                    if (cautionEl) cautionEl.textContent = '';
                } else {
                    if (detectionEl) {
                        if (engineCount === 0) {
                            detectionEl.textContent = 'No engines scanned yet';
                        } else if (positive > 0) {
                            detectionEl.textContent = `${positive} detections — ${engineCount} engines scanned`;
                        } else {
                            detectionEl.textContent = `No detections — ${engineCount} engines scanned`;
                        }
                    }
                }

                if (timeEl) {
                    if (result.analysis_time) {
                        try {
                            const dt = new Date(result.analysis_time);
                            timeEl.textContent = `Last analysis: ${dt.toLocaleString()}`;
                        } catch { timeEl.textContent = '' }
                    } else {
                        timeEl.textContent = '';
                    }
                }

                if (vtLinkEl) {
                    if (result.vt_report_url) {
                        vtLinkEl.href = result.vt_report_url;
                        vtLinkEl.textContent = 'View on VirusTotal';
                    } else {
                        vtLinkEl.href = '';
                        vtLinkEl.textContent = '';
                    }
                }

                if (cautionEl) {
                    if (engineCount === 0) {
                        cautionEl.textContent = 'UNVERIFIABLE — no engines have scanned this resource yet.';
                    } else if (positive === 0 && engineCount < 10) {
                        cautionEl.textContent = 'No detections, but only a small number of engines scanned — results may be incomplete.';
                    } else if (positive === 0) {
                        cautionEl.textContent = 'No vendors flagged this resource — not guaranteed safe.';
                    } else {
                        cautionEl.textContent = '';
                    }
                }

                if (messageElement) messageElement.textContent = result.message || "No message available.";

                if (engineCount === 0 && statusElement && (!result.status || result.status.toUpperCase() !== 'SCANNING')) {
                    statusElement.textContent = "UNVERIFIABLE";
                }
                if (statusCircle) {
                    const status = result.status.toUpperCase();
                    statusCircle.className = "status-circle";
                    
                    if (status === "SAFE") {
                        statusCircle.classList.add("valid");
                    } else if (status === "MALICIOUS") {
                        statusCircle.classList.add("danger");
                    } else if (status === "SCANNING") {
                        statusCircle.classList.add("scanning", "invalid");
                    } else {
                        statusCircle.classList.add("invalid");
                    }
                }
            } else {
                if (statusElement) statusElement.textContent = "No scan performed";
                if (scannedUrlElement) scannedUrlElement.textContent = "";
                if (cleanedUrlElement) {
                    cleanedUrlElement.href = "";
                    cleanedUrlElement.textContent = "";
                }
                if (messageElement) messageElement.textContent = "Right-click on any link and select 'Scan Link with VirusTotal' to check if it's safe.";
                if (statusCircle) statusCircle.className = "status-circle invalid";
            }
        });
    }

    loadScanResult();

    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === "session" && changes.lastScanResult) {
            loadScanResult();
        }
    });

    refreshBtn.addEventListener("click", () => {
        loadScanResult();
    });
});
